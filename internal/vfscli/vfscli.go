// Package vfscli implements the weaverssh vfs:// command-line tools. A single
// implementation backs four entry points dispatched by program name:
//
//	wls     list a vfs:// directory
//	wcp     copy between vfs:// and the local filesystem (either direction)
//	wmkdir  create directories in the vfs:// namespace
//	wtool   multitool: publish (setroot/serve) plus ls/cp/mkdir/cat/rm/status
//
// vfs:// refers to a directory published by wv-9p / `wtool setroot`, reached
// over the weaverssh tunnel so bytes move endpoint-to-endpoint without staging
// on any intermediary hop.
package vfscli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/internal/vfs"
	"weaverssh/pubsub"
)

const dialTimeout = 10 * time.Second

// Main dispatches on the invoked program name and returns a process exit code.
func Main(prog string, args []string) int {
	switch base(prog) {
	case "wls":
		return run(cmdLs(args))
	case "wcp":
		return run(cmdCp(args))
	case "wmkdir":
		return run(cmdMkdir(args))
	case "wtool":
		return cmdWtool(args)
	default:
		fmt.Fprintf(os.Stderr, "vfscli: unknown program %q (expected wls/wcp/wmkdir/wtool)\n", prog)
		return 2
	}
}

func base(prog string) string {
	b := filepath.Base(prog)
	return strings.TrimSuffix(b, ".exe")
}

func run(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cpEndpoints(args []string) (src, dst string, err error) {
	if len(args) == 3 && strings.EqualFold(args[1], "to") {
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 {
		return "", "", fmt.Errorf("cp needs exactly SRC and DST")
	}
	return args[0], args[1], nil
}

// --- wls -------------------------------------------------------------------

func cmdLs(args []string) error {
	fs := flag.NewFlagSet("wls", flag.ContinueOnError)
	long := fs.Bool("l", false, "long listing (type, size, name)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: wv ls [-l] [vfs://PATH ...]") }
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := fs.Args()
	if len(targets) == 0 {
		targets = []string{vfs.Scheme}
	}
	view, err := activeView()
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	observer, err := newInfrastructureObserver()
	if err != nil {
		return err
	}
	defer observer.Close()
	multi := len(targets) > 1
	for i, t := range targets {
		viewRel, sourceRel, err := resolveViewRef(view, t)
		if err != nil {
			return err
		}
		entries, err := c.List(sourceRel)
		if err != nil {
			return fmt.Errorf("list %s: %w", t, err)
		}
		entries, err = view.ApplyList(sourceRel, viewRel, entries)
		if err != nil {
			return err
		}
		observer.emitFileOperation(context.Background(), pubsub.FileListed, pubsub.FileEvent{
			Path:      t,
			ViewPath:  viewRel,
			Component: pubsub.ComponentVFS,
			Protocol:  "vfs-9p",
			Subsystem: "vfs",
			Files:     int64(len(entries)),
			IsDir:     true,
			Status:    "completed",
		})
		if multi {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("%s:\n", t)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			name := e.Name
			if e.IsDir {
				name += "/"
			}
			if *long {
				kind := "f"
				if e.IsDir {
					kind = "d"
				}
				fmt.Printf("%s %10d  %s\n", kind, e.Size, name)
			} else {
				fmt.Println(name)
			}
		}
	}
	return nil
}

// --- wcp -------------------------------------------------------------------

func cmdCp(args []string) error {
	fs := flag.NewFlagSet("wcp", flag.ContinueOnError)
	recursive := fs.Bool("r", false, "copy directories recursively")
	eventsPath := fs.String("events", envOr("WEAVERSSH_TRANSFER_EVENTS", ""), "append file-transfer events as JSONL to FILE")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv cp [-r] [-events FILE] SRC [to] DST")
		fmt.Fprintln(os.Stderr, "  SRC or DST may be vfs://PATH, vfs::NODE:/PATH, or SCP-style NODE:/PATH / USER@NODE:~/PATH; the other is local.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	src, dst, err := cpEndpoints(fs.Args())
	if err != nil {
		fs.Usage()
		return err
	}

	view, err := activeView()
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	observer, err := newTransferObserver(*eventsPath)
	if err != nil {
		return err
	}
	defer observer.Close()
	cp := &copier{c: c, recursive: *recursive, view: view, transfers: observer}

	switch {
	case vfs.IsVFS(src) && !vfs.IsVFS(dst):
		return cp.fromVFS(src, dst)
	case !vfs.IsVFS(src) && vfs.IsVFS(dst):
		return cp.toVFS(src, dst)
	case vfs.IsVFS(src) && vfs.IsVFS(dst):
		return fmt.Errorf("vfs-to-vfs copy is not supported; stage through a local path")
	default:
		return fmt.Errorf("at least one of SRC/DST must be a VFS path or SCP-style node path")
	}
}

type copier struct {
	c         *p9client.Client
	recursive bool
	view      vfs.ViewConfig
	transfers *transferObserver
}

// fromVFS copies a vfs:// source to a local destination.
func (cp *copier) fromVFS(src, dst string) error {
	viewRel, sourceRel, err := resolveViewRef(cp.view, src)
	if err != nil {
		return err
	}
	st, err := cp.c.Stat(sourceRel)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if st.IsDir {
		if !cp.recursive {
			return fmt.Errorf("%s is a directory (use -r)", src)
		}
		return cp.dirFromVFS(sourceRel, viewRel, localJoinDir(dst, viewRel))
	}
	target := dst
	if isLocalDir(dst) {
		target = filepath.Join(dst, path.Base(viewRel))
	}
	return cp.fileFromVFS(sourceRel, viewRel, target)
}

func (cp *copier) fileFromVFS(sourceRel, viewRel, localPath string) error {
	transfer := pubsub.FileTransfer{
		Operation:   "cp",
		Direction:   pubsub.TransferVfsToLocal,
		Source:      vfs.Scheme + viewRel,
		Destination: localPath,
		SourceView:  viewRel,
		Protocol:    "vfs-9p",
		Files:       1,
	}
	return cp.transfers.run(context.Background(), transfer, func(meta *pubsub.FileTransfer) error {
		data, err := cp.c.ReadFile(sourceRel)
		if err != nil {
			return fmt.Errorf("read %s: %w", sourceRel, err)
		}
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(localPath, data, 0o644); err != nil {
			return err
		}
		meta.Bytes = int64(len(data))
		fmt.Printf("%s%s -> %s (%d bytes)\n", vfs.Scheme, viewRel, localPath, len(data))
		return nil
	})
}

func (cp *copier) dirFromVFS(sourceRel, viewRel, localDir string) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}
	entries, err := cp.c.List(sourceRel)
	if err != nil {
		return err
	}
	mapped, err := cp.view.ListEntries(sourceRel, viewRel, entries)
	if err != nil {
		return err
	}
	for _, e := range mapped {
		localName := e.Entry.Name
		if e.Entry.IsDir {
			if err := cp.dirFromVFS(e.SourcePath, e.ViewPath, filepath.Join(localDir, localName)); err != nil {
				return err
			}
		} else {
			if err := cp.fileFromVFS(e.SourcePath, e.ViewPath, filepath.Join(localDir, localName)); err != nil {
				return err
			}
		}
	}
	return nil
}

// toVFS copies a local source into the vfs:// namespace.
func (cp *copier) toVFS(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	viewDst, sourceDst, err := resolveViewRef(cp.view, dst)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !cp.recursive {
			return fmt.Errorf("%s is a directory (use -r)", src)
		}
		name := filepath.Base(src)
		return cp.dirToVFS(src, joinRel(sourceDst, name), joinRel(viewDst, name))
	}
	sourceTarget := sourceDst
	viewTarget := viewDst
	// If dst names an existing vfs directory, copy into it under the basename.
	if st, err := cp.c.Stat(sourceDst); err == nil && st.IsDir {
		sourceTarget = joinRel(sourceDst, filepath.Base(src))
		viewTarget = joinRel(viewDst, filepath.Base(src))
	} else if strings.HasSuffix(dst, "/") {
		sourceTarget = joinRel(sourceDst, filepath.Base(src))
		viewTarget = joinRel(viewDst, filepath.Base(src))
	}
	return cp.fileToVFS(src, sourceTarget, viewTarget)
}

func (cp *copier) fileToVFS(localPath, sourceRel, viewRel string) error {
	if cp.view.IsHiddenSource(sourceRel) {
		return fmt.Errorf("refusing to write hidden VFS view path %s%s", vfs.Scheme, viewRel)
	}
	transfer := pubsub.FileTransfer{
		Operation:       "cp",
		Direction:       pubsub.TransferLocalToVfs,
		Source:          localPath,
		Destination:     vfs.Scheme + viewRel,
		DestinationView: viewRel,
		Protocol:        "vfs-9p",
		Files:           1,
	}
	return cp.transfers.run(context.Background(), transfer, func(meta *pubsub.FileTransfer) error {
		data, err := os.ReadFile(localPath)
		if err != nil {
			return err
		}
		if parent, _ := splitRel(sourceRel); parent != "" {
			if err := cp.c.MkdirAll(parent); err != nil {
				return fmt.Errorf("mkdir %s: %w", parent, err)
			}
		}
		if err := cp.c.WriteFile(sourceRel, data); err != nil {
			return fmt.Errorf("write %s: %w", sourceRel, err)
		}
		meta.Bytes = int64(len(data))
		fmt.Printf("%s -> %s%s (%d bytes)\n", localPath, vfs.Scheme, viewRel, len(data))
		return nil
	})
}

func (cp *copier) dirToVFS(localDir, sourceRel, viewRel string) error {
	if cp.view.IsHiddenSource(sourceRel) {
		return fmt.Errorf("refusing to write hidden VFS view path %s%s", vfs.Scheme, viewRel)
	}
	if err := cp.c.MkdirAll(sourceRel); err != nil {
		return err
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		childLocal := filepath.Join(localDir, e.Name())
		childSourceRel := joinRel(sourceRel, e.Name())
		childViewRel := joinRel(viewRel, e.Name())
		if cp.view.IsHiddenSource(childSourceRel) {
			continue
		}
		if e.IsDir() {
			if err := cp.dirToVFS(childLocal, childSourceRel, childViewRel); err != nil {
				return err
			}
		} else {
			if err := cp.fileToVFS(childLocal, childSourceRel, childViewRel); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- wmkdir ----------------------------------------------------------------

func cmdMkdir(args []string) error {
	fs := flag.NewFlagSet("wmkdir", flag.ContinueOnError)
	parents := fs.Bool("p", false, "create parent directories as needed")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: wv mkdir [-p] vfs://PATH ...") }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("mkdir needs at least one vfs:// path")
	}
	view, err := activeView()
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	observer, err := newInfrastructureObserver()
	if err != nil {
		return err
	}
	defer observer.Close()
	for _, t := range fs.Args() {
		viewRel, sourceRel, err := resolveViewRef(view, t)
		if err != nil {
			return err
		}
		if sourceRel == "" {
			return fmt.Errorf("refusing to mkdir the namespace root")
		}
		if *parents {
			err = c.MkdirAll(sourceRel)
		} else {
			err = c.Mkdir(sourceRel)
		}
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", t, err)
		}
		observer.emitFileOperation(context.Background(), pubsub.FileMkdir, pubsub.FileEvent{
			Path:      vfs.Scheme + viewRel,
			ViewPath:  viewRel,
			Component: pubsub.ComponentVFS,
			Protocol:  "vfs-9p",
			Subsystem: "vfs",
			IsDir:     true,
			Status:    "completed",
		})
		fmt.Printf("created %s%s\n", vfs.Scheme, viewRel)
	}
	return nil
}

// --- wtool -----------------------------------------------------------------

func cmdWtool(args []string) int {
	// Accept the documented `wtool -vfs -setroot DIR` form alongside subcommands.
	if i := indexOf(args, "-setroot"); i >= 0 {
		rest := append(append([]string{}, args[:i]...), args[i+1:]...)
		rest = removeFlag(rest, "-vfs")
		return run(cmdSetroot(rest))
	}
	if len(args) == 0 {
		return run(cmdStatus(nil))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "setroot":
		return run(cmdSetroot(rest))
	case "serve":
		return run(cmdServe(rest))
	case "ls":
		return run(cmdLs(rest))
	case "cp":
		return run(cmdCp(rest))
	case "mkdir":
		return run(cmdMkdir(rest))
	case "cat":
		return run(cmdCat(rest))
	case "rm":
		return run(cmdRm(rest))
	case "view":
		return run(cmdView(rest))
	case "mount":
		return run(cmdMount(rest))
	case "unmount", "umount":
		return run(cmdUnmount(rest))
	case "sshfs":
		return run(cmdSshfs(rest))
	case "libvirt-xml":
		return run(cmdLibvirtXML(rest))
	case "status":
		return run(cmdStatus(rest))
	case "help", "-h", "--help":
		printWtoolHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "wtool: unknown subcommand %q (try `wtool help`)\n", sub)
		return 2
	}
}

func printWtoolHelp() {
	fmt.Println(`wtool — weaverssh vfs:// multitool

publish (workstation side):
  wtool setroot DIR [-listen ADDR] [-read-write]   publish DIR and serve 9P
  wtool serve [DIR] [-listen ADDR] [-read-write]   serve without rewriting config
  wtool status [-json]                             show root, endpoint, and FUSE readiness

namespace (remote side, over the tunnel):
  wtool ls    [-l] [vfs://PATH ...]                also: wls
  wtool cp    [-r] SRC DST                         also: wcp; supports NODE:/path and USER@NODE:~/path
  wtool mkdir [-p] vfs://PATH ...                  also: wmkdir
  wtool cat   vfs://PATH                           print a file
  wtool rm    vfs://PATH                           remove a file or empty dir
  wtool view  [-json|-example|-set FILE|-clear]    inspect or configure VFS view rules

mount as a real filesystem (macFUSE / libfuse):
  wtool mount   DIR [-rw] [-allow-other] [-name L]  mount the namespace at DIR
  wtool unmount DIR                                 unmount it (also: wv-mount)

mount a remote sshd host over the tunnel (sshfs + SOCKS):
  wtool sshfs [-socks A] [-ro] user@host:/path DIR  sshfs through the weaverssh proxy

libvirt / virtio-9p passthrough:
  wtool libvirt-xml -mount DIR [-tag T] [-readonly]  print a <filesystem> snippet

endpoint resolution (remote side):
  WEAVERSSH_VFS_ENDPOINT  host:port of the 9P service (default 127.0.0.1:5640)
  WEAVERSSH_VFS_SOCKS     SOCKS5 proxy to reach the endpoint (optional)
  WEAVERSSH_VFS_VIEW      JSON file with hide/rename projection rules (optional)`)
}

func cmdSetroot(args []string) error {
	fs := flag.NewFlagSet("setroot", flag.ContinueOnError)
	listen := fs.String("listen", vfs.DefaultEndpoint, "TCP listen address")
	readWrite := fs.Bool("read-write", false, "allow create/write/remove")
	saveOnly := fs.Bool("save-only", false, "record the root in config without serving")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: wv share DIR [--rw] [-listen ADDR] [-save-only]")
	}
	root, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := vfs.SaveConfig(vfs.Config{Root: root, Listen: *listen}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("published root recorded: %s (listen %s) -> %s\n", root, *listen, vfs.ConfigPath())
	if *saveOnly {
		return nil
	}
	return serve(root, *listen, *readWrite)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "TCP listen address (default: from config or 127.0.0.1:5640)")
	readWrite := fs.Bool("read-write", false, "allow create/write/remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root := ""
	addr := *listen
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	} else if cfg, err := vfs.LoadConfig(); err == nil {
		root = cfg.Root
		if addr == "" {
			addr = cfg.Listen
		}
	}
	if root == "" {
		return fmt.Errorf("no root given and none recorded; run `wv share DIR` first")
	}
	if addr == "" {
		addr = vfs.DefaultEndpoint
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	return serve(abs, addr, *readWrite)
}

func serve(root, addr string, readWrite bool) error {
	logger := log.New(os.Stderr, "wv ", log.LstdFlags)
	srv, err := p9svc.New(p9svc.Config{Root: root, Addr: addr, ReadOnly: !readWrite, Logger: logger})
	if err != nil {
		return err
	}
	mode := "read-only"
	if readWrite {
		mode = "read-write"
	}
	logger.Printf("publishing %s as vfs:// (%s) on %s", root, mode, addr)
	return srv.ListenAndServe()
}

type statusPayload struct {
	ConfigPath  string     `json:"config_path"`
	Root        string     `json:"root,omitempty"`
	Listen      string     `json:"listen,omitempty"`
	Published   bool       `json:"published"`
	Endpoint    string     `json:"endpoint"`
	Socks       string     `json:"socks,omitempty"`
	ViewPath    string     `json:"view_path"`
	ViewEnabled bool       `json:"view_enabled"`
	ViewRules   int        `json:"view_rules"`
	FUSE        FUSEStatus `json:"fuse"`
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv status [-json]")
		fmt.Fprintln(os.Stderr, "  Shows vfs:// config, resolved endpoint, and FUSE/libfuse/macFUSE readiness.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("status takes no positional arguments")
	}
	endpoint, socks, err := vfs.EndpointChecked()
	if err != nil {
		return fmt.Errorf("resolve VFS endpoint: %w", err)
	}
	payload := statusPayload{
		ConfigPath: vfs.ConfigPath(),
		Endpoint:   endpoint,
		Socks:      socks,
		ViewPath:   vfs.ViewPath(),
		FUSE:       currentFUSEStatus(),
	}
	if cfg, err := vfs.LoadConfig(); err == nil {
		payload.Published = true
		payload.Root = cfg.Root
		payload.Listen = cfg.Listen
	}
	if view, err := vfs.LoadView(); err == nil {
		payload.ViewEnabled = true
		payload.ViewRules = len(view.Rules)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("load VFS view: %w", err)
	}
	if *jsonOut {
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Printf("config:   %s\n", vfs.ConfigPath())
	if payload.Published {
		fmt.Printf("root:     %s\n", payload.Root)
		fmt.Printf("listen:   %s\n", payload.Listen)
	} else {
		fmt.Printf("root:     (not published; run `wv share DIR`)\n")
	}
	fmt.Printf("endpoint: %s\n", endpoint)
	if socks != "" {
		fmt.Printf("socks:    %s\n", socks)
	}
	if payload.ViewEnabled {
		fmt.Printf("view:     enabled (%d rule(s)) at %s\n", payload.ViewRules, payload.ViewPath)
	} else {
		fmt.Printf("view:     disabled (%s)\n", payload.ViewPath)
	}
	fmt.Printf("fuse:     %s\n", payload.FUSE.Summary())
	if payload.FUSE.Reason != "" {
		fmt.Printf("          reason: %s\n", payload.FUSE.Reason)
	}
	if payload.FUSE.NextAction != "" && !payload.FUSE.Enabled {
		fmt.Printf("          action: %s\n", payload.FUSE.NextAction)
	}
	return nil
}

func cmdView(args []string) error {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	setFile := fs.String("set", "", "validate and install VFS view JSON from FILE")
	clear := fs.Bool("clear", false, "remove the configured VFS view file")
	example := fs.Bool("example", false, "print an example VFS view JSON document")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv view [-json|-example|-set FILE|-clear]")
		fmt.Fprintln(os.Stderr, "  VFS views hide or rename paths in the vfs:// namespace without changing the published root.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("view takes no positional arguments")
	}
	if *example {
		data, _ := json.MarshalIndent(exampleView(), "", "  ")
		fmt.Println(string(data))
		return nil
	}
	if *clear {
		if err := os.Remove(vfs.ViewPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("VFS view disabled: removed %s\n", vfs.ViewPath())
		return nil
	}
	if *setFile != "" {
		data, err := os.ReadFile(*setFile)
		if err != nil {
			return err
		}
		var cfg vfs.ViewConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		if err := vfs.SaveView(cfg); err != nil {
			return err
		}
		fmt.Printf("VFS view installed: %s\n", vfs.ViewPath())
		return nil
	}
	view, err := vfs.LoadView()
	enabled := true
	if os.IsNotExist(err) {
		view = vfs.DefaultView()
		enabled = false
	} else if err != nil {
		return err
	}
	if *jsonOut {
		payload := struct {
			Path    string         `json:"path"`
			Enabled bool           `json:"enabled"`
			Config  vfs.ViewConfig `json:"config"`
		}{Path: vfs.ViewPath(), Enabled: enabled, Config: view}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if !enabled {
		fmt.Printf("view: disabled\npath: %s\n", vfs.ViewPath())
		return nil
	}
	fmt.Printf("view: enabled\npath: %s\nrules: %d\n", vfs.ViewPath(), len(view.Rules))
	for i, r := range view.Rules {
		if r.Action == vfs.ViewActionRename {
			fmt.Printf("%d. rename %s -> %s\n", i+1, r.Match, r.To)
		} else {
			fmt.Printf("%d. hide %s\n", i+1, r.Match)
		}
	}
	return nil
}

func cmdCat(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: wv cat vfs://PATH")
	}
	view, err := activeView()
	if err != nil {
		return err
	}
	viewRel, sourceRel, err := resolveViewRef(view, args[0])
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	observer, err := newInfrastructureObserver()
	if err != nil {
		return err
	}
	defer observer.Close()
	observer.emitFileOperation(context.Background(), pubsub.FileOpened, pubsub.FileEvent{
		Path:      args[0],
		ViewPath:  viewRel,
		Component: pubsub.ComponentVFS,
		Protocol:  "vfs-9p",
		Subsystem: "vfs",
		Status:    "started",
	})
	data, err := c.ReadFile(sourceRel)
	if err != nil {
		return err
	}
	observer.emitFileOperation(context.Background(), pubsub.FileRead, pubsub.FileEvent{
		Path:      args[0],
		ViewPath:  viewRel,
		Component: pubsub.ComponentVFS,
		Protocol:  "vfs-9p",
		Subsystem: "vfs",
		Bytes:     int64(len(data)),
		Status:    "completed",
	})
	_, err = io.Copy(os.Stdout, strings.NewReader(string(data)))
	return err
}

func cmdRm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wv rm vfs://PATH ...")
	}
	view, err := activeView()
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	observer, err := newInfrastructureObserver()
	if err != nil {
		return err
	}
	defer observer.Close()
	for _, t := range args {
		viewRel, sourceRel, err := resolveViewRef(view, t)
		if err != nil {
			return err
		}
		if sourceRel == "" {
			return fmt.Errorf("refusing to remove the namespace root")
		}
		if err := c.Remove(sourceRel); err != nil {
			return fmt.Errorf("rm %s: %w", t, err)
		}
		observer.emitFileOperation(context.Background(), pubsub.FileRemoved, pubsub.FileEvent{
			Path:      vfs.Scheme + viewRel,
			ViewPath:  viewRel,
			Component: pubsub.ComponentVFS,
			Protocol:  "vfs-9p",
			Subsystem: "vfs",
			Status:    "completed",
		})
		fmt.Printf("removed %s%s\n", vfs.Scheme, viewRel)
	}
	return nil
}

// --- mount (FUSE) ----------------------------------------------------------

// mountOptions is the platform-neutral request; the platform-specific runMount
// (mount_supported.go / mount_other.go) maps it onto go-fuse.
type mountOptions struct {
	mountpoint string
	readWrite  bool
	allowOther bool
	volumeName string
	debug      bool
}

func cmdMount(args []string) error {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	rw := fs.Bool("rw", false, "mount read-write (default: read-only)")
	allowOther := fs.Bool("allow-other", false, "allow other users to access the mount")
	name := fs.String("name", "weaverssh", "volume label (macFUSE)")
	debug := fs.Bool("debug", false, "log FUSE protocol traffic")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv mount DIR [-rw] [-allow-other] [-name LABEL] [-debug]")
		fmt.Fprintln(os.Stderr, "  Mounts the vfs:// namespace at DIR via macFUSE/libfuse. Blocks until")
		fmt.Fprintln(os.Stderr, "  unmounted (Ctrl-C, or `wtool unmount DIR` from another shell).")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("mount needs exactly one mountpoint DIR")
	}
	return runMount(mountOptions{
		mountpoint: fs.Arg(0),
		readWrite:  *rw,
		allowOther: *allowOther,
		volumeName: *name,
		debug:      *debug,
	})
}

func cmdUnmount(args []string) error {
	fs := flag.NewFlagSet("unmount", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: wv unmount DIR") }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("unmount needs exactly one mountpoint DIR")
	}
	return runUnmount(fs.Arg(0))
}

// cmdLibvirtXML prints a libvirt <filesystem> passthrough element for sharing a
// FUSE-mounted vfs:// directory into a guest over virtio-9p, plus the matching
// guest mount command. Platform-neutral: it only emits text.
func cmdLibvirtXML(args []string) error {
	fs := flag.NewFlagSet("libvirt-xml", flag.ContinueOnError)
	mount := fs.String("mount", "", "host path of the FUSE mount to share (required)")
	tag := fs.String("tag", "weaverssh", "9p mount tag the guest will use")
	readonly := fs.Bool("readonly", false, "share read-only")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv libvirt-xml -mount DIR [-tag TAG] [-readonly]")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mount == "" {
		fs.Usage()
		return fmt.Errorf("-mount is required")
	}
	abs, err := filepath.Abs(*mount)
	if err != nil {
		return err
	}
	ro := ""
	if *readonly {
		ro = "\n  <readonly/>"
	}
	fmt.Printf(`<!-- Add inside <devices> in the libvirt domain XML.
     Host: mount the namespace first, e.g.  wtool mount %s
     Then libvirt/QEMU passes that directory into the guest over virtio-9p. -->
<filesystem type='mount' accessmode='passthrough'>
  <driver type='virtiofs'/>
  <source dir='%s'/>
  <target dir='%s'/>%s
</filesystem>

<!-- 9p (trans=virtio) alternative driver:
<filesystem type='mount' accessmode='passthrough'>
  <source dir='%s'/>
  <target dir='%s'/>%s
</filesystem>
-->

# In the guest, mount the share:
#   virtiofs:  mount -t virtiofs %s /mnt/weaverssh
#   9p:        mount -t 9p -o trans=virtio,version=9p2000.L %s /mnt/weaverssh

# Direct (no libvirt): a Linux guest/host can mount the wv-9p TCP export itself:
#   mount -t 9p -o trans=tcp,port=5640,version=9p2000 127.0.0.1 /mnt/weaverssh
`, abs, abs, *tag, ro, abs, *tag, ro, *tag, *tag)
	return nil
}

// --- sshfs over the tunnel -------------------------------------------------

// multiFlag collects a repeatable string flag (e.g. -o a -o b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type sshfsOptions struct {
	remote      string // user@host:/path
	mountpoint  string
	readOnly    bool
	volumeName  string
	extraOpts   []string // each rendered as -o <opt>
	passthrough []string // appended verbatim to the sshfs argv
}

// cmdSshfs mounts a remote sshd host's directory with the system sshfs, routing
// its SSH connection through the weaverssh SOCKS proxy. This needs only stock
// sshd on the remote (no wv-9p/agent there) and reaches hosts that are
// outbound-only/NAT'd, because the proxy is the tunnel's local SOCKS endpoint.
func cmdSshfs(args []string) error {
	fs := flag.NewFlagSet("sshfs", flag.ContinueOnError)
	socks := fs.String("socks", envOr("WEAVERSSH_SOCKS", "127.0.0.1:1080"), "SOCKS5 proxy host:port (empty to connect directly, no tunnel)")
	connector := fs.String("connector", "", "override the SOCKS connector ProxyCommand (use %h %p; %s expands to the proxy addr)")
	ro := fs.Bool("ro", false, "mount read-only")
	name := fs.String("name", "", "volume label (macOS)")
	dryRun := fs.Bool("print", false, "print the sshfs command and exit without mounting")
	var oOpts multiFlag
	fs.Var(&oOpts, "o", "extra -o option passed to sshfs (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv sshfs [flags] user@host:/path MOUNTPOINT [-- extra sshfs args]")
		fmt.Fprintln(os.Stderr, "  Mounts a remote sshd host over the weaverssh SOCKS tunnel (no remote install needed).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fs.Usage()
		return fmt.Errorf("sshfs needs user@host:/path and a MOUNTPOINT")
	}
	opts := sshfsOptions{
		remote:      rest[0],
		mountpoint:  rest[1],
		readOnly:    *ro,
		volumeName:  *name,
		extraOpts:   oOpts,
		passthrough: rest[2:],
	}
	conn, err := resolveConnector(*connector, *socks)
	if err != nil {
		return err
	}
	sshfsArgs := buildSshfsArgs(opts, conn)

	if *dryRun {
		fmt.Println(shellJoin(append([]string{"sshfs"}, sshfsArgs...)))
		return nil
	}
	if _, err := exec.LookPath("sshfs"); err != nil {
		return fmt.Errorf("sshfs not found in PATH (install sshfs / macFUSE-sshfs); run with -print to see the command")
	}
	if err := os.MkdirAll(opts.mountpoint, 0o755); err != nil {
		return fmt.Errorf("mountpoint %s: %w", opts.mountpoint, err)
	}
	if conn != "" {
		fmt.Printf("sshfs %s -> %s via SOCKS %s\n", opts.remote, opts.mountpoint, *socks)
	} else {
		fmt.Printf("sshfs %s -> %s (direct, no tunnel)\n", opts.remote, opts.mountpoint)
	}
	cmd := exec.Command("sshfs", sshfsArgs...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// buildSshfsArgs renders the sshfs argv. conn, when non-empty, is the
// ProxyCommand that routes ssh through the SOCKS proxy.
func buildSshfsArgs(o sshfsOptions, conn string) []string {
	args := []string{o.remote, o.mountpoint}
	if conn != "" {
		args = append(args, "-o", "ProxyCommand="+conn)
	}
	// Resilient defaults: survive tunnel blips and detect dead sessions.
	args = append(args, "-o", "reconnect", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3")
	if o.readOnly {
		args = append(args, "-o", "ro")
	}
	if o.volumeName != "" {
		args = append(args, "-o", "volname="+o.volumeName)
	}
	for _, e := range o.extraOpts {
		args = append(args, "-o", e)
	}
	args = append(args, o.passthrough...)
	return args
}

// resolveConnector returns the ssh ProxyCommand that tunnels through the SOCKS
// proxy. An empty socks means a direct connection (no ProxyCommand). A custom
// template may use %s for the proxy address and must keep ssh's %h/%p tokens.
func resolveConnector(template, socks string) (string, error) {
	if strings.TrimSpace(socks) == "" {
		return "", nil
	}
	if template != "" {
		return strings.ReplaceAll(template, "%s", socks), nil
	}
	if _, err := exec.LookPath("ncat"); err == nil {
		return fmt.Sprintf("ncat --proxy %s --proxy-type socks5 %%h %%p", socks), nil
	}
	if _, err := exec.LookPath("nc"); err == nil {
		// OpenBSD/macOS nc: -X 5 selects SOCKS5, -x sets the proxy address.
		return fmt.Sprintf("nc -X 5 -x %s %%h %%p", socks), nil
	}
	return "", fmt.Errorf("no SOCKS connector found: install ncat or openbsd-nc, or pass -connector")
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// shellJoin renders argv for display, quoting tokens that contain whitespace.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t") {
			out[i] = "'" + a + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// --- helpers ---------------------------------------------------------------

func activeView() (vfs.ViewConfig, error) {
	view, err := vfs.LoadView()
	if os.IsNotExist(err) {
		return vfs.DefaultView(), nil
	}
	if err != nil {
		return vfs.ViewConfig{}, fmt.Errorf("load VFS view: %w", err)
	}
	return view, nil
}

func resolveViewRef(view vfs.ViewConfig, ref string) (viewRel, sourceRel string, err error) {
	viewRel, err = vfs.ParsePath(ref)
	if err != nil {
		return "", "", err
	}
	sourceRel, hidden, err := view.SourcePath(viewRel)
	if err != nil {
		return "", "", err
	}
	if hidden {
		return "", "", fmt.Errorf("%s is hidden by the active VFS view", ref)
	}
	return viewRel, sourceRel, nil
}

func exampleView() vfs.ViewConfig {
	return vfs.ViewConfig{
		Version: vfs.ViewVersion,
		Rules: []vfs.ViewRule{
			{Action: vfs.ViewActionHide, Match: ".git"},
			{Action: vfs.ViewActionHide, Match: "node_modules"},
			{Action: vfs.ViewActionRename, Match: "docs", To: "Documentation"},
		},
	}
}

func isLocalDir(p string) bool {
	if strings.HasSuffix(p, string(os.PathSeparator)) || strings.HasSuffix(p, "/") {
		return true
	}
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func localJoinDir(dst, rel string) string {
	if isLocalDir(dst) {
		return filepath.Join(dst, path.Base(rel))
	}
	return dst
}

func joinRel(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func splitRel(rel string) (parent, name string) {
	rel = strings.Trim(rel, "/")
	i := strings.LastIndex(rel, "/")
	if i < 0 {
		return "", rel
	}
	return rel[:i], rel[i+1:]
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

func removeFlag(ss []string, flagName string) []string {
	out := ss[:0:0]
	for _, s := range ss {
		if s == flagName {
			continue
		}
		out = append(out, s)
	}
	return out
}
