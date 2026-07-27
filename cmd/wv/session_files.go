package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

type sessionPath struct {
	Node          string
	Path          string
	TrailingSlash bool
}

// cmdFileVerb routes explicit NODE:/path operands through the active dynamic
// session. Commands without such an operand retain the compatibility VFS path.
func cmdFileVerb(verb string, args []string) int {
	hasSessionPath, parseErr := containsSessionPath(args)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "wv %s: %v\n", verb, parseErr)
		return 2
	}
	if !hasSessionPath {
		return runVFSCommand(append([]string{verb}, args...))
	}

	switch verb {
	case "ls":
		return cmdSessionLS(args, os.Stdout, os.Stderr)
	case "cat":
		return cmdSessionCat(args, os.Stdout, os.Stderr)
	case "cp":
		return cmdSessionCP(args, os.Stdin, os.Stdout, os.Stderr)
	case "mkdir":
		return cmdSessionMkdir(args, os.Stderr)
	case "rm":
		return cmdSessionRM(args, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "wv: session file verb %q is not implemented\n", verb)
		return 2
	}
}

func containsSessionPath(args []string) (bool, error) {
	found := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || arg == "" {
			continue
		}
		_, matched, err := parseSessionPath(arg)
		if err != nil {
			return false, err
		}
		found = found || matched
	}
	return found, nil
}

// parseSessionPath recognizes only explicit NODE:/path syntax. vfs:// and
// vfs::NODE:/path remain compatibility forms and are deliberately excluded.
func parseSessionPath(raw string) (sessionPath, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "vfs://") || strings.HasPrefix(raw, "vfs::") || strings.Contains(raw, "://") {
		return sessionPath{}, false, nil
	}

	var node, remote string
	bracketed := strings.HasPrefix(raw, "[")
	if bracketed {
		end := strings.Index(raw, "]:")
		if end < 0 {
			return sessionPath{}, false, nil
		}
		node = raw[1:end]
		remote = raw[end+2:]
	} else {
		index := strings.IndexByte(raw, ':')
		if index <= 0 {
			return sessionPath{}, false, nil
		}
		// Do not interpret Windows drive paths as session paths.
		if index == 1 && len(raw) > 2 && ((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z')) && (raw[2] == '\\' || raw[2] == '/') {
			return sessionPath{}, false, nil
		}
		node = raw[:index]
		remote = raw[index+1:]
	}

	node = strings.TrimSpace(node)
	if node == "" || strings.IndexByte(node, 0) >= 0 {
		return sessionPath{}, true, errors.New("invalid session node reference")
	}
	// A pre-colon token containing path separators is a local path, not a
	// malformed node reference. Bracketed syntax remains an explicit node form.
	if !bracketed && strings.ContainsAny(node, "/\\") {
		return sessionPath{}, false, nil
	}
	if strings.ContainsAny(node, "/\\") {
		return sessionPath{}, true, errors.New("invalid session node reference")
	}
	if strings.Contains(node, "@") {
		return sessionPath{}, true, errors.New("NODE:/path uses a registered node ID, not user@host syntax")
	}
	if remote != "" && !strings.HasPrefix(remote, "/") {
		if strings.HasPrefix(remote, "~") {
			return sessionPath{}, true, errors.New("NODE:~/path home expansion is not defined; use a path rooted in the exported share")
		}
		return sessionPath{}, false, nil
	}
	if strings.IndexByte(remote, 0) >= 0 {
		return sessionPath{}, true, errors.New("session path contains NUL")
	}

	trailingSlash := strings.HasSuffix(remote, "/") && remote != "/"
	cleaned := path.Clean("/" + strings.TrimPrefix(remote, "/"))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "." {
		cleaned = ""
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return sessionPath{}, true, errors.New("session path escapes the exported root")
	}
	return sessionPath{Node: node, Path: cleaned, TrailingSlash: trailingSlash}, true, nil
}

func activeSessionClient(ctx context.Context, node string) (*p9client.Client, error) {
	state, err := sessionbroker.ActiveState()
	if err != nil {
		return nil, err
	}
	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := sessionbroker.Dial(openCtx, "unix", state.Socket, sessionbroker.OpenRequest{
		Node:    node,
		Service: sessionmux.ServiceFS,
	})
	if err != nil {
		return nil, fmt.Errorf("open fs stream for node %s: %w", node, err)
	}
	client, err := p9client.Attach(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func cmdSessionLS(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	long := fs.Bool("l", false, "show type and size")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv ls [-l|--json] NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched {
		fmt.Fprintf(stderr, "wv ls: %v\n", firstError(err, errors.New("expected NODE:/path")))
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv ls: %v\n", err)
		return 1
	}
	defer client.Close()
	entries, err := client.List(ref.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv ls: %v\n", err)
		return 1
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(entries); err != nil {
			fmt.Fprintf(stderr, "wv ls: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range entries {
		name := entry.Name
		if entry.IsDir {
			name += "/"
		}
		if *long {
			kind := "-"
			if entry.IsDir {
				kind = "d"
			}
			fmt.Fprintf(stdout, "%s %12d %s\n", kind, entry.Size, name)
		} else {
			fmt.Fprintln(stdout, name)
		}
	}
	return 0
}

func cmdSessionCat(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv cat NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched || ref.Path == "" {
		fmt.Fprintf(stderr, "wv cat: %v\n", firstError(err, errors.New("expected NODE:/file")))
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 1
	}
	defer client.Close()
	reader, err := client.OpenReader(ref.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 1
	}
	defer reader.Close()
	if _, err := io.Copy(stdout, reader); err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 1
	}
	return 0
}

func cmdSessionMkdir(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mkdir", flag.ContinueOnError)
	fs.SetOutput(stderr)
	parents := fs.Bool("p", false, "create missing parents")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv mkdir [-p] NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched || ref.Path == "" {
		fmt.Fprintf(stderr, "wv mkdir: %v\n", firstError(err, errors.New("expected NODE:/directory")))
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv mkdir: %v\n", err)
		return 1
	}
	defer client.Close()
	if *parents {
		err = client.MkdirAll(ref.Path)
	} else {
		err = client.Mkdir(ref.Path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "wv mkdir: %v\n", err)
		return 1
	}
	return 0
}

func cmdSessionRM(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv rm NODE:/path")
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched || ref.Path == "" {
		fmt.Fprintf(stderr, "wv rm: %v\n", firstError(err, errors.New("refusing to remove the exported root")))
		return 2
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv rm: %v\n", err)
		return 1
	}
	defer client.Close()
	if err := client.Remove(ref.Path); err != nil {
		fmt.Fprintf(stderr, "wv rm: %v\n", err)
		return 1
	}
	return 0
}

func cmdSessionCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: wv cp SOURCE DESTINATION")
		return 2
	}
	srcRaw, dstRaw := fs.Arg(0), fs.Arg(1)
	src, srcRemote, srcErr := parseSessionPath(srcRaw)
	dst, dstRemote, dstErr := parseSessionPath(dstRaw)
	if srcErr != nil || dstErr != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", firstError(srcErr, dstErr))
		return 2
	}
	if srcRemote && dstRemote {
		fmt.Fprintln(stderr, "wv cp: node-to-node copy is not implemented; copy through an explicit local file or stream")
		return 2
	}
	if !srcRemote && !dstRemote {
		return runVFSCommand(append([]string{"cp"}, args...))
	}
	if srcRemote {
		return copySessionToLocal(src, dstRaw, stdout, stderr)
	}
	return copyLocalToSession(srcRaw, dst, stdin, stderr)
}

func copySessionToLocal(src sessionPath, destination string, stdout, stderr io.Writer) int {
	if src.Path == "" {
		fmt.Fprintln(stderr, "wv cp: source must be a file, not the exported root")
		return 2
	}
	client, err := activeSessionClient(context.Background(), src.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	defer client.Close()
	reader, err := client.OpenReader(src.Path)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	defer reader.Close()
	if destination == "-" {
		if _, err := io.Copy(stdout, reader); err != nil {
			fmt.Fprintf(stderr, "wv cp: %v\n", err)
			return 1
		}
		return 0
	}

	finalPath := destination
	if info, err := os.Stat(destination); err == nil && info.IsDir() {
		finalPath = filepath.Join(destination, path.Base(src.Path))
	} else if strings.HasSuffix(destination, string(os.PathSeparator)) {
		fmt.Fprintf(stderr, "wv cp: local destination directory does not exist: %s\n", destination)
		return 1
	}
	dir := filepath.Dir(finalPath)
	tmp, err := os.CreateTemp(dir, ".wv-download-*")
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, reader); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	if err := tmp.Close(); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	ok = true
	return 0
}

func copyLocalToSession(source string, dst sessionPath, stdin io.Reader, stderr io.Writer) int {
	var reader io.Reader
	var closer io.Closer
	var sourceName string
	perm := uint32(0o644)
	if source == "-" {
		reader = stdin
	} else {
		file, err := os.Open(source)
		if err != nil {
			fmt.Fprintf(stderr, "wv cp: %v\n", err)
			return 1
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			fmt.Fprintf(stderr, "wv cp: %v\n", err)
			return 1
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			fmt.Fprintln(stderr, "wv cp: recursive directory copy is not implemented")
			return 2
		}
		reader, closer, sourceName = file, file, filepath.Base(source)
		perm = uint32(info.Mode().Perm())
	}
	if closer != nil {
		defer closer.Close()
	}

	client, err := activeSessionClient(context.Background(), dst.Node)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	defer client.Close()
	remotePath := dst.Path
	if remotePath == "" || dst.TrailingSlash {
		if sourceName == "" {
			fmt.Fprintln(stderr, "wv cp: stdin upload requires a destination file name")
			return 2
		}
		remotePath = path.Join(remotePath, sourceName)
	} else if entry, statErr := client.Stat(remotePath); statErr == nil && entry.IsDir {
		if sourceName == "" {
			fmt.Fprintln(stderr, "wv cp: stdin upload to a directory requires a destination file name")
			return 2
		}
		remotePath = path.Join(remotePath, sourceName)
	}
	writer, err := client.OpenWriter(remotePath, perm)
	if err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	defer writer.Close()
	if _, err := io.Copy(writer, reader); err != nil {
		fmt.Fprintf(stderr, "wv cp: %v\n", err)
		return 1
	}
	return 0
}

func firstError(errorsIn ...error) error {
	for _, err := range errorsIn {
		if err != nil {
			return err
		}
	}
	return errors.New("invalid argument")
}
