package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// topLevelCommands is the verb list used by help and shell completion.
var topLevelCommands = []string{
	"agent", "proxy", "relay", "server",
	"share", "ls", "cp", "mkdir", "cat", "rm", "mount", "unmount", "sshfs", "status",
	"connection", "connections", "mcp", "pubsub", "events", "compat", "compatibility", "node-context", "context", "rules", "policy", "9p-adapter", "9p-provider", "vfs-provider", "instrument", "observe", "flow", "buffer", "buffers", "deps", "dependencies", "install", "push-agent", "build", "completion", "version", "help",
}

// deployInstall installs this wv binary into one or more remote hosts'
// ~/.weaverssh/bin over SSH — a persistent, no-root, per-user install for hosts
// where you only have an SSH login. Unlike push-agent it does not run anything.
// For each host it detects the OS/arch (`uname -sm`) and produces a matching
// binary via the project's build matrix (falling back to a plain cross-build),
// caching per target so same-arch hosts share one build, and adds
// ~/.weaverssh/bin to the remote shell PATH.
func deployInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", ".weaverssh/bin", "remote install dir, relative to the remote $HOME")
	binary := fs.String("binary", "", "binary to install (default: matched per host)")
	target := fs.String("target", "", "force GOOS/GOARCH for all hosts (skip remote detection)")
	noRC := fs.Bool("no-rc", false, "do not add ~/.weaverssh/bin to the remote shell PATH")
	scpBin := fs.String("scp", "scp", "scp command to use")
	sshBin := fs.String("ssh", "ssh", "ssh command to use")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv install [flags] [user@]host... [-- extra ssh args]")
		fmt.Fprintln(os.Stderr, "  Installs wv into each host's ~/.weaverssh/bin over SSH (no root, persistent).")
		fmt.Fprintln(os.Stderr, "  Detects each host's OS/arch and builds a matching binary via the build matrix.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	hosts, sshExtra := splitDashDash(fs.Args())
	if len(hosts) == 0 {
		fs.Usage()
		return 2
	}

	remoteDir := *dir
	remoteWV := remoteDir + "/wv"

	b := newBinBuilder()
	defer b.cleanup()

	failures := 0
	for _, host := range hosts {
		src, err := resolveBinary(host, *binary, *target, *sshBin, sshExtra, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "install %s: %v\n", host, err)
			failures++
			continue
		}
		if err := deployTo(*sshBin, *scpBin, host, sshExtra, src, remoteDir, remoteWV, *noRC); err != nil {
			fmt.Fprintf(os.Stderr, "install %s: %v\n", host, err)
			failures++
			continue
		}
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "install: %d of %d host(s) failed\n", failures, len(hosts))
		return 1
	}
	return 0
}

// deployTo places src at the host's ~/<remoteWV>, chmods it, and (unless noRC)
// adds the dir to the remote shell PATH.
func deployTo(sshBin, scpBin, host string, sshExtra []string, src, remoteDir, remoteWV string, noRC bool) error {
	if err := runStdio(sshBin, append(append([]string{}, sshExtra...), host, "mkdir -p ~/"+remoteDir)); err != nil {
		return fmt.Errorf("mkdir ~/%s: %w", remoteDir, err)
	}
	fmt.Printf("install %s: copying %s -> ~/%s\n", host, src, remoteWV)
	if err := runStdio(scpBin, append([]string{src, host + ":" + remoteWV}, sshExtra...)); err != nil {
		return fmt.Errorf("scp: %w", err)
	}
	if err := runStdio(sshBin, append(append([]string{}, sshExtra...), host, "chmod +x ~/"+remoteWV)); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if !noRC {
		if err := runStdio(sshBin, append(append([]string{}, sshExtra...), host, pathRCScript(remoteDir))); err != nil {
			fmt.Fprintf(os.Stderr, "install %s: binary installed but PATH update failed: %v\n", host, err)
		}
	}
	fmt.Printf("install %s: done (~/%s)\n", host, remoteWV)
	return nil
}

// resolveBinary returns the local path to a wv binary matching the host: an
// explicit --binary, this executable when the target matches local, or a
// freshly built one (via binBuilder) otherwise.
func resolveBinary(host, binaryFlag, targetFlag, sshBin string, sshExtra []string, b *binBuilder) (string, error) {
	if binaryFlag != "" {
		return binaryFlag, nil
	}
	var goos, goarch string
	if targetFlag != "" {
		g, a, ok := splitTarget(targetFlag)
		if !ok {
			return "", fmt.Errorf("invalid --target %q (want GOOS/GOARCH)", targetFlag)
		}
		goos, goarch = g, a
	} else {
		g, a, err := detectRemotePlatform(sshBin, host, sshExtra)
		if err != nil {
			fmt.Fprintf(os.Stderr, "install %s: platform detection failed (%v); using this %s/%s binary\n", host, err, runtime.GOOS, runtime.GOARCH)
			return os.Executable()
		}
		goos, goarch = g, a
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		return os.Executable()
	}
	fmt.Printf("install %s: target %s/%s; building...\n", host, goos, goarch)
	return b.forTarget(goos, goarch)
}

// binBuilder produces wv binaries per GOOS/GOARCH, preferring the project build
// matrix and falling back to a plain cross-build. Results are cached per target
// and temp dirs are cleaned up at the end.
type binBuilder struct {
	script    string
	hasScript bool
	matrixDir string
	cache     map[string]string
	tmps      []string
}

func newBinBuilder() *binBuilder {
	script, ok := matrixScriptPath()
	return &binBuilder{script: script, hasScript: ok, cache: map[string]string{}}
}

func (b *binBuilder) forTarget(goos, goarch string) (string, error) {
	spec := goos + "/" + goarch
	if p, ok := b.cache[spec]; ok {
		return p, nil
	}
	var p string
	var err error
	if b.hasScript {
		if b.matrixDir == "" {
			if b.matrixDir, err = os.MkdirTemp("", "wv-matrix-"); err != nil {
				return "", err
			}
		}
		if p, err = matrixBuildOne(b.script, spec, b.matrixDir); err == nil {
			b.cache[spec] = p
			return p, nil
		}
		fmt.Fprintf(os.Stderr, "install: matrix build failed (%v); falling back to plain go build\n", err)
	}
	path, tmp, berr := crossBuildWV(goos, goarch)
	if berr != nil {
		if !b.hasScript {
			return "", fmt.Errorf("%w (run from a weaverssh checkout, or pass --binary)", berr)
		}
		return "", berr
	}
	b.tmps = append(b.tmps, tmp)
	b.cache[spec] = path
	return path, nil
}

func (b *binBuilder) cleanup() {
	for _, t := range b.tmps {
		_ = os.RemoveAll(t)
	}
	if b.matrixDir != "" {
		_ = os.RemoveAll(b.matrixDir)
	}
}

// splitDashDash splits args at the first "--": everything before is hosts,
// everything after is extra ssh/scp args applied to all hosts.
func splitDashDash(args []string) (before, after []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// splitTarget parses "GOOS/GOARCH".
func splitTarget(s string) (string, string, bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// detectRemotePlatform runs `uname -sm` on the host and maps it to GOOS/GOARCH.
func detectRemotePlatform(sshBin, host string, sshExtra []string) (goos, goarch string, err error) {
	out, err := exec.Command(sshBin, append(append([]string{}, sshExtra...), host, "uname -sm")...).Output()
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", "", fmt.Errorf("unexpected `uname -sm` output: %q", strings.TrimSpace(string(out)))
	}
	return mapUname(fields[0], fields[1])
}

// mapUname translates `uname -s`/`uname -m` values to Go's GOOS/GOARCH.
func mapUname(osName, machine string) (string, string, error) {
	goos := strings.ToLower(osName)
	switch goos {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd":
		// already a valid GOOS
	}
	var goarch string
	switch machine {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	case "armv7l", "armv6l", "arm":
		goarch = "arm"
	case "i386", "i686":
		goarch = "386"
	default:
		goarch = machine
	}
	return goos, goarch, nil
}

// crossBuildWV builds cmd/wv for the target platform with the local Go toolchain.
// It requires running from the module checkout. Returns the binary path and its
// temp dir (to clean up).
func crossBuildWV(goos, goarch string) (binPath, tmpDir string, err error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", "", fmt.Errorf("go toolchain not found")
	}
	tmpDir, err = os.MkdirTemp("", "wv-build-")
	if err != nil {
		return "", "", err
	}
	out := filepath.Join(tmpDir, "wv")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/wv")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("go build ./cmd/wv (run from the repo root): %w", err)
	}
	return out, tmpDir, nil
}

// pathRCScript returns an idempotent remote shell snippet that adds the install
// dir to PATH in the user's login rc files.
func pathRCScript(remoteDir string) string {
	line := `export PATH="$HOME/` + remoteDir + `:$PATH"`
	return "set -e\n" +
		"touch ~/.profile\n" +
		"L='" + line + "'\n" +
		"for f in ~/.profile ~/.bashrc ~/.zshrc; do\n" +
		"  [ -e \"$f\" ] || continue\n" +
		"  grep -qF '" + remoteDir + "' \"$f\" 2>/dev/null || printf '\\n# weaverssh\\n%s\\n' \"$L\" >> \"$f\"\n" +
		"done"
}

// pushAgent implements the zero-install remote-exec flow: copy this `wv` binary
// to a remote host over SSH and run the agent from a temp path — no install,
// no package manager, useful on locked-down bastions.
func pushAgent(args []string) int {
	fs := flag.NewFlagSet("push-agent", flag.ContinueOnError)
	port := fs.Int("port", 6000, "agent port on the remote host")
	remotePath := fs.String("remote-path", "/tmp/wv", "where to place the binary on the remote")
	binary := fs.String("binary", "", "binary to push (default: this wv executable)")
	scpBin := fs.String("scp", "scp", "scp command to use")
	sshBin := fs.String("ssh", "ssh", "ssh command to use")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv push-agent [flags] [user@]host [-- extra ssh args]")
		fmt.Fprintln(os.Stderr, "  Copies this wv binary to the host and runs `wv agent` from it.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return 2
	}
	host := fs.Arg(0)
	sshExtra := fs.Args()[1:]

	src := *binary
	if src == "" {
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "push-agent: cannot locate this binary: %v\n", err)
			return 1
		}
		src = self
	}

	// 1. copy the binary over.
	fmt.Printf("push-agent: copying %s -> %s:%s\n", src, host, *remotePath)
	scpArgs := append([]string{src, host + ":" + *remotePath}, sshExtra...)
	if err := runStdio(*scpBin, scpArgs); err != nil {
		fmt.Fprintf(os.Stderr, "push-agent: scp failed: %v (note: the binary must match the remote OS/arch)\n", err)
		return 1
	}

	// 2. run the agent from the pushed binary.
	remoteCmd := fmt.Sprintf("chmod +x %s && %s agent --port %d", *remotePath, *remotePath, *port)
	fmt.Printf("push-agent: starting agent on %s (port %d)\n", host, *port)
	sshArgs := append(append([]string{}, sshExtra...), host, remoteCmd)
	if err := runStdio(*sshBin, sshArgs); err != nil {
		fmt.Fprintf(os.Stderr, "push-agent: remote agent exited: %v\n", err)
		return 1
	}
	return 0
}

func runStdio(name string, args []string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// completion prints a shell completion script for the requested shell.
func completion(args []string) int {
	shell := "bash"
	if len(args) > 0 {
		shell = args[0]
	}
	switch shell {
	case "bash":
		fmt.Printf(bashCompletion, joinWords(topLevelCommands))
	case "zsh":
		fmt.Printf(zshCompletion, joinWords(topLevelCommands))
	case "fish":
		for _, c := range topLevelCommands {
			fmt.Printf("complete -c wv -n __fish_use_subcommand -a %s\n", c)
		}
	default:
		fmt.Fprintf(os.Stderr, "wv completion: unsupported shell %q (use bash|zsh|fish)\n", shell)
		return 2
	}
	return 0
}

func joinWords(ws []string) string {
	out := ""
	for i, w := range ws {
		if i > 0 {
			out += " "
		}
		out += w
	}
	return out
}

const bashCompletion = `# wv bash completion — source this or install to /etc/bash_completion.d/wv
_wv_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "%s" -- "$cur") )
    return 0
  fi
  COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -F _wv_complete wv
`

const zshCompletion = `#compdef wv
# wv zsh completion — place on your $fpath as _wv
_wv() {
  local -a cmds
  cmds=(%s)
  if (( CURRENT == 2 )); then
    compadd -- $cmds
  else
    _files
  fi
}
_wv "$@"
`
