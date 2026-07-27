// Package agentbridge forwards the SSH agent protocol between a local endpoint
// (a UNIX socket, or stdin/stdout) and an upstream agent. The upstream may be a
// standard ssh-agent — a UNIX socket, or on Windows the OpenSSH agent named
// pipe — PuTTY Pageant (just a different ssh-agent implementation, reached via
// WM_COPYDATA), or a helper process spoken over stdio.
//
// One wv binary provides both ends, so a WSL2 ssh-agent can use keys held by a
// Windows agent (OpenSSH or Pageant) without socat or a separate helper:
//
//	# WSL2
//	wv agent-bridge --listen ~/.ssh/agent.sock --upstream 'exec:wv.exe agent-bridge --stdio'
//	export SSH_AUTH_SOCK=~/.ssh/agent.sock
package agentbridge

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const agentMaxMessageLength = 8192

// ErrUnsupported marks operations unavailable on the current platform (Pageant
// and Windows named pipes off Windows).
var ErrUnsupported = errors.New("agent-bridge: not supported on this platform")

// agentFailure is SSH_AGENT_FAILURE, returned if the upstream errors mid-message.
var agentFailure = []byte{0, 0, 0, 1, 5}

// upstream is a resolved forwarding target: either a stream agent (dial) or a
// per-message agent (message, e.g. Pageant's WM_COPYDATA).
type upstream struct {
	label   string
	message bool
	dial    func() (io.ReadWriteCloser, error)
}

// Resolve turns a --upstream string into a target. An empty target selects the
// platform default (Windows: OpenSSH agent pipe; otherwise $SSH_AUTH_SOCK).
func Resolve(target string) (upstream, error) {
	target = strings.TrimSpace(target)
	switch {
	case target == "":
		return platformDefaultUpstream()
	case target == "pageant":
		return upstream{label: "pageant", message: true}, nil
	case strings.HasPrefix(target, "unix:"):
		return unixUpstream(strings.TrimPrefix(target, "unix:")), nil
	case strings.HasPrefix(target, "pipe:"):
		name := strings.TrimPrefix(target, "pipe:")
		return upstream{label: "pipe:" + name, dial: func() (io.ReadWriteCloser, error) { return dialPipe(name) }}, nil
	case strings.HasPrefix(target, "exec:"):
		cmdline := strings.TrimPrefix(target, "exec:")
		return upstream{label: "exec:" + cmdline, dial: func() (io.ReadWriteCloser, error) { return dialExec(cmdline) }}, nil
	case strings.HasPrefix(target, "/"), strings.HasPrefix(target, "~/"), strings.HasPrefix(target, "./"):
		return unixUpstream(target), nil
	default:
		return upstream{}, fmt.Errorf("agent-bridge: unknown upstream %q (use unix:PATH, pipe:NAME, pageant, or exec:CMD)", target)
	}
}

func unixUpstream(path string) upstream {
	path = expandTilde(path)
	return upstream{label: "unix:" + path, dial: func() (io.ReadWriteCloser, error) { return net.Dial("unix", path) }}
}

// Serve listens on listenPath (a UNIX socket) and forwards each connection to up.
func Serve(listenPath string, up upstream, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	listenPath = expandTilde(strings.TrimSpace(listenPath))
	if listenPath == "" {
		return errors.New("agent-bridge: listen socket path is required")
	}
	if fi, err := os.Stat(listenPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(listenPath)
	}
	ln, err := net.Listen("unix", listenPath)
	if err != nil {
		return fmt.Errorf("agent-bridge: listen %s: %w", listenPath, err)
	}
	defer ln.Close()
	logf("agent-bridge: %s -> %s", listenPath, up.label)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("agent-bridge: accept: %w", err)
		}
		go func(c net.Conn) {
			if err := handle(c, up); err != nil {
				logf("agent-bridge: connection error: %v", err)
			}
		}(conn)
	}
}

// Stdio forwards stdin/stdout to up. This is the mode a listener execs on the
// far side (e.g. `wv.exe agent-bridge --stdio` invoked from WSL2).
func Stdio(up upstream) error {
	if up.message {
		return bridgeMessages(os.Stdin, os.Stdout)
	}
	us, err := up.dial()
	if err != nil {
		return err
	}
	defer us.Close()
	proxyStreams(stdio{}, us)
	return nil
}

func handle(conn net.Conn, up upstream) error {
	defer conn.Close()
	if up.message {
		return bridgeMessages(conn, conn)
	}
	us, err := up.dial()
	if err != nil {
		return err
	}
	defer us.Close()
	proxyStreams(conn, us)
	return nil
}

// proxyStreams copies bytes both ways until either side closes. The ssh-agent
// protocol is transport-agnostic, so a standard agent needs nothing more.
func proxyStreams(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// bridgeMessages answers length-prefixed ssh-agent requests from r using Query
// (Pageant's WM_COPYDATA is request/response, not a stream) and writes replies
// to w. It returns at EOF.
func bridgeMessages(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(br, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(header)
		if n == 0 || n > agentMaxMessageLength {
			return fmt.Errorf("agent-bridge: invalid request length %d", n)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
		request := make([]byte, 0, 4+len(body))
		request = append(append(request, header...), body...)
		reply, err := Query(request)
		if err != nil {
			reply = agentFailure
		}
		if _, err := w.Write(reply); err != nil {
			return err
		}
	}
}

// dialExec runs cmdline and speaks the agent protocol over its stdio.
func dialExec(cmdline string) (io.ReadWriteCloser, error) {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return nil, errors.New("agent-bridge: empty exec command")
	}
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("agent-bridge: start %q: %w", fields[0], err)
	}
	return &execConn{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

type execConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (e *execConn) Read(p []byte) (int, error)  { return e.stdout.Read(p) }
func (e *execConn) Write(p []byte) (int, error) { return e.stdin.Write(p) }
func (e *execConn) Close() error {
	_ = e.stdin.Close()
	err := e.cmd.Wait()
	_ = e.stdout.Close()
	return err
}

// stdio adapts the process's standard streams to io.ReadWriteCloser.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return nil }

func expandTilde(p string) string {
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
