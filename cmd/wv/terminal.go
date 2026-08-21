package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"weaverssh/containerstream"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
	"weaverssh/terminalsession"
)

const defaultTerminalDetachByte = byte(0x1d) // Ctrl-]

var errTerminalDetached = errors.New("terminal detached")

type repeatedTerminalOption []string

func (o *repeatedTerminalOption) String() string { return strings.Join(*o, ",") }
func (o *repeatedTerminalOption) Set(value string) error {
	*o = append(*o, value)
	return nil
}

func cmdTerminal(args []string) int {
	if len(args) == 0 {
		printTerminalUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "connect", "open":
		return cmdTerminalConnect(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "reattach", "resume":
		return cmdTerminalReattach(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "terminate", "kill":
		return cmdTerminalTerminate(args[1:], os.Stdout, os.Stderr)
	case "inspect", "status":
		return cmdTerminalInspect(args[1:], os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		printTerminalUsage(os.Stdout)
		return 0
	default:
		return cmdTerminalConnect(args, os.Stdin, os.Stdout, os.Stderr)
	}
}

func printTerminalUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: wv terminal connect [options] NODE TARGET ACTION [ARG ...]")
	fmt.Fprintln(writer, "       wv terminal reattach [options] SESSION_OR_FILE")
	fmt.Fprintln(writer, "       wv terminal terminate SESSION_OR_FILE")
	fmt.Fprintln(writer, "       wv terminal inspect [--json] SESSION_OR_FILE")
	fmt.Fprintln(writer, "ACTION is policy-defined. Ctrl-] detaches without terminating the remote PTY.")
}

func cmdTerminalConnect(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("terminal connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", "", "request one policy-allowed provider; default is locked discovery")
	namespace := fs.String("namespace", "", "orchestration namespace option")
	container := fs.String("container", "", "Kubernetes container option")
	task := fs.String("task", "", "Nomad task option")
	termName := fs.String("term", strings.TrimSpace(os.Getenv("TERM")), "remote TERM value")
	rows := fs.Uint("rows", 0, "initial terminal rows; detected when zero")
	cols := fs.Uint("cols", 0, "initial terminal columns; detected when zero")
	sessionFile := fs.String("session-file", "", "owner-only resume-state path")
	detachKey := fs.String("detach-key", "ctrl-]", "local detach key: ctrl-] or none")
	noRaw := fs.Bool("no-raw", false, "do not place stdin in raw mode")
	timeout := fs.Duration("timeout", 15*time.Second, "broker and negotiation timeout")
	var options repeatedTerminalOption
	fs.Var(&options, "option", "bounded provider option NAME=VALUE; repeatable")
	fs.Usage = func() { printTerminalUsage(stderr); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 3 || *timeout <= 0 || *rows > 65535 || *cols > 65535 {
		fs.Usage()
		return 2
	}
	node, targetID, action := strings.TrimSpace(fs.Arg(0)), strings.TrimSpace(fs.Arg(1)), strings.TrimSpace(fs.Arg(2))
	targetURI, err := buildTerminalTargetURI(node, targetID, *provider, *namespace, *container, *task, options)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: target: %v\n", err)
		return 2
	}
	size := resolveTerminalSize(stdin, stdout, uint16(*rows), uint16(*cols))
	detachByte, err := parseDetachKey(*detachKey)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 2
	}
	request := terminalsession.OpenRequest{
		Protocol: terminalsession.ProtocolVersion, Operation: terminalsession.OperationConnect,
		TargetURI: targetURI, Action: action, Args: append([]string(nil), fs.Args()[3:]...),
		Rows: size.Rows, Cols: size.Cols, Term: strings.TrimSpace(*termName),
	}
	client, ready, err := openTerminalSession(node, request, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	defer client.Close()
	if ready.ResumeToken == "" {
		_ = client.Terminate(context.Background())
		fmt.Fprintln(stderr, "wv terminal: agent omitted initial resume token")
		return 1
	}
	statePath := strings.TrimSpace(*sessionFile)
	if statePath == "" {
		statePath, err = defaultTerminalStatePath(ready.SessionID)
		if err != nil {
			_ = client.Terminate(context.Background())
			fmt.Fprintf(stderr, "wv terminal: resume state: %v\n", err)
			return 1
		}
	}
	now := time.Now().UTC()
	state := terminalsession.ClientState{
		Version: terminalsession.ClientStateVersion, Node: node, SessionID: ready.SessionID,
		ResumeToken: ready.ResumeToken, CreatedAt: now, UpdatedAt: now,
	}
	if err := terminalsession.SaveClientState(statePath, state); err != nil {
		_ = client.Terminate(context.Background())
		fmt.Fprintf(stderr, "wv terminal: save resume state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "wv terminal: session=%s resume=%s detach=%s\n", ready.SessionID, statePath, detachKeyLabel(detachByte))
	return runTerminalClient(client, statePath, &state, stdin, stdout, stderr, !*noRaw, detachByte, size)
}

func cmdTerminalReattach(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("terminal reattach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	detachKey := fs.String("detach-key", "ctrl-]", "local detach key: ctrl-] or none")
	noRaw := fs.Bool("no-raw", false, "do not place stdin in raw mode")
	rows := fs.Uint("rows", 0, "initial terminal rows; detected when zero")
	cols := fs.Uint("cols", 0, "initial terminal columns; detected when zero")
	timeout := fs.Duration("timeout", 15*time.Second, "broker and negotiation timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *timeout <= 0 || *rows > 65535 || *cols > 65535 {
		printTerminalUsage(stderr)
		return 2
	}
	statePath, state, err := resolveTerminalClientState(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	if state.Terminated {
		fmt.Fprintln(stderr, "wv terminal: session is already terminated")
		return 1
	}
	detachByte, err := parseDetachKey(*detachKey)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 2
	}
	size := resolveTerminalSize(stdin, stdout, uint16(*rows), uint16(*cols))
	request := terminalsession.OpenRequest{
		Protocol: terminalsession.ProtocolVersion, Operation: terminalsession.OperationReattach,
		SessionID: state.SessionID, ResumeToken: state.ResumeToken, AfterSequence: state.LastSequence,
		Rows: size.Rows, Cols: size.Cols,
	}
	client, ready, err := openTerminalSession(state.Node, request, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	defer client.Close()
	if ready.SessionID != state.SessionID {
		fmt.Fprintln(stderr, "wv terminal: agent returned a different session ID")
		return 1
	}
	fmt.Fprintf(stderr, "wv terminal: reattached session=%s generation=%d detach=%s\n", ready.SessionID, ready.Generation, detachKeyLabel(detachByte))
	return runTerminalClient(client, statePath, &state, stdin, stdout, stderr, !*noRaw, detachByte, size)
}

func cmdTerminalTerminate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("terminal terminate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 15*time.Second, "broker and negotiation timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *timeout <= 0 {
		printTerminalUsage(stderr)
		return 2
	}
	statePath, state, err := resolveTerminalClientState(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	if state.Terminated {
		fmt.Fprintf(stdout, "terminal session %s is already terminated\n", state.SessionID)
		return 0
	}
	request := terminalsession.OpenRequest{
		Protocol: terminalsession.ProtocolVersion, Operation: terminalsession.OperationReattach,
		SessionID: state.SessionID, ResumeToken: state.ResumeToken, AfterSequence: state.LastSequence,
	}
	client, _, err := openTerminalSession(state.Node, request, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	defer client.Close()
	exit, err := terminateTerminalClient(client, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: terminate: %v\n", err)
		return 1
	}
	state.Terminated = true
	state.ResumeToken = ""
	state.ExitCode = &exit.ExitCode
	state.UpdatedAt = time.Now().UTC()
	if err := terminalsession.SaveClientState(statePath, state); err != nil {
		fmt.Fprintf(stderr, "wv terminal: save state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "terminated terminal session %s\n", state.SessionID)
	return 0
}

// terminateTerminalClient drains replay concurrently with the terminate
// request. Without the reader, a large replay can fill the mux flow-control
// window before the agent returns from reattach negotiation and reads the
// control frame. FrameExit acknowledges that the session is terminal, whether
// the terminate request won or the process exited concurrently.
func terminateTerminalClient(client *terminalsession.Client, timeout time.Duration) (terminalsession.Exit, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		exit terminalsession.Exit
		err  error
	}
	acknowledged := make(chan result, 1)
	go func() {
		for {
			frame, err := client.ReadEvent()
			if err != nil {
				acknowledged <- result{err: err}
				return
			}
			if frame.Type != terminalsession.FrameExit {
				continue
			}
			exit, err := terminalsession.DecodeExit(frame.Payload)
			acknowledged <- result{exit: exit, err: err}
			return
		}
	}()
	if err := client.Terminate(ctx); err != nil {
		return terminalsession.Exit{}, err
	}
	select {
	case result := <-acknowledged:
		return result.exit, result.err
	case <-ctx.Done():
		return terminalsession.Exit{}, ctx.Err()
	}
}

func cmdTerminalInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("terminal inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit redacted JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printTerminalUsage(stderr)
		return 2
	}
	path, state, err := resolveTerminalClientState(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wv terminal: %v\n", err)
		return 1
	}
	view := struct {
		Version         string `json:"version"`
		Path            string `json:"path"`
		Node            string `json:"node"`
		SessionID       string `json:"session_id"`
		LastSequence    uint64 `json:"last_sequence"`
		ResumeAvailable bool   `json:"resume_available"`
		Terminated      bool   `json:"terminated"`
		ExitCode        *int   `json:"exit_code,omitempty"`
	}{state.Version, path, state.Node, state.SessionID, state.LastSequence, state.ResumeToken != "", state.Terminated, state.ExitCode}
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(view); err != nil {
			fmt.Fprintf(stderr, "wv terminal: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "session=%s node=%s sequence=%d resumable=%t terminated=%t state=%s\n", view.SessionID, view.Node, view.LastSequence, view.ResumeAvailable, view.Terminated, view.Path)
	return 0
}

func openTerminalSession(node string, request terminalsession.OpenRequest, timeout time.Duration) (*terminalsession.Client, terminalsession.Ready, error) {
	metadata, err := terminalsession.NewOpenMetadata(node)
	if err != nil {
		return nil, terminalsession.Ready{}, err
	}
	state, err := sessionbroker.ActiveState()
	if err != nil {
		return nil, terminalsession.Ready{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stream, err := sessionbroker.Dial(ctx, "unix", state.Socket, sessionbroker.OpenRequest{
		Node: node, Service: sessionmux.ServiceTerminal, Data: metadata,
	})
	if err != nil {
		return nil, terminalsession.Ready{}, fmt.Errorf("open %s: %w", node, err)
	}
	client, err := terminalsession.NewClient(stream, terminalsession.Codec{})
	if err != nil {
		_ = stream.Close()
		return nil, terminalsession.Ready{}, err
	}
	ready, err := client.Negotiate(ctx, request)
	if err != nil {
		_ = client.Close()
		return nil, terminalsession.Ready{}, err
	}
	return client, ready, nil
}

func runTerminalClient(client *terminalsession.Client, statePath string, state *terminalsession.ClientState, stdin *os.File, stdout, stderr io.Writer, raw bool, detachByte *byte, initialSize terminalsession.TerminalSize) int {
	if raw && (stdin == nil || !term.IsTerminal(int(stdin.Fd()))) {
		fmt.Fprintln(stderr, "wv terminal: stdin is not a terminal; use --no-raw for scripted input")
		return 2
	}
	var restore func()
	if raw {
		previous, err := term.MakeRaw(int(stdin.Fd()))
		if err != nil {
			fmt.Fprintf(stderr, "wv terminal: raw mode: %v\n", err)
			return 1
		}
		restore = func() { _ = term.Restore(int(stdin.Fd()), previous) }
		defer restore()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := client.Resize(ctx, initialSize); err != nil {
		fmt.Fprintf(stderr, "wv terminal: initial resize: %v\n", err)
		return 1
	}
	resizeEvents := make(chan struct{}, 1)
	stopResize := watchTerminalResize(resizeEvents)
	defer stopResize()
	events := make(chan terminalEventResult, 1)
	go func() {
		for {
			frame, err := client.ReadEvent()
			events <- terminalEventResult{frame: frame, err: err}
			if err != nil {
				return
			}
		}
	}()
	localDetach := &atomic.Bool{}
	inputDone := make(chan error, 1)
	go func() { inputDone <- pumpTerminalInput(ctx, client, stdin, detachByte, localDetach) }()

	for {
		select {
		case result := <-events:
			if result.err != nil {
				state.UpdatedAt = time.Now().UTC()
				_ = terminalsession.SaveClientState(statePath, *state)
				if localDetach.Load() || errors.Is(result.err, io.EOF) && ctx.Err() != nil {
					return 0
				}
				fmt.Fprintf(stderr, "wv terminal: stream ended; reattach with %s: %v\n", statePath, result.err)
				return 1
			}
			switch result.frame.Type {
			case terminalsession.FrameOutput:
				if result.frame.Sequence <= state.LastSequence {
					continue
				}
				if result.frame.Sequence != state.LastSequence+1 && result.frame.Flags&terminalsession.FlagTruncated == 0 {
					fmt.Fprintf(stderr, "wv terminal: output sequence gap: got=%d expected=%d\n", result.frame.Sequence, state.LastSequence+1)
					return 1
				}
				if result.frame.Flags&terminalsession.FlagTruncated != 0 {
					fmt.Fprintf(stderr, "wv terminal: warning: replay before sequence %d was truncated\n", result.frame.Sequence)
				}
				if _, err := stdout.Write(result.frame.Payload); err != nil {
					localDetach.Store(true)
					_ = client.Detach(context.Background())
					fmt.Fprintf(stderr, "wv terminal: output: %v\n", err)
					return 1
				}
				state.LastSequence = result.frame.Sequence
				state.UpdatedAt = time.Now().UTC()
				if err := terminalsession.SaveClientState(statePath, *state); err != nil {
					localDetach.Store(true)
					_ = client.Detach(context.Background())
					fmt.Fprintf(stderr, "wv terminal: save replay cursor: %v\n", err)
					return 1
				}
			case terminalsession.FrameExit:
				exit, err := terminalsession.DecodeExit(result.frame.Payload)
				if err != nil {
					fmt.Fprintf(stderr, "wv terminal: exit status: %v\n", err)
					return 1
				}
				state.Terminated = true
				state.ResumeToken = ""
				state.ExitCode = &exit.ExitCode
				state.UpdatedAt = time.Now().UTC()
				if err := terminalsession.SaveClientState(statePath, *state); err != nil {
					fmt.Fprintf(stderr, "wv terminal: save exit state: %v\n", err)
					return 1
				}
				if exit.ExitCode == 0 {
					return 0
				}
				return 1
			case terminalsession.FramePing:
				if err := client.Pong(ctx); err != nil {
					fmt.Fprintf(stderr, "wv terminal: pong: %v\n", err)
					return 1
				}
			}
		case err := <-inputDone:
			if errors.Is(err, errTerminalDetached) {
				state.UpdatedAt = time.Now().UTC()
				_ = terminalsession.SaveClientState(statePath, *state)
				return 0
			}
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(stderr, "wv terminal: input: %v\n", err)
				return 1
			}
		case <-resizeEvents:
			size := resolveTerminalSize(stdin, stdout, 0, 0)
			if err := client.Resize(ctx, size); err != nil {
				fmt.Fprintf(stderr, "wv terminal: resize: %v\n", err)
				return 1
			}
		case <-ctx.Done():
			localDetach.Store(true)
			_ = client.Detach(context.Background())
			state.UpdatedAt = time.Now().UTC()
			_ = terminalsession.SaveClientState(statePath, *state)
			return 0
		}
	}
}

type terminalEventResult struct {
	frame terminalsession.Frame
	err   error
}

func pumpTerminalInput(ctx context.Context, client *terminalsession.Client, stdin io.Reader, detachByte *byte, localDetach *atomic.Bool) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := stdin.Read(buffer)
		if n > 0 {
			payload := buffer[:n]
			if detachByte != nil {
				if index := indexByte(payload, *detachByte); index >= 0 {
					if index > 0 {
						if sendErr := client.SendInput(ctx, payload[:index]); sendErr != nil {
							return sendErr
						}
					}
					localDetach.Store(true)
					if sendErr := client.Detach(context.Background()); sendErr != nil {
						return sendErr
					}
					return errTerminalDetached
				}
			}
			if sendErr := client.SendInput(ctx, payload); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			localDetach.Store(true)
			_ = client.Detach(context.Background())
			if errors.Is(err, io.EOF) {
				return errTerminalDetached
			}
			return err
		}
	}
}

func buildTerminalTargetURI(node, target, provider, namespace, container, task string, rawOptions []string) (string, error) {
	node = strings.TrimSpace(node)
	target = strings.TrimSpace(target)
	if node == "" || target == "" {
		return "", errors.New("node and target are required")
	}
	values := make(url.Values)
	set := func(name, value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if _, exists := values[name]; exists {
			return fmt.Errorf("repeated option %q", name)
		}
		values.Set(name, value)
		return nil
	}
	if err := set("provider", provider); err != nil {
		return "", err
	}
	if err := set("namespace", namespace); err != nil {
		return "", err
	}
	if err := set("container", container); err != nil {
		return "", err
	}
	if err := set("task", task); err != nil {
		return "", err
	}
	for _, raw := range rawOptions {
		name, value, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("invalid option %q; expected NAME=VALUE", raw)
		}
		if err := set(strings.TrimSpace(name), value); err != nil {
			return "", err
		}
	}
	raw := "vfs://container/" + url.PathEscape(node) + "/" + url.PathEscape(target) + "/dev/tty"
	if encoded := values.Encode(); encoded != "" {
		raw += "?" + encoded
	}
	if _, err := containerstream.ParseURI(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func resolveTerminalSize(stdin *os.File, stdout io.Writer, rows, cols uint16) terminalsession.TerminalSize {
	if rows != 0 && cols != 0 {
		return terminalsession.TerminalSize{Rows: rows, Cols: cols}
	}
	width, height := 80, 24
	if file, ok := stdout.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if detectedWidth, detectedHeight, err := term.GetSize(int(file.Fd())); err == nil && detectedWidth > 0 && detectedHeight > 0 {
			width, height = detectedWidth, detectedHeight
		}
	} else if stdin != nil && term.IsTerminal(int(stdin.Fd())) {
		if detectedWidth, detectedHeight, err := term.GetSize(int(stdin.Fd())); err == nil && detectedWidth > 0 && detectedHeight > 0 {
			width, height = detectedWidth, detectedHeight
		}
	}
	if rows != 0 {
		height = int(rows)
	}
	if cols != 0 {
		width = int(cols)
	}
	if height > 65535 {
		height = 65535
	}
	if width > 65535 {
		width = 65535
	}
	return terminalsession.TerminalSize{Rows: uint16(height), Cols: uint16(width)}
}

func parseDetachKey(raw string) (*byte, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "ctrl-]", "^]":
		value := defaultTerminalDetachByte
		return &value, nil
	case "none", "off":
		return nil, nil
	default:
		return nil, errors.New("--detach-key must be ctrl-] or none")
	}
}

func detachKeyLabel(value *byte) string {
	if value == nil {
		return "none"
	}
	return "Ctrl-]"
}

func defaultTerminalStatePath(sessionID string) (string, error) {
	if strings.TrimSpace(sessionID) == "" || strings.ContainsAny(sessionID, `/\\`) {
		return "", errors.New("invalid terminal session ID")
	}
	base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if base == "" {
		if runtime.GOOS == "windows" {
			config, err := os.UserConfigDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(config, "weaverssh", "state")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
	}
	return filepath.Join(base, "weaverssh", "terminals", sessionID+".json"), nil
}

func resolveTerminalClientState(reference string) (string, terminalsession.ClientState, error) {
	reference = strings.TrimSpace(reference)
	path := reference
	if reference == "" {
		return "", terminalsession.ClientState{}, errors.New("terminal session reference is required")
	}
	if !strings.ContainsAny(reference, `/\\`) && filepath.Ext(reference) == "" {
		var err error
		path, err = defaultTerminalStatePath(reference)
		if err != nil {
			return "", terminalsession.ClientState{}, err
		}
	}
	state, err := terminalsession.LoadClientState(path)
	if err != nil {
		return "", terminalsession.ClientState{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", terminalsession.ClientState{}, err
	}
	return absolute, state, nil
}

func indexByte(payload []byte, target byte) int {
	for index, value := range payload {
		if value == target {
			return index
		}
	}
	return -1
}
