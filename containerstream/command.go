package containerstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

const maxCommandStderr = 64 << 10

// Command is an argv-only streaming invocation. Providers never invoke a shell.
type Command struct {
	Args           []string          `json:"args"`
	Environment    map[string]string `json:"environment,omitempty"`
	InheritHostEnv bool              `json:"inherit_host_environment,omitempty"`
}

// CommandRunner starts a provider command and exposes its stdout as a stream.
// Tests and embedders can replace it without depending on host CLIs.
type CommandRunner interface {
	Open(context.Context, Command) (io.ReadCloser, error)
}

// DuplexCommandRunner is the optional command-runner extension used by the
// synthetic process filesystem. It exposes all three standard streams without
// buffering the process payload.
type DuplexCommandRunner interface {
	CommandRunner
	Start(context.Context, Command) (Process, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Start(ctx context.Context, request Command) (Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(request.Args) == 0 || strings.TrimSpace(request.Args[0]) == "" {
		return nil, errors.New("containerstream: provider command is required")
	}
	command := exec.CommandContext(ctx, request.Args[0], request.Args[1:]...)
	environment, err := commandEnvironment(request)
	if err != nil {
		return nil, err
	}
	command.Env = environment
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("containerstream: open provider stdin: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("containerstream: open provider stdout: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("containerstream: open provider stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("containerstream: start %s: %w", request.Args[0], err)
	}
	return &commandProcess{
		command: command,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		done:    make(chan struct{}),
	}, nil
}

func (OSCommandRunner) Open(ctx context.Context, request Command) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(request.Args) == 0 || strings.TrimSpace(request.Args[0]) == "" {
		return nil, errors.New("containerstream: provider command is required")
	}
	command := exec.CommandContext(ctx, request.Args[0], request.Args[1:]...)
	environment, err := commandEnvironment(request)
	if err != nil {
		return nil, err
	}
	command.Env = environment
	stderr := &boundedWriter{maximum: maxCommandStderr}
	command.Stderr = stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("containerstream: open provider stdout: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("containerstream: start %s: %w", request.Args[0], err)
	}
	return &processStream{stdout: stdout, command: command, stderr: stderr}, nil
}

func commandEnvironment(request Command) ([]string, error) {
	values := map[string]string{}
	if request.InheritHostEnv {
		for _, entry := range os.Environ() {
			name, value, ok := strings.Cut(entry, "=")
			if ok && validEnvironmentName(name) && !strings.ContainsAny(value, "\x00\r\n") {
				values[name] = value
			}
		}
	}
	for name, value := range request.Environment {
		if !validEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("containerstream: invalid environment entry %q", name)
		}
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+"="+values[name])
	}
	return out, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

type boundedWriter struct {
	buffer  bytes.Buffer
	maximum int
	mu      sync.Mutex
}

func (w *boundedWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(payload)
	remaining := w.maximum - w.buffer.Len()
	if remaining > 0 {
		if len(payload) > remaining {
			payload = payload[:remaining]
		}
		_, _ = w.buffer.Write(payload)
	}
	return original, nil
}

func (w *boundedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(w.buffer.String())
}

type processStream struct {
	stdout  io.ReadCloser
	command *exec.Cmd
	stderr  *boundedWriter
	mu      sync.Mutex
	done    bool
	waitErr error
}

type commandProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser

	waitOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
	result    ProcessResult
}

func (p *commandProcess) ProviderName() string { return "" }
func (p *commandProcess) Capabilities() ProcessCapabilities {
	return ProcessCapabilities{Stdin: true, Stdout: true, Stderr: true}
}
func (p *commandProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *commandProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *commandProcess) Stderr() io.ReadCloser { return p.stderr }

func (p *commandProcess) Wait() ProcessResult {
	p.waitOnce.Do(func() {
		err := p.command.Wait()
		exitCode := 0
		if err != nil {
			exitCode = -1
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				exitCode = exitError.ExitCode()
			}
		}
		p.result = ProcessResult{ExitCode: exitCode, Err: err}
		close(p.done)
	})
	<-p.done
	return p.result
}

func (p *commandProcess) Signal(context.Context, ProcessSignal) error {
	return ErrControlUnsupported
}

func (p *commandProcess) Resize(context.Context, TerminalSize) error {
	return ErrControlUnsupported
}

func (p *commandProcess) Close() error {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()
		if p.command.Process != nil {
			_ = p.command.Process.Kill()
		}
	})
	_ = p.Wait()
	return nil
}

func (s *processStream) Read(payload []byte) (int, error) {
	n, err := s.stdout.Read(payload)
	if !errors.Is(err, io.EOF) {
		return n, err
	}
	if waitErr := s.wait(false); waitErr != nil {
		return n, waitErr
	}
	return n, io.EOF
}

func (s *processStream) Close() error {
	_ = s.stdout.Close()
	return s.wait(true)
}

func (s *processStream) wait(cancel bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return s.waitErr
	}
	if cancel && s.command.Process != nil {
		_ = s.command.Process.Kill()
	}
	err := s.command.Wait()
	if cancel {
		err = nil
	}
	if err != nil {
		detail := s.stderr.String()
		if detail != "" {
			err = fmt.Errorf("containerstream: provider command failed: %w: %s", err, detail)
		} else {
			err = fmt.Errorf("containerstream: provider command failed: %w", err)
		}
	}
	s.done = true
	s.waitErr = err
	return err
}
