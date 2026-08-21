package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	MaxProcessArgs        = 64
	MaxProcessArgument    = 4096
	MaxProcessEnvironment = 64 << 10
	MaxProcessStdin       = int64(1 << 40)
)

var (
	// ErrExecutionUnsupported means a provider can serve read-only file
	// streams but cannot create a bidirectional process session.
	ErrExecutionUnsupported = errors.New("containerstream: provider does not support process execution")
	// ErrControlUnsupported means the process transport cannot faithfully
	// translate an optional control operation such as a signal or resize.
	ErrControlUnsupported = errors.New("containerstream: process control operation is unsupported")
)

// ProcessSpec is the policy-authorized, provider-neutral process description.
// Argv is always an explicit argument vector; providers must never pass it to
// a shell. The executable must be absolute inside the target workload.
type ProcessSpec struct {
	Argv          []string          `json:"argv"`
	Environment   map[string]string `json:"environment,omitempty"`
	TTY           bool              `json:"tty,omitempty"`
	Timeout       time.Duration     `json:"-"`
	MaxStdinBytes int64             `json:"-"`
}

// ProcessCapabilities declares only operations the active transport can
// faithfully apply to the remote process. Terminate means Process.Close can
// stop the exact remote exec process, which is required for manager-owned,
// detachable terminals. In particular, signaling or killing a local CLI
// wrapper is not advertised as controlling the container process.
type ProcessCapabilities struct {
	Stdin     bool `json:"stdin"`
	Stdout    bool `json:"stdout"`
	Stderr    bool `json:"stderr"`
	TTY       bool `json:"tty"`
	Signals   bool `json:"signals"`
	Resize    bool `json:"resize"`
	Terminate bool `json:"terminate"`
}

type ProcessSignal string

const (
	SignalHUP   ProcessSignal = "SIGHUP"
	SignalINT   ProcessSignal = "SIGINT"
	SignalQUIT  ProcessSignal = "SIGQUIT"
	SignalTERM  ProcessSignal = "SIGTERM"
	SignalKILL  ProcessSignal = "SIGKILL"
	SignalWINCH ProcessSignal = "SIGWINCH"
)

type TerminalSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type ProcessResult struct {
	ExitCode int
	Err      error
}

// Process is one active container process. Its standard streams are
// single-consumer streams. Wait may be called more than once and must return
// the same terminal result.
type Process interface {
	ProviderName() string
	Capabilities() ProcessCapabilities
	Stdin() io.WriteCloser
	Stdout() io.ReadCloser
	Stderr() io.ReadCloser
	Wait() ProcessResult
	Signal(context.Context, ProcessSignal) error
	Resize(context.Context, TerminalSize) error
	Close() error
}

// ExecutionProvider is the optional extension implemented by providers that
// can start interactive processes in addition to opening read-only streams.
type ExecutionProvider interface {
	Provider
	StartContainerProcess(context.Context, Request, ProcessSpec) (Process, error)
}

func validateProcessSpec(spec ProcessSpec) error {
	if len(spec.Argv) == 0 || len(spec.Argv) > MaxProcessArgs {
		return errors.New("containerstream: process argv is empty or too large")
	}
	if !path.IsAbs(spec.Argv[0]) || path.Clean(spec.Argv[0]) != spec.Argv[0] || spec.Argv[0] == "/" || strings.ContainsAny(spec.Argv[0], "\\\x00\r\n") {
		return errors.New("containerstream: process executable must be absolute")
	}
	for _, argument := range spec.Argv {
		if len(argument) > MaxProcessArgument || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("containerstream: invalid process argument")
		}
	}
	if spec.Timeout < 0 || spec.Timeout > 24*time.Hour {
		return errors.New("containerstream: invalid process timeout")
	}
	if spec.MaxStdinBytes < 0 || spec.MaxStdinBytes > MaxProcessStdin {
		return errors.New("containerstream: invalid process stdin limit")
	}
	totalEnvironment := 0
	for name, value := range spec.Environment {
		if !validEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("containerstream: invalid process environment entry %q", name)
		}
		if credentialLikeEnvironment(name) {
			return fmt.Errorf("containerstream: credential-like process environment key %q", name)
		}
		totalEnvironment += len(name) + len(value) + 1
	}
	if totalEnvironment > MaxProcessEnvironment {
		return errors.New("containerstream: process environment is too large")
	}
	return nil
}

func credentialLikeEnvironment(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return upper == "SSH_AUTH_SOCK" || upper == "GPG_AGENT_INFO" ||
		strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "CREDENTIAL") ||
		strings.Contains(upper, "PRIVATE_KEY")
}

func validProcessSignal(signal ProcessSignal) bool {
	switch signal {
	case SignalHUP, SignalINT, SignalQUIT, SignalTERM, SignalKILL, SignalWINCH:
		return true
	default:
		return false
	}
}

func remoteArgv(spec ProcessSpec) []string {
	if len(spec.Environment) == 0 {
		return append([]string(nil), spec.Argv...)
	}
	names := make([]string, 0, len(spec.Environment))
	for name := range spec.Environment {
		names = append(names, name)
	}
	sort.Strings(names)
	argv := []string{"env", "--"}
	for _, name := range names {
		argv = append(argv, name+"="+spec.Environment[name])
	}
	return append(argv, spec.Argv...)
}
