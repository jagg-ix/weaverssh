package terminalsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"weaverssh/containerstream"
)

const (
	OperationConnect  = "connect"
	OperationReattach = "reattach"
)

var (
	ErrDenied         = errors.New("terminalsession: denied")
	ErrInvalidRequest = errors.New("terminalsession: invalid request")
	ErrNotFound       = errors.New("terminalsession: session not found")
	ErrStaleLease     = errors.New("terminalsession: stale attachment lease")
	ErrTerminated     = errors.New("terminalsession: session terminated")
)

// State is the mutually exclusive lifecycle state of a remote PTY.
type State string

const (
	StateProvisioning State = "PROVISIONING"
	StateActive       State = "ACTIVE"
	StateDetaching    State = "DETACHING"
	StateDetached     State = "DETACHED"
	StateRecovering   State = "RECOVERING"
	StateTerminated   State = "TERMINATED"
)

// Identity is derived from authenticated, broker-bound routing metadata. It is
// never accepted from the terminal protocol's OPEN payload.
type Identity struct {
	Principal     string
	SourceNode    string
	SourceBinding string
	ChainSHA256   string
}

func (i Identity) Validate() error {
	if strings.TrimSpace(i.Principal) == "" || strings.TrimSpace(i.SourceNode) == "" || strings.TrimSpace(i.SourceBinding) == "" || !lowerSHA256(strings.ToLower(strings.TrimSpace(i.ChainSHA256))) {
		return errors.New("terminalsession: incomplete authenticated identity")
	}
	return nil
}

func lowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type TerminalSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

func (s TerminalSize) Validate() error {
	if s.Rows == 0 || s.Cols == 0 {
		return errors.New("terminalsession: terminal dimensions must be non-zero")
	}
	return nil
}

// OpenRequest is the SOCKS-style negotiation message sent as the first frame.
// Action is a policy name, not an arbitrary shell command.
type OpenRequest struct {
	Protocol      string            `json:"protocol"`
	Operation     string            `json:"operation"`
	TargetURI     string            `json:"target_uri,omitempty"`
	Action        string            `json:"action,omitempty"`
	Args          []string          `json:"args,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	Rows          uint16            `json:"rows,omitempty"`
	Cols          uint16            `json:"cols,omitempty"`
	Term          string            `json:"term,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	ResumeToken   string            `json:"resume_token,omitempty"`
	AfterSequence uint64            `json:"after_sequence,omitempty"`
}

func (r OpenRequest) validate() error {
	if r.Protocol != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol", ErrInvalidRequest)
	}
	switch r.Operation {
	case OperationConnect:
		if strings.TrimSpace(r.TargetURI) == "" || strings.TrimSpace(r.Action) == "" || strings.TrimSpace(r.SessionID) != "" || strings.TrimSpace(r.ResumeToken) != "" {
			return ErrInvalidRequest
		}
		if _, err := containerstream.ParseURI(r.TargetURI); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		if err := (TerminalSize{Rows: r.Rows, Cols: r.Cols}).Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		if len(r.Term) > 128 || strings.ContainsAny(r.Term, "\x00\r\n") {
			return ErrInvalidRequest
		}
	case OperationReattach:
		if strings.TrimSpace(r.SessionID) == "" || strings.TrimSpace(r.ResumeToken) == "" || r.TargetURI != "" || r.Action != "" || len(r.Args) != 0 || len(r.Environment) != 0 {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

type RecordingMode string

const (
	RecordingOff        RecordingMode = "off"
	RecordingBestEffort RecordingMode = "best-effort"
	RecordingRequired   RecordingMode = "required"
)

// Grant is returned by the final-node, default-deny authorizer. It converts an
// action name into a provider-neutral process spec without invoking a shell.
type Grant struct {
	Process       containerstream.ProcessSpec
	DetachTTL     time.Duration
	ReplayBytes   int
	RecordingMode RecordingMode
}

type Snapshot struct {
	ID             string `json:"id"`
	State          State  `json:"state"`
	Generation     uint64 `json:"generation"`
	Principal      string `json:"principal"`
	SourceNode     string `json:"source_node"`
	TargetURI      string `json:"target_uri"`
	Action         string `json:"action"`
	Provider       string `json:"provider,omitempty"`
	ExitCode       *int   `json:"exit_code,omitempty"`
	ReplayFloor    uint64 `json:"replay_floor"`
	ReplayCeiling  uint64 `json:"replay_ceiling"`
	DroppedBytes   uint64 `json:"dropped_bytes"`
	DetachedAtUnix int64  `json:"detached_at_unix,omitempty"`
}

type Ready struct {
	Protocol      string `json:"protocol"`
	SessionID     string `json:"session_id"`
	ResumeToken   string `json:"resume_token,omitempty"`
	Generation    uint64 `json:"generation"`
	State         State  `json:"state"`
	ReplayFloor   uint64 `json:"replay_floor"`
	ReplayCeiling uint64 `json:"replay_ceiling"`
	DroppedBytes  uint64 `json:"dropped_bytes"`
}

type ResponseError struct {
	Protocol string `json:"protocol"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type Exit struct {
	Protocol string `json:"protocol"`
	ExitCode int    `json:"exit_code"`
	Reason   string `json:"reason,omitempty"`
}

type Authorizer interface {
	AuthorizeOpen(context.Context, Identity, OpenRequest) (Grant, error)
	AuthorizeReattach(context.Context, Identity, Snapshot) error
}

type AuthorizerFuncs struct {
	Open     func(context.Context, Identity, OpenRequest) (Grant, error)
	Reattach func(context.Context, Identity, Snapshot) error
}

func (a AuthorizerFuncs) AuthorizeOpen(ctx context.Context, identity Identity, request OpenRequest) (Grant, error) {
	if a.Open == nil {
		return Grant{}, ErrDenied
	}
	return a.Open(ctx, identity, request)
}

func (a AuthorizerFuncs) AuthorizeReattach(ctx context.Context, identity Identity, snapshot Snapshot) error {
	if a.Reattach == nil {
		return ErrDenied
	}
	return a.Reattach(ctx, identity, snapshot)
}

// Terminal is the agent-owned master side of one provider PTY.
type Terminal interface {
	ProviderName() string
	WriteInput([]byte) (int, error)
	Output() io.ReadCloser
	Resize(context.Context, TerminalSize) error
	Wait() containerstream.ProcessResult
	Close() error
}

type Spawner interface {
	Spawn(context.Context, containerstream.Request, containerstream.ProcessSpec) (Terminal, error)
}

// Attachment is one currently bound tunnel. Implementations serialize writes.
type Attachment interface {
	Send(context.Context, Frame) error
	Close() error
}

type Lease struct {
	SessionID  string
	Generation uint64
}

type Transition struct {
	SessionID string
	From      State
	To        State
	Reason    string
	At        time.Time
}

type Observer interface {
	Observe(context.Context, Transition) error
}

type OutputRecord struct {
	SessionID string
	Sequence  uint64
	Payload   []byte
	At        time.Time
}

type Recorder interface {
	RecordOutput(context.Context, OutputRecord) error
}

// ContainerSpawner bridges the orchestration provider abstraction to PTY
// ownership. Providers that cannot resize the TTY and terminate the exact
// remote exec process are rejected.
type ContainerSpawner struct{ Router *containerstream.Router }

func (s ContainerSpawner) Spawn(ctx context.Context, target containerstream.Request, spec containerstream.ProcessSpec) (Terminal, error) {
	if s.Router == nil {
		return nil, errors.New("terminalsession: container router unavailable")
	}
	spec.TTY = true
	process, err := s.Router.StartContainerProcess(ctx, target, spec)
	if err != nil {
		return nil, err
	}
	caps := process.Capabilities()
	if !caps.TTY || !caps.Stdin || !caps.Stdout || !caps.Resize || !caps.Terminate || process.Stdin() == nil || process.Stdout() == nil {
		_ = process.Close()
		return nil, errors.New("terminalsession: provider lacks faithful PTY, stdin, stdout, resize, or exact-process termination support")
	}
	return &processTerminal{Process: process, stdin: process.Stdin(), output: process.Stdout()}, nil
}

type processTerminal struct {
	containerstream.Process
	stdin  io.WriteCloser
	output io.ReadCloser
}

func (p *processTerminal) WriteInput(data []byte) (int, error) { return p.stdin.Write(data) }
func (p *processTerminal) Output() io.ReadCloser               { return p.output }
func (p *processTerminal) Resize(ctx context.Context, size TerminalSize) error {
	return p.Process.Resize(ctx, containerstream.TerminalSize{Rows: size.Rows, Cols: size.Cols})
}
