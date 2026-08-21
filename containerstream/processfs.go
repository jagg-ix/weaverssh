package containerstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	ProcessControlProtocol = "weaverssh.procctl.v1"
	ProcessStatusProtocol  = "weaverssh.procstatus.v1"
	ProcessRoot            = "/.wv/processes"
	ProcessFileControl     = "ctl"
	ProcessFileStdin       = "stdin"
	ProcessFileStdout      = "stdout"
	ProcessFileStderr      = "stderr"
	ProcessFileStatus      = "status"
	defaultControlBytes    = 64 << 10
	defaultProcessSessions = 64
	defaultStdinBytes      = int64(4 << 20)
)

var (
	ErrProcessNotFound   = errors.New("containerstream: synthetic process session not found")
	ErrProcessState      = errors.New("containerstream: invalid synthetic process state")
	ErrProcessPermission = errors.New("containerstream: synthetic file access denied")
	ErrProcessLimit      = errors.New("containerstream: synthetic process limit exceeded")
)

type ProcessState string

const (
	ProcessCreated  ProcessState = "created"
	ProcessStarting ProcessState = "starting"
	ProcessRunning  ProcessState = "running"
	ProcessExited   ProcessState = "exited"
	ProcessFailed   ProcessState = "failed"
	ProcessClosed   ProcessState = "closed"
)

// SyntheticFile describes the stable entries in every process directory.
type SyntheticFile struct {
	Name      string `json:"name"`
	Readable  bool   `json:"readable"`
	Writable  bool   `json:"writable"`
	Streaming bool   `json:"streaming"`
}

var syntheticProcessFiles = []SyntheticFile{
	{Name: ProcessFileControl, Writable: true},
	{Name: ProcessFileStdin, Writable: true, Streaming: true},
	{Name: ProcessFileStdout, Readable: true, Streaming: true},
	{Name: ProcessFileStderr, Readable: true, Streaming: true},
	{Name: ProcessFileStatus, Readable: true},
}

// ProcessStatus is the JSON snapshot served by the synthetic status file.
// It intentionally excludes argv and environment values.
type ProcessStatus struct {
	Protocol     string              `json:"protocol"`
	SessionID    string              `json:"session_id"`
	State        ProcessState        `json:"state"`
	Provider     string              `json:"provider,omitempty"`
	Capabilities ProcessCapabilities `json:"capabilities"`
	ExitCode     *int                `json:"exit_code,omitempty"`
	Error        string              `json:"error,omitempty"`
	StdinBytes   int64               `json:"stdin_bytes"`
	CreatedAt    time.Time           `json:"created_at"`
	StartedAt    *time.Time          `json:"started_at,omitempty"`
	EndedAt      *time.Time          `json:"ended_at,omitempty"`
}

// StartRequest is the untrusted start payload written to ctl. Action is a
// policy name, not an executable or a shell command. The authorizer resolves
// it into a ProcessSpec after applying source, target, argument, environment,
// concurrency, and timeout policy.
type StartRequest struct {
	Action      string            `json:"action"`
	Args        []string          `json:"args,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	TTY         bool              `json:"tty,omitempty"`
}

// ProcessIdentity is authenticated routing provenance supplied by the broker,
// never by a process protocol payload. Local ProcessFS callers may leave it
// empty when their authorizer derives identity from an enclosing mount.
type ProcessIdentity struct {
	Principal     string `json:"principal,omitempty"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
}

type ControlRequest struct {
	Protocol    string            `json:"protocol"`
	Operation   string            `json:"op"`
	Action      string            `json:"action,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	TTY         bool              `json:"tty,omitempty"`
	Signal      ProcessSignal     `json:"signal,omitempty"`
	Rows        uint16            `json:"rows,omitempty"`
	Cols        uint16            `json:"cols,omitempty"`
}

type ProcessAuthorizer interface {
	AuthorizeContainerProcess(context.Context, ProcessIdentity, Request, StartRequest) (ProcessSpec, error)
}

type ProcessAuthorizerFunc func(context.Context, ProcessIdentity, Request, StartRequest) (ProcessSpec, error)

func (f ProcessAuthorizerFunc) AuthorizeContainerProcess(ctx context.Context, identity ProcessIdentity, target Request, request StartRequest) (ProcessSpec, error) {
	return f(ctx, identity, target, request)
}

type ProcessFSConfig struct {
	MaxSessions          int
	MaxControlBytes      int
	DefaultMaxStdinBytes int64
	NewSessionID         func() (string, error)
}

// ProcessFS is an in-memory synthetic filesystem facade. It stores only
// process metadata and live stream handles; payload bytes flow directly
// between the VFS caller and the provider.
type ProcessFS struct {
	manager *ProcessManager
	config  ProcessFSConfig
}

func NewProcessFS(ctx context.Context, router *Router, authorizer ProcessAuthorizer, config ProcessFSConfig) (*ProcessFS, error) {
	if config.MaxControlBytes == 0 {
		config.MaxControlBytes = defaultControlBytes
	}
	if config.MaxControlBytes < 256 || config.MaxControlBytes > 1<<20 {
		return nil, errors.New("containerstream: invalid process filesystem limits")
	}
	manager, err := NewProcessManager(ctx, router, authorizer, ProcessManagerConfig{
		MaxSessions: config.MaxSessions, DefaultMaxStdinBytes: config.DefaultMaxStdinBytes,
		NewSessionID: config.NewSessionID,
	})
	if err != nil {
		return nil, err
	}
	return NewProcessFSWithManager(manager, config.MaxControlBytes)
}

// NewProcessFSWithManager builds the composable filesystem facade over an
// existing manager. Exec RPC and ProcessFS can therefore share one lifecycle,
// policy, provider-selection, and quota implementation.
func NewProcessFSWithManager(manager *ProcessManager, maxControlBytes int) (*ProcessFS, error) {
	if manager == nil {
		return nil, errors.New("containerstream: process filesystem requires a process manager")
	}
	if maxControlBytes == 0 {
		maxControlBytes = defaultControlBytes
	}
	if maxControlBytes < 256 || maxControlBytes > 1<<20 {
		return nil, errors.New("containerstream: invalid process filesystem control limit")
	}
	return &ProcessFS{manager: manager, config: ProcessFSConfig{MaxControlBytes: maxControlBytes}}, nil
}

// CreateSession allocates a synthetic directory for one target. It does not
// start a process; execution begins only after an authorized start message is
// written to ctl.
func (fs *ProcessFS) CreateSession(target Request) (*ProcessSession, error) {
	return fs.CreateSessionFor(ProcessIdentity{}, target)
}

// CreateSessionFor allocates a directory with identity already derived by the
// authenticated mount or broker boundary. The identity is never read from ctl.
func (fs *ProcessFS) CreateSessionFor(identity ProcessIdentity, target Request) (*ProcessSession, error) {
	if fs == nil {
		return nil, errors.New("containerstream: process filesystem unavailable")
	}
	return fs.manager.CreateSession(identity, target)
}

// OpenReader opens stdout, stderr, or a point-in-time status JSON snapshot.
func (fs *ProcessFS) OpenReader(ctx context.Context, rawURI string) (io.ReadCloser, error) {
	ref, session, err := fs.resolve(rawURI)
	if err != nil {
		return nil, err
	}
	switch ref.File {
	case ProcessFileStdout, ProcessFileStderr:
		return session.openOutput(ref.File)
	case ProcessFileStatus:
		payload, err := session.statusJSON()
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(payload)), nil
	default:
		return nil, fmt.Errorf("%w: %s is not readable", ErrProcessPermission, ref.File)
	}
}

// OpenWriter opens stdin as a live stream or ctl as a bounded transactional
// writer. A ctl operation is decoded and applied when the writer is closed.
func (fs *ProcessFS) OpenWriter(ctx context.Context, rawURI string) (io.WriteCloser, error) {
	ref, session, err := fs.resolve(rawURI)
	if err != nil {
		return nil, err
	}
	switch ref.File {
	case ProcessFileStdin:
		return session.openStdin()
	case ProcessFileControl:
		if ctx == nil {
			ctx = context.Background()
		}
		return &controlWriter{ctx: ctx, session: session, maximum: fs.config.MaxControlBytes}, nil
	default:
		return nil, fmt.Errorf("%w: %s is not writable", ErrProcessPermission, ref.File)
	}
}

// RemoveSession removes the synthetic directory and cancels any live process.
// rawURI may identify either the session directory or one of its files.
func (fs *ProcessFS) RemoveSession(rawURI string) error {
	ref, err := ParseProcessURI(rawURI)
	if err != nil {
		return err
	}
	key := processSessionKey(ref.Endpoint, ref.TargetID, ref.SessionID)
	return fs.manager.removeByKey(key, nil)
}

type ProcessReference struct {
	Request
	SessionID string `json:"session_id"`
	File      string `json:"file,omitempty"`
}

// ParseProcessURI parses
// vfs://container/ENDPOINT/TARGET/.wv/processes/SESSION/[FILE].
func ParseProcessURI(rawURI string) (ProcessReference, error) {
	request, err := ParseURI(rawURI)
	if err != nil {
		return ProcessReference{}, err
	}
	prefix := ProcessRoot + "/"
	if !strings.HasPrefix(request.FilePath, prefix) {
		return ProcessReference{}, errors.New("containerstream: URI is outside the synthetic process namespace")
	}
	parts := strings.Split(strings.TrimPrefix(request.FilePath, prefix), "/")
	if len(parts) < 1 || len(parts) > 2 || !targetPattern.MatchString(parts[0]) {
		return ProcessReference{}, errors.New("containerstream: invalid synthetic process path")
	}
	ref := ProcessReference{Request: request, SessionID: parts[0]}
	if len(parts) == 2 {
		if !validSyntheticProcessFile(parts[1]) {
			return ProcessReference{}, errors.New("containerstream: unknown synthetic process file")
		}
		ref.File = parts[1]
	}
	return ref, nil
}

func (fs *ProcessFS) resolve(rawURI string) (ProcessReference, *ProcessSession, error) {
	if fs == nil {
		return ProcessReference{}, nil, errors.New("containerstream: process filesystem unavailable")
	}
	ref, err := ParseProcessURI(rawURI)
	if err != nil {
		return ProcessReference{}, nil, err
	}
	if ref.File == "" {
		return ProcessReference{}, nil, errors.New("containerstream: synthetic process file is required")
	}
	session, ok := fs.manager.lookup(processSessionKey(ref.Endpoint, ref.TargetID, ref.SessionID))
	if !ok {
		return ProcessReference{}, nil, ErrProcessNotFound
	}
	return ref, session, nil
}

type ProcessSession struct {
	manager  *ProcessManager
	ctx      context.Context
	cancel   context.CancelFunc
	id       string
	identity ProcessIdentity
	target   Request

	mu           sync.Mutex
	status       ProcessStatus
	process      Process
	processClose context.CancelFunc
	stdin        io.WriteCloser
	stdinLimit   int64
	stdinOpened  bool
	stdinClosed  bool
	stdoutOpened bool
	stderrOpened bool
	closeOnce    sync.Once
	closeErr     error
	done         chan struct{}
	doneOnce     sync.Once
}

func (s *ProcessSession) ID() string { return s.id }

func (s *ProcessSession) Files() []SyntheticFile {
	return append([]SyntheticFile(nil), syntheticProcessFiles...)
}

func (s *ProcessSession) URI(file string) (string, error) {
	if s == nil {
		return "", errors.New("containerstream: nil process session")
	}
	if file != "" && !validSyntheticProcessFile(file) {
		return "", errors.New("containerstream: unknown synthetic process file")
	}
	path := ProcessRoot + "/" + s.id
	if file != "" {
		path += "/" + file
	}
	uri := url.URL{Scheme: "vfs", Host: "container", Path: "/" + s.target.Endpoint + "/" + s.target.TargetID + path}
	query := url.Values{}
	if s.target.ProviderHint != "" {
		query.Set("provider", s.target.ProviderHint)
	}
	for name, value := range s.target.Options {
		query.Set(name, value)
	}
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}

func (s *ProcessSession) Status() ProcessStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneProcessStatus(s.status)
}

func (s *ProcessSession) statusJSON() ([]byte, error) {
	status := s.Status()
	payload, err := json.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("containerstream: encode process status: %w", err)
	}
	return append(payload, '\n'), nil
}

func (s *ProcessSession) applyControl(ctx context.Context, payload []byte) error {
	var request ControlRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("containerstream: decode process control: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	request.Protocol = strings.TrimSpace(request.Protocol)
	request.Operation = strings.ToLower(strings.TrimSpace(request.Operation))
	if request.Protocol != ProcessControlProtocol {
		return errors.New("containerstream: unsupported process control protocol")
	}
	switch request.Operation {
	case "start":
		if request.Signal != "" || request.Rows != 0 || request.Cols != 0 {
			return errors.New("containerstream: start control contains unrelated fields")
		}
		return s.start(ctx, StartRequest{Action: request.Action, Args: request.Args, Environment: request.Environment, TTY: request.TTY})
	case "signal":
		if request.Action != "" || len(request.Args) != 0 || len(request.Environment) != 0 || request.TTY || request.Rows != 0 || request.Cols != 0 {
			return errors.New("containerstream: signal control contains unrelated fields")
		}
		return s.signal(ctx, ProcessSignal(strings.ToUpper(strings.TrimSpace(string(request.Signal)))))
	case "resize":
		if request.Action != "" || len(request.Args) != 0 || len(request.Environment) != 0 || request.Signal != "" || request.TTY {
			return errors.New("containerstream: resize control contains unrelated fields")
		}
		return s.resize(ctx, TerminalSize{Rows: request.Rows, Cols: request.Cols})
	case "close-stdin":
		if request.Action != "" || len(request.Args) != 0 || len(request.Environment) != 0 || request.TTY || request.Signal != "" || request.Rows != 0 || request.Cols != 0 {
			return errors.New("containerstream: close-stdin contains unrelated fields")
		}
		return s.closeStdin()
	case "close":
		if request.Action != "" || len(request.Args) != 0 || len(request.Environment) != 0 || request.TTY || request.Signal != "" || request.Rows != 0 || request.Cols != 0 {
			return errors.New("containerstream: close control contains unrelated fields")
		}
		return s.close()
	default:
		return errors.New("containerstream: unknown process control operation")
	}
}

func (s *ProcessSession) start(ctx context.Context, request StartRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request.Action = strings.TrimSpace(request.Action)
	if err := validateStartRequest(request); err != nil {
		return err
	}
	s.mu.Lock()
	if s.status.State != ProcessCreated {
		s.mu.Unlock()
		return ErrProcessState
	}
	s.status.State = ProcessStarting
	s.mu.Unlock()

	spec, err := s.manager.authorizer.AuthorizeContainerProcess(ctx, s.identity, s.target, request)
	if err != nil {
		s.failStart(err)
		return err
	}
	if spec.MaxStdinBytes == 0 {
		spec.MaxStdinBytes = s.manager.config.DefaultMaxStdinBytes
	}
	if err := validateProcessSpec(spec); err != nil {
		s.failStart(err)
		return err
	}
	s.mu.Lock()
	stillStarting := s.status.State == ProcessStarting && s.ctx.Err() == nil
	s.mu.Unlock()
	if !stillStarting {
		return ErrProcessState
	}
	processCtx := s.ctx
	processCancel := func() {}
	if spec.Timeout > 0 {
		processCtx, processCancel = context.WithTimeout(s.ctx, spec.Timeout)
	}
	process, err := s.manager.router.StartContainerProcess(processCtx, s.target, spec)
	if err != nil {
		processCancel()
		s.failStart(err)
		return err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	if s.status.State != ProcessStarting || s.ctx.Err() != nil {
		s.mu.Unlock()
		processCancel()
		_ = process.Close()
		return ErrProcessState
	}
	s.process = process
	s.processClose = processCancel
	s.stdinLimit = spec.MaxStdinBytes
	s.status.State = ProcessRunning
	s.status.Provider = process.ProviderName()
	s.status.Capabilities = process.Capabilities()
	s.status.StartedAt = &now
	s.mu.Unlock()
	go s.wait(process, processCancel)
	return nil
}

func (s *ProcessSession) wait(process Process, cancel context.CancelFunc) {
	result := process.Wait()
	cancel()
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != ProcessClosed {
		s.status.State = ProcessExited
	}
	exitCode := result.ExitCode
	s.status.ExitCode = &exitCode
	if result.Err != nil {
		s.status.Error = boundedError(result.Err)
	}
	s.status.EndedAt = &now
	s.finish()
}

func (s *ProcessSession) failStart(err error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != ProcessStarting {
		return
	}
	s.status.State = ProcessFailed
	s.status.Error = boundedError(err)
	s.status.EndedAt = &now
	s.finish()
}

func (s *ProcessSession) signal(ctx context.Context, signal ProcessSignal) error {
	if !validProcessSignal(signal) {
		return errors.New("containerstream: invalid process signal")
	}
	s.mu.Lock()
	process := s.process
	state := s.status.State
	capabilities := s.status.Capabilities
	s.mu.Unlock()
	if state != ProcessRunning || process == nil {
		return ErrProcessState
	}
	if !capabilities.Signals {
		return ErrControlUnsupported
	}
	return process.Signal(ctx, signal)
}

func (s *ProcessSession) resize(ctx context.Context, size TerminalSize) error {
	if size.Rows == 0 || size.Cols == 0 {
		return errors.New("containerstream: terminal rows and columns must be non-zero")
	}
	s.mu.Lock()
	process := s.process
	state := s.status.State
	capabilities := s.status.Capabilities
	s.mu.Unlock()
	if state != ProcessRunning || process == nil {
		return ErrProcessState
	}
	if !capabilities.TTY || !capabilities.Resize {
		return ErrControlUnsupported
	}
	return process.Resize(ctx, size)
}

func (s *ProcessSession) openOutput(file string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != ProcessRunning && s.status.State != ProcessExited {
		return nil, ErrProcessState
	}
	if s.process == nil {
		return nil, ErrProcessState
	}
	switch file {
	case ProcessFileStdout:
		if !s.status.Capabilities.Stdout || s.stdoutOpened {
			return nil, ErrProcessState
		}
		reader := s.process.Stdout()
		if reader == nil {
			return nil, errors.New("containerstream: provider returned nil stdout")
		}
		s.stdoutOpened = true
		return reader, nil
	case ProcessFileStderr:
		if !s.status.Capabilities.Stderr || s.stderrOpened {
			return nil, ErrProcessState
		}
		reader := s.process.Stderr()
		if reader == nil {
			return nil, errors.New("containerstream: provider returned nil stderr")
		}
		s.stderrOpened = true
		return reader, nil
	default:
		return nil, ErrProcessPermission
	}
}

func (s *ProcessSession) openStdin() (io.WriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != ProcessRunning || s.process == nil || !s.status.Capabilities.Stdin || s.stdinOpened || s.stdinClosed {
		return nil, ErrProcessState
	}
	s.stdinOpened = true
	s.stdin = s.process.Stdin()
	if s.stdin == nil {
		s.stdinOpened = false
		return nil, ErrProcessState
	}
	return &sessionStdinWriter{session: s, writer: s.stdin}, nil
}

func (s *ProcessSession) closeStdin() error {
	s.mu.Lock()
	if s.status.State != ProcessRunning || s.process == nil || !s.status.Capabilities.Stdin {
		s.mu.Unlock()
		return ErrProcessState
	}
	if s.stdinClosed {
		s.mu.Unlock()
		return nil
	}
	if s.stdin == nil {
		s.stdin = s.process.Stdin()
		s.stdinOpened = true
	}
	stdin := s.stdin
	s.stdinClosed = true
	s.mu.Unlock()
	if stdin == nil {
		return ErrProcessState
	}
	return stdin.Close()
}

func (s *ProcessSession) close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		process := s.process
		processCancel := s.processClose
		now := time.Now().UTC()
		if s.status.State != ProcessExited && s.status.State != ProcessFailed {
			s.status.State = ProcessClosed
			s.status.EndedAt = &now
		}
		s.mu.Unlock()
		if processCancel != nil {
			processCancel()
		}
		if process != nil {
			s.closeErr = process.Close()
		}
		s.finish()
	})
	return s.closeErr
}

type sessionStdinWriter struct {
	session *ProcessSession
	writer  io.WriteCloser
	mu      sync.Mutex
	closed  bool
}

func (w *sessionStdinWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("containerstream: write to closed synthetic stdin")
	}
	w.session.mu.Lock()
	limit := w.session.stdinLimit
	if int64(len(payload)) > limit-w.session.status.StdinBytes {
		w.session.mu.Unlock()
		return 0, ErrProcessLimit
	}
	w.session.mu.Unlock()
	n, err := w.writer.Write(payload)
	w.session.mu.Lock()
	w.session.status.StdinBytes += int64(n)
	w.session.mu.Unlock()
	return n, err
}

func (w *sessionStdinWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	w.session.mu.Lock()
	w.session.stdinClosed = true
	w.session.mu.Unlock()
	return w.writer.Close()
}

type controlWriter struct {
	ctx     context.Context
	session *ProcessSession
	maximum int

	mu       sync.Mutex
	buffer   bytes.Buffer
	writeErr error
	closed   bool
	closeErr error
}

func (w *controlWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("containerstream: write to closed synthetic ctl")
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if len(payload) > w.maximum-w.buffer.Len() {
		w.writeErr = ErrProcessLimit
		return 0, w.writeErr
	}
	return w.buffer.Write(payload)
}

func (w *controlWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	if w.writeErr != nil {
		w.closeErr = w.writeErr
		return w.closeErr
	}
	if w.buffer.Len() == 0 {
		w.closeErr = errors.New("containerstream: empty process control message")
		return w.closeErr
	}
	w.closeErr = w.session.applyControl(w.ctx, w.buffer.Bytes())
	return w.closeErr
}

func validateStartRequest(request StartRequest) error {
	request.Action = strings.TrimSpace(request.Action)
	if !providerNamePattern.MatchString(strings.ToLower(request.Action)) || len(request.Action) > 128 {
		return errors.New("containerstream: invalid process action")
	}
	if len(request.Args) > MaxProcessArgs {
		return errors.New("containerstream: too many process arguments")
	}
	for _, argument := range request.Args {
		if len(argument) > MaxProcessArgument || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("containerstream: invalid process argument")
		}
	}
	totalEnvironment := 0
	for name, value := range request.Environment {
		if !validEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") || credentialLikeEnvironment(name) {
			return fmt.Errorf("containerstream: invalid process environment entry %q", name)
		}
		totalEnvironment += len(name) + len(value) + 1
	}
	if totalEnvironment > MaxProcessEnvironment {
		return errors.New("containerstream: process environment is too large")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("containerstream: multiple process control values")
		}
		return fmt.Errorf("containerstream: decode trailing process control data: %w", err)
	}
	return nil
}

func validSyntheticProcessFile(file string) bool {
	switch file {
	case ProcessFileControl, ProcessFileStdin, ProcessFileStdout, ProcessFileStderr, ProcessFileStatus:
		return true
	default:
		return false
	}
}

func cloneProcessStatus(status ProcessStatus) ProcessStatus {
	if status.ExitCode != nil {
		value := *status.ExitCode
		status.ExitCode = &value
	}
	if status.StartedAt != nil {
		value := *status.StartedAt
		status.StartedAt = &value
	}
	if status.EndedAt != nil {
		value := *status.EndedAt
		status.EndedAt = &value
	}
	return status
}

func cloneOptions(options map[string]string) map[string]string {
	if len(options) == 0 {
		return nil
	}
	clone := make(map[string]string, len(options))
	for name, value := range options {
		clone[name] = value
	}
	return clone
}

func processSessionKey(endpoint, target, session string) string {
	return endpoint + "\x00" + target + "\x00" + session
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}

func randomSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
