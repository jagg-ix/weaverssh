package containerstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultNomadAddress   = "http://127.0.0.1:4646"
	nomadHandshakeTimeout = 5 * time.Second
	nomadWriteTimeout     = 5 * time.Second
	nomadHeartbeatPeriod  = 15 * time.Second
	maxNomadFrame         = 32 << 20
	maxNomadHTTPError     = 64 << 10
)

var errNomadClientConfiguration = errors.New("containerstream: invalid Nomad client configuration")

var nomadAllocationIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type nomadWebSocket interface {
	ReadJSON(any) error
	WriteJSON(any) error
	SetReadLimit(int64)
	SetWriteDeadline(time.Time) error
	Close() error
}

type nomadDialFunc func(context.Context, string, http.Header) (nomadWebSocket, *http.Response, error)

// NomadAPIConfig configures the native Nomad allocation-exec transport.
// Credentials are loaded from the agent environment, never from a process
// request or target URI.
type NomadAPIConfig struct {
	LookupEnv func(string) (string, bool)
}

type NomadAPIProvider struct {
	lookupEnv func(string) (string, bool)
	dial      nomadDialFunc
}

func NewNomadAPIProvider(config NomadAPIConfig) *NomadAPIProvider {
	lookup := config.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	provider := &NomadAPIProvider{lookupEnv: lookup}
	if provider.dial == nil {
		provider.dial = provider.defaultDial
	}
	return provider
}

func newDefaultNomadAPIProvider() Provider { return NewNomadAPIProvider(NomadAPIConfig{}) }

func (*NomadAPIProvider) Name() string { return ProviderNomad }

func (p *NomadAPIProvider) Discover(probe Probe) Candidate {
	if probe == nil {
		probe = OSProbe{}
	}
	candidate := Candidate{Provider: ProviderNomad}
	if value, ok := probe.LookupEnv("NOMAD_ADDR"); ok && strings.TrimSpace(value) != "" {
		candidate.Score += 35
		candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "environment", Value: "NOMAD_ADDR", Weight: 35})
	}
	if value, ok := probe.LookupEnv("NOMAD_TOKEN"); ok && strings.TrimSpace(value) != "" {
		candidate.Score += 5
		candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "environment", Value: "NOMAD_TOKEN", Weight: 5})
	}
	return candidate
}

func (p *NomadAPIProvider) OpenContainerStream(ctx context.Context, request Request) (io.ReadCloser, error) {
	if request.FilePath == "" || !strings.HasPrefix(request.FilePath, "/") || strings.ContainsAny(request.FilePath, "\x00\r\n") {
		return nil, errors.New("containerstream: Nomad API requires an absolute file path")
	}
	process, err := p.start(ctx, request, []string{"cat", "--", request.FilePath}, false, 0)
	if err != nil {
		return nil, err
	}
	_ = process.Stdin().Close()
	return newProcessFileStream(process)
}

func (p *NomadAPIProvider) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	if err := validateProcessSpec(spec); err != nil {
		return nil, err
	}
	return p.start(ctx, request, remoteArgv(spec), spec.TTY, spec.Timeout)
}

func (p *NomadAPIProvider) start(ctx context.Context, request Request, command []string, tty bool, timeout time.Duration) (Process, error) {
	if p == nil || p.lookupEnv == nil || p.dial == nil {
		return nil, errors.New("containerstream: Nomad API provider unavailable")
	}
	if _, err := safeAdapterToken("allocation", request.TargetID); err != nil {
		return nil, err
	}
	if err := validateNomadOptions(request); err != nil {
		return nil, err
	}
	task := strings.TrimSpace(request.Options["task"])
	if task == "" {
		// The native endpoint requires a task name. The CLI can resolve the
		// allocation's default task, so this is a safe pre-execution fallback.
		return nil, fmt.Errorf("%w: Nomad task option", ErrFastPathUnavailable)
	}
	if !nomadAllocationIDPattern.MatchString(request.TargetID) {
		// The HTTP endpoint requires a full allocation UUID; the CLI can
		// resolve allocation prefixes without weakening this API adapter.
		return nil, fmt.Errorf("%w: full Nomad allocation ID", ErrFastPathUnavailable)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	processContext, cancel := context.WithCancel(ctx)
	if timeout > 0 {
		processContext, cancel = context.WithTimeout(ctx, timeout)
	}
	execURL, token, err := p.execURL(request, task, command, tty)
	if err != nil {
		cancel()
		return nil, err
	}
	connection, response, err := p.dial(processContext, execURL.String(), nil)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		cancel()
		if errors.Is(err, errNomadClientConfiguration) {
			return nil, err
		}
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return nil, fmt.Errorf("containerstream: Nomad TLS verification: %w", err)
		}
		if response == nil {
			return nil, fmt.Errorf("%w: Nomad WebSocket: %v", ErrFastPathUnavailable, err)
		}
		var detail []byte
		if response.Body != nil {
			detail, _ = io.ReadAll(io.LimitReader(response.Body, maxNomadHTTPError))
		}
		return nil, fmt.Errorf("containerstream: Nomad WebSocket HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(detail)))
	}
	if connection == nil {
		cancel()
		return nil, errors.New("containerstream: Nomad WebSocket dialer returned nil")
	}
	connection.SetReadLimit(maxNomadFrame)
	process := newNomadProcess(processContext, cancel, connection, tty)
	if token != "" {
		if err := process.writeFrame(processContext, nomadAuthFrame{Version: 1, AuthToken: token}); err != nil {
			process.finish(ProcessResult{ExitCode: -1, Err: err})
			return nil, fmt.Errorf("containerstream: Nomad WebSocket authentication handshake: %w", err)
		}
	}
	process.run()
	return process, nil
}

func validateNomadOptions(request Request) error {
	for name, value := range request.Options {
		if name != "namespace" && name != "task" {
			return fmt.Errorf("containerstream: provider Nomad API does not support option %q", name)
		}
		if _, err := safeAdapterToken(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *NomadAPIProvider) execURL(request Request, task string, command []string, tty bool) (*url.URL, string, error) {
	address := defaultNomadAddress
	if value, ok := p.lookupEnv("NOMAD_ADDR"); ok && strings.TrimSpace(value) != "" {
		address = strings.TrimSpace(value)
	}
	base, err := url.Parse(address)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https" && base.Scheme != "ws" && base.Scheme != "wss") {
		return nil, "", errors.New("containerstream: invalid NOMAD_ADDR")
	}
	switch base.Scheme {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/client/allocation/" + url.PathEscape(request.TargetID) + "/exec"
	encodedCommand, err := json.Marshal(command)
	if err != nil {
		return nil, "", fmt.Errorf("containerstream: encode Nomad command: %w", err)
	}
	query := base.Query()
	query.Set("command", string(encodedCommand))
	query.Set("task", task)
	query.Set("tty", strconv.FormatBool(tty))
	if namespace := strings.TrimSpace(request.Options["namespace"]); namespace != "" {
		query.Set("namespace", namespace)
	}
	token, _ := p.lookupEnv("NOMAD_TOKEN")
	token = strings.TrimSpace(token)
	if token != "" {
		query.Set("ws_handshake", "true")
	}
	base.RawQuery = query.Encode()
	return base, token, nil
}

func (p *NomadAPIProvider) defaultDial(ctx context.Context, address string, header http.Header) (nomadWebSocket, *http.Response, error) {
	dialer := *websocket.DefaultDialer
	dialer.Proxy = http.ProxyFromEnvironment
	dialer.HandshakeTimeout = nomadHandshakeTimeout
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Scheme == "wss" {
		tlsConfig, err := p.nomadTLSConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errNomadClientConfiguration, err)
		}
		dialer.TLSClientConfig = tlsConfig
	}
	return dialer.DialContext(ctx, address, header)
}

func (p *NomadAPIProvider) nomadTLSConfig() (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if value, ok := p.lookupEnv("NOMAD_TLS_SERVER_NAME"); ok {
		config.ServerName = strings.TrimSpace(value)
	}
	if value, ok := p.lookupEnv("NOMAD_SKIP_VERIFY"); ok && strings.TrimSpace(value) != "" {
		skip, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("containerstream: invalid NOMAD_SKIP_VERIFY: %w", err)
		}
		config.InsecureSkipVerify = skip //nolint:gosec -- explicit Nomad operator setting
	}
	if path, ok := p.lookupEnv("NOMAD_CACERT"); ok && strings.TrimSpace(path) != "" {
		pem, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("containerstream: read NOMAD_CACERT: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("containerstream: NOMAD_CACERT contains no certificates")
		}
		config.RootCAs = roots
	}
	certificatePath, certificateSet := p.lookupEnv("NOMAD_CLIENT_CERT")
	keyPath, keySet := p.lookupEnv("NOMAD_CLIENT_KEY")
	certificatePath, keyPath = strings.TrimSpace(certificatePath), strings.TrimSpace(keyPath)
	if certificateSet || keySet {
		if certificatePath == "" || keyPath == "" {
			return nil, errors.New("containerstream: NOMAD_CLIENT_CERT and NOMAD_CLIENT_KEY must be configured together")
		}
		certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("containerstream: load Nomad client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

type nomadAuthFrame struct {
	Version   int    `json:"version"`
	AuthToken string `json:"auth_token"`
}

type nomadIOOperation struct {
	Data  []byte `json:"data,omitempty"`
	Close bool   `json:"close,omitempty"`
}

type nomadTTYSize struct {
	Height int `json:"height,omitempty"`
	Width  int `json:"width,omitempty"`
}

type nomadExecInput struct {
	Stdin   *nomadIOOperation `json:"stdin,omitempty"`
	TTYSize *nomadTTYSize     `json:"tty_size,omitempty"`
}

type nomadExecResult struct {
	ExitCode int `json:"exit_code"`
}

type nomadExecOutput struct {
	Stdout *nomadIOOperation `json:"stdout,omitempty"`
	Stderr *nomadIOOperation `json:"stderr,omitempty"`
	Exited bool              `json:"exited,omitempty"`
	Result *nomadExecResult  `json:"result,omitempty"`
}

type nomadStdin struct {
	process *nomadProcess
	mu      sync.Mutex
	closed  bool
}

func (s *nomadStdin) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if err := s.process.writeFrame(context.Background(), nomadExecInput{Stdin: &nomadIOOperation{Data: payload}}); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (s *nomadStdin) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.process.writeFrame(context.Background(), nomadExecInput{Stdin: &nomadIOOperation{Close: true}})
	if errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

type nomadProcess struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   nomadWebSocket
	tty    bool
	stdin  *nomadStdin

	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	stderrR io.ReadCloser
	stderrW *io.PipeWriter

	writeMu sync.Mutex
	stateMu sync.Mutex
	closing bool
	result  ProcessResult

	finishOnce sync.Once
	closeOnce  sync.Once
	done       chan struct{}
}

func newNomadProcess(ctx context.Context, cancel context.CancelFunc, connection nomadWebSocket, tty bool) *nomadProcess {
	stdoutR, stdoutW := io.Pipe()
	process := &nomadProcess{ctx: ctx, cancel: cancel, conn: connection, tty: tty, stdoutR: stdoutR, stdoutW: stdoutW, done: make(chan struct{})}
	if tty {
		process.stderrR = io.NopCloser(strings.NewReader(""))
	} else {
		process.stderrR, process.stderrW = io.Pipe()
	}
	process.stdin = &nomadStdin{process: process}
	return process
}

func (p *nomadProcess) run() {
	go p.readLoop()
	go p.heartbeatLoop()
	go func() {
		select {
		case <-p.ctx.Done():
			_ = p.conn.Close()
		case <-p.done:
		}
	}()
}

func (*nomadProcess) ProviderName() string { return ProviderNomad }
func (p *nomadProcess) Capabilities() ProcessCapabilities {
	// Allocation-exec disconnect semantics vary by task driver and cannot
	// guarantee termination of the exact exec, so Terminate stays false.
	return ProcessCapabilities{Stdin: true, Stdout: true, Stderr: !p.tty, TTY: p.tty, Resize: p.tty}
}
func (p *nomadProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *nomadProcess) Stdout() io.ReadCloser { return p.stdoutR }
func (p *nomadProcess) Stderr() io.ReadCloser { return p.stderrR }
func (*nomadProcess) Signal(context.Context, ProcessSignal) error {
	return ErrControlUnsupported
}

func (p *nomadProcess) Resize(ctx context.Context, size TerminalSize) error {
	if !p.tty {
		return ErrControlUnsupported
	}
	if size.Rows == 0 || size.Cols == 0 {
		return errors.New("containerstream: terminal dimensions must be non-zero")
	}
	return p.writeFrame(ctx, nomadExecInput{TTYSize: &nomadTTYSize{Height: int(size.Rows), Width: int(size.Cols)}})
}

func (p *nomadProcess) writeFrame(ctx context.Context, frame any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-p.done:
		return io.ErrClosedPipe
	default:
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(nomadWriteTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := p.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return p.conn.WriteJSON(frame)
}

func (p *nomadProcess) readLoop() {
	for {
		var frame nomadExecOutput
		if err := p.conn.ReadJSON(&frame); err != nil {
			p.finishStreamError(err)
			return
		}
		fields := 0
		if frame.Stdout != nil {
			fields++
		}
		if frame.Stderr != nil {
			fields++
		}
		if frame.Exited || frame.Result != nil {
			fields++
		}
		if fields > 1 {
			p.finish(ProcessResult{ExitCode: -1, Err: errors.New("containerstream: invalid Nomad output frame")})
			return
		}
		if frame.Stdout != nil {
			if err := writeNomadOutput(p.stdoutW, frame.Stdout); err != nil {
				p.finishStreamError(err)
				return
			}
			continue
		}
		if frame.Stderr != nil {
			destination := p.stderrW
			if p.tty {
				destination = p.stdoutW
			}
			if err := writeNomadOutput(destination, frame.Stderr); err != nil {
				p.finishStreamError(err)
				return
			}
			continue
		}
		if frame.Exited || frame.Result != nil {
			if !frame.Exited || frame.Result == nil {
				p.finish(ProcessResult{ExitCode: -1, Err: errors.New("containerstream: incomplete Nomad exit frame")})
			} else {
				p.finish(ProcessResult{ExitCode: frame.Result.ExitCode})
			}
			return
		}
		// An empty object is Nomad's application-level heartbeat.
	}
}

func (p *nomadProcess) finishStreamError(err error) {
	p.stateMu.Lock()
	closing := p.closing
	p.stateMu.Unlock()
	if closing {
		err = nil
	} else if p.ctx.Err() != nil {
		err = p.ctx.Err()
	}
	p.finish(ProcessResult{ExitCode: -1, Err: err})
}

func writeNomadOutput(destination *io.PipeWriter, operation *nomadIOOperation) error {
	if destination == nil || operation == nil {
		return errors.New("containerstream: invalid Nomad output destination")
	}
	if len(operation.Data) > 0 && operation.Close {
		return errors.New("containerstream: Nomad output frame cannot contain data and close")
	}
	if len(operation.Data) > 0 {
		if _, err := destination.Write(operation.Data); err != nil {
			return err
		}
	}
	if operation.Close {
		return destination.Close()
	}
	return nil
}

func (p *nomadProcess) heartbeatLoop() {
	ticker := time.NewTicker(nomadHeartbeatPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			if err := p.writeFrame(context.Background(), nomadExecInput{}); err != nil {
				_ = p.conn.Close()
				return
			}
		}
	}
}

func (p *nomadProcess) finish(result ProcessResult) {
	p.finishOnce.Do(func() {
		p.stateMu.Lock()
		p.result = result
		p.stateMu.Unlock()
		_ = p.stdoutW.Close()
		if p.stderrW != nil {
			_ = p.stderrW.Close()
		}
		p.cancel()
		_ = p.conn.Close()
		close(p.done)
	})
}

func (p *nomadProcess) Wait() ProcessResult {
	<-p.done
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.result
}

func (p *nomadProcess) Close() error {
	p.closeOnce.Do(func() {
		p.stateMu.Lock()
		p.closing = true
		p.stateMu.Unlock()
		_ = p.stdin.Close()
		_ = p.stdoutR.Close()
		_ = p.stderrR.Close()
		p.cancel()
		_ = p.conn.Close()
	})
	<-p.done
	return nil
}
