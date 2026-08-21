package containerstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxEngineAPIError     = 64 << 10
	maxEngineOutputFrame  = 32 << 20
	engineInspectDeadline = 2 * time.Second
	engineCleanupDeadline = 30 * time.Second
)

// EngineAPIConfig configures a Docker-compatible or Podman Libpod API fast
// path. Only a local Unix socket is accepted; remote engine contexts remain
// the CLI adapter's responsibility so this provider never creates a listener
// or silently broadens network reachability.
type EngineAPIConfig struct {
	Name             string
	SocketPath       string
	APIVersion       string
	LibpodAPIVersion string
	Probe            Probe
	DialContext      func(context.Context, string, string) (net.Conn, error)
}

// EngineAPIProvider implements Docker-compatible exec for Docker Engine and
// Podman's richer Libpod exec API. Docker remains non-TTY because its API has
// no per-exec termination operation. Podman TTY sessions use Libpod resize and
// forced exec removal so the detachable terminal manager owns their lifetime.
type EngineAPIProvider struct {
	name             string
	socketPath       string
	apiVersion       string
	libpodAPIVersion string
	probe            Probe
	dialContext      func(context.Context, string, string) (net.Conn, error)
	resolve          func(Probe) []string
}

func NewEngineAPIProvider(config EngineAPIConfig) (*EngineAPIProvider, error) {
	name := normalizeProviderName(config.Name)
	if name != ProviderDocker && name != ProviderPodman {
		return nil, errors.New("containerstream: Engine API provider must be docker or podman")
	}
	socketPath := strings.TrimSpace(config.SocketPath)
	if socketPath != "" && !safeEngineSocketPath(socketPath) {
		return nil, errors.New("containerstream: invalid Engine API socket path")
	}
	version := strings.TrimPrefix(strings.TrimSpace(config.APIVersion), "v")
	if version != "" && !validEngineAPIVersion(version) {
		return nil, errors.New("containerstream: invalid Engine API version")
	}
	libpodVersion := strings.TrimPrefix(strings.TrimSpace(config.LibpodAPIVersion), "v")
	if libpodVersion != "" && !validLibpodAPIVersion(libpodVersion) {
		return nil, errors.New("containerstream: invalid Libpod API version")
	}
	if name != ProviderPodman && libpodVersion != "" {
		return nil, errors.New("containerstream: Libpod API version is valid only for podman")
	}
	probe := config.Probe
	if probe == nil {
		probe = OSProbe{}
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	provider := &EngineAPIProvider{
		name: name, socketPath: socketPath, apiVersion: version, libpodAPIVersion: libpodVersion,
		probe: probe, dialContext: dial,
	}
	if name == ProviderDocker {
		provider.resolve = dockerEngineSockets
	} else {
		provider.resolve = podmanEngineSockets
	}
	return provider, nil
}

func newDefaultEngineAPIProvider(name string) Provider {
	provider, err := NewEngineAPIProvider(EngineAPIConfig{Name: name})
	if err != nil {
		panic(err)
	}
	return provider
}

func (p *EngineAPIProvider) Name() string { return p.name }

func (p *EngineAPIProvider) Discover(probe Probe) Candidate {
	if probe == nil {
		probe = OSProbe{}
	}
	candidate := Candidate{Provider: p.name}
	weight := 35
	environmentName := "DOCKER_HOST"
	environmentWeight := 30
	if p.name == ProviderPodman {
		weight = 45
		environmentName = "CONTAINER_HOST"
		environmentWeight = 20
	}
	if p.socketPath == "" {
		if value, ok := probe.LookupEnv(environmentName); ok && strings.TrimSpace(value) != "" {
			candidate.Score += environmentWeight
			candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "environment", Value: environmentName, Weight: environmentWeight})
		}
	}
	for _, socket := range p.socketPaths(probe) {
		if probe.Socket(socket) {
			candidate.Available = true
			candidate.Score += weight
			candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "socket", Value: socket, Weight: weight})
			break
		}
	}
	return candidate
}

func (p *EngineAPIProvider) OpenContainerStream(ctx context.Context, request Request) (io.ReadCloser, error) {
	if err := validateEngineRequest(p.name, request); err != nil {
		return nil, err
	}
	process, err := p.start(ctx, request, []string{"cat", "--", request.FilePath}, nil, false)
	if err != nil {
		return nil, err
	}
	_ = process.Stdin().Close()
	stderr := &boundedWriter{maximum: maxEngineAPIError}
	stderrDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(stderr, process.Stderr())
		close(stderrDone)
	}()
	return &engineFileStream{process: process, stdout: process.Stdout(), stderr: stderr, stderrDone: stderrDone}, nil
}

func (p *EngineAPIProvider) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	if err := validateEngineRequest(p.name, request); err != nil {
		return nil, err
	}
	if err := validateProcessSpec(spec); err != nil {
		return nil, err
	}
	if spec.TTY && p.name != ProviderPodman {
		return nil, fmt.Errorf("%w: Docker-compatible API fast path has no portable per-exec termination contract", ErrControlUnsupported)
	}
	return p.start(ctx, request, spec.Argv, spec.Environment, spec.TTY)
}

func (p *EngineAPIProvider) start(ctx context.Context, request Request, argv []string, environment map[string]string, tty bool) (Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	socket, err := p.availableSocket()
	if err != nil {
		return nil, err
	}
	endpoint := newEngineEndpoint(socket, p.name, p.apiVersion, p.libpodAPIVersion, p.dialContext)
	libpod := p.name == ProviderPodman && tty
	succeeded := false
	defer func() {
		if !succeeded {
			endpoint.transport.CloseIdleConnections()
		}
	}()
	if err := endpoint.negotiate(ctx, libpod); err != nil {
		return nil, classifyEngineDialError(err)
	}
	if libpod && !libpodSupportsExecRemove(endpoint.libpodVersion) {
		return nil, fmt.Errorf("%w: Podman detachable TTY requires Libpod API 4.8.0 or newer", ErrControlUnsupported)
	}
	execID, err := endpoint.createExec(ctx, request.TargetID, argv, environment, tty, libpod)
	if err != nil {
		return nil, err
	}
	duplex, err := endpoint.startExec(ctx, execID, tty, libpod)
	if err != nil {
		if libpod {
			cleanupContext, cancel := context.WithTimeout(context.Background(), engineCleanupDeadline)
			_ = endpoint.removeExec(cleanupContext, execID)
			cancel()
		}
		return nil, err
	}
	succeeded = true
	return newEngineProcess(ctx, p.name, endpoint, execID, duplex, tty, libpod), nil
}

func (p *EngineAPIProvider) availableSocket() (string, error) {
	for _, socket := range p.socketPaths(p.probe) {
		if p.probe.Socket(socket) {
			return socket, nil
		}
	}
	return "", ErrFastPathUnavailable
}

func (p *EngineAPIProvider) socketPaths(probe Probe) []string {
	if p.socketPath != "" {
		return []string{p.socketPath}
	}
	if p.resolve == nil {
		return nil
	}
	return p.resolve(probe)
}

func validateEngineRequest(name string, request Request) error {
	if _, err := safeAdapterToken("target", request.TargetID); err != nil {
		return err
	}
	if request.FilePath == "" || !strings.HasPrefix(request.FilePath, "/") || strings.ContainsAny(request.FilePath, "\x00\r\n") {
		return errors.New("containerstream: Engine API requires an absolute file path")
	}
	for option := range request.Options {
		if (name == ProviderDocker && option == "context") || (name == ProviderPodman && option == "connection") {
			return ErrFastPathUnavailable
		}
		return fmt.Errorf("containerstream: provider %s does not support option %q", name, option)
	}
	return nil
}

type engineEndpoint struct {
	socket        string
	provider      string
	version       string
	libpodVersion string
	dialContext   func(context.Context, string, string) (net.Conn, error)
	client        *http.Client
	transport     *http.Transport
	mu            sync.Mutex
}

func newEngineEndpoint(socket, provider, version, libpodVersion string, dial func(context.Context, string, string) (net.Conn, error)) *engineEndpoint {
	endpoint := &engineEndpoint{socket: socket, provider: provider, version: version, libpodVersion: libpodVersion, dialContext: dial}
	endpoint.transport = &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "unix", socket)
		},
	}
	endpoint.client = &http.Client{Transport: endpoint.transport}
	return endpoint
}

func (e *engineEndpoint) negotiate(ctx context.Context, requireLibpod bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.version != "" && (!requireLibpod || e.libpodVersion != "") {
		return nil
	}
	var response struct {
		APIVersion string `json:"ApiVersion"`
		Components []struct {
			Name    string            `json:"Name"`
			Details map[string]string `json:"Details"`
		} `json:"Components"`
	}
	if err := e.doJSON(ctx, http.MethodGet, "/version", nil, &response); err != nil {
		return err
	}
	if e.version == "" {
		version := strings.TrimPrefix(strings.TrimSpace(response.APIVersion), "v")
		if !validEngineAPIVersion(version) {
			return errors.New("containerstream: Engine API returned an invalid version")
		}
		e.version = version
	}
	if !requireLibpod || e.libpodVersion != "" {
		return nil
	}
	version := ""
	for _, component := range response.Components {
		candidate := strings.TrimPrefix(strings.TrimSpace(component.Details["APIVersion"]), "v")
		if strings.EqualFold(strings.TrimSpace(component.Name), "Podman Engine") && validLibpodAPIVersion(candidate) {
			version = candidate
			break
		}
	}
	if !validLibpodAPIVersion(version) {
		return errors.New("containerstream: Podman version response omitted a valid Libpod API version")
	}
	e.libpodVersion = version
	return nil
}

func (e *engineEndpoint) createExec(ctx context.Context, target string, argv []string, environment map[string]string, tty, libpod bool) (string, error) {
	values := make([]string, 0, len(environment))
	for name, value := range environment {
		values = append(values, name+"="+value)
	}
	sort.Strings(values)
	request := struct {
		AttachStdin  bool     `json:"AttachStdin"`
		AttachStdout bool     `json:"AttachStdout"`
		AttachStderr bool     `json:"AttachStderr"`
		TTY          bool     `json:"Tty"`
		Cmd          []string `json:"Cmd"`
		Env          []string `json:"Env,omitempty"`
	}{true, true, true, tty, append([]string(nil), argv...), values}
	var response struct {
		ID string `json:"Id"`
	}
	path := e.execAPIPath("/containers/"+url.PathEscape(target)+"/exec", libpod)
	if err := e.doJSON(ctx, http.MethodPost, path, request, &response); err != nil {
		return "", err
	}
	response.ID = strings.TrimSpace(response.ID)
	if response.ID == "" || len(response.ID) > 256 || strings.ContainsAny(response.ID, "/\\\x00\r\n") {
		return "", errors.New("containerstream: Engine API returned an invalid exec ID")
	}
	return response.ID, nil
}

func (e *engineEndpoint) startExec(ctx context.Context, execID string, tty, libpod bool) (*engineDuplex, error) {
	payload, _ := json.Marshal(struct {
		Detach bool `json:"Detach"`
		TTY    bool `json:"Tty"`
	}{false, tty})
	conn, err := e.dialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, classifyEngineDialError(err)
	}
	path := e.execAPIPath("/exec/"+url.PathEscape(execID)+"/start", libpod)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://engine"+path, bytes.NewReader(payload))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "tcp")
	if err := request.Write(conn); err != nil {
		_ = conn.Close()
		return nil, classifyEngineDialError(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols && response.StatusCode != http.StatusOK {
		message := readEngineError(response.Body)
		_ = response.Body.Close()
		_ = conn.Close()
		return nil, &engineAPIError{StatusCode: response.StatusCode, Message: message}
	}
	duplex := &engineDuplex{conn: conn, reader: reader}
	if response.StatusCode == http.StatusOK {
		duplex.reader = response.Body
		duplex.body = response.Body
	}
	return duplex, nil
}

func (e *engineEndpoint) inspectExec(ctx context.Context, execID string, libpod bool) (bool, int, error) {
	var response struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	path := e.execAPIPath("/exec/"+url.PathEscape(execID)+"/json", libpod)
	if err := e.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return false, -1, err
	}
	return response.Running, response.ExitCode, nil
}

func (e *engineEndpoint) resizeExec(ctx context.Context, execID string, size TerminalSize, libpod bool) error {
	values := url.Values{}
	values.Set("h", strconv.FormatUint(uint64(size.Rows), 10))
	values.Set("w", strconv.FormatUint(uint64(size.Cols), 10))
	path := e.execAPIPath("/exec/"+url.PathEscape(execID)+"/resize", libpod) + "?" + values.Encode()
	return e.doJSON(ctx, http.MethodPost, path, nil, nil)
}

func (e *engineEndpoint) removeExec(ctx context.Context, execID string) error {
	request := struct {
		Force bool `json:"Force"`
	}{Force: true}
	path := e.execAPIPath("/exec/"+url.PathEscape(execID)+"/remove", true)
	return e.doJSON(ctx, http.MethodPost, path, request, nil)
}

func (e *engineEndpoint) apiPath(path string) string { return "/v" + e.version + path }

func (e *engineEndpoint) execAPIPath(path string, libpod bool) string {
	if libpod {
		return "/v" + e.libpodVersion + "/libpod" + path
	}
	return e.apiPath(path)
}

func (e *engineEndpoint) doJSON(ctx context.Context, method, path string, requestBody, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://engine"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := e.client.Do(request)
	if err != nil {
		return classifyEngineDialError(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &engineAPIError{StatusCode: response.StatusCode, Message: readEngineError(response.Body)}
	}
	if responseBody == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(responseBody); err != nil {
		return fmt.Errorf("containerstream: decode Engine API response: %w", err)
	}
	return nil
}

type engineAPIError struct {
	StatusCode int
	Message    string
}

func (e *engineAPIError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("containerstream: Engine API status %d: %s", e.StatusCode, message)
}

func engineStatus(err error, status int) bool {
	var apiError *engineAPIError
	return errors.As(err, &apiError) && apiError.StatusCode == status
}

type engineDuplex struct {
	conn   net.Conn
	reader io.Reader
	body   io.Closer
	once   sync.Once
}

func (d *engineDuplex) Close() error {
	var closeErr error
	d.once.Do(func() {
		if d.body != nil {
			closeErr = d.body.Close()
		}
		closeErr = errors.Join(closeErr, d.conn.Close())
	})
	return closeErr
}

type engineStdin struct {
	conn net.Conn
	mu   sync.Mutex
	done bool
}

func (w *engineStdin) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return 0, io.ErrClosedPipe
	}
	return w.conn.Write(payload)
}

func (w *engineStdin) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	if closer, ok := w.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

type engineProcess struct {
	ctx      context.Context
	provider string
	endpoint *engineEndpoint
	execID   string
	duplex   *engineDuplex
	tty      bool
	libpod   bool
	stdin    *engineStdin
	stdout   *io.PipeReader
	stderr   io.ReadCloser
	pumpDone chan error

	waitOnce  sync.Once
	closeOnce sync.Once
	stateMu   sync.Mutex
	closing   bool
	closeErr  error
	done      chan struct{}
	result    ProcessResult
}

func newEngineProcess(ctx context.Context, provider string, endpoint *engineEndpoint, execID string, duplex *engineDuplex, tty, libpod bool) *engineProcess {
	stdout, stdoutWriter := io.Pipe()
	process := &engineProcess{
		ctx: ctx, provider: provider, endpoint: endpoint, execID: execID, duplex: duplex,
		tty: tty, libpod: libpod, stdin: &engineStdin{conn: duplex.conn}, stdout: stdout,
		pumpDone: make(chan error, 1), done: make(chan struct{}),
	}
	var stderrWriter *io.PipeWriter
	if tty {
		process.stderr = io.NopCloser(strings.NewReader(""))
	} else {
		process.stderr, stderrWriter = io.Pipe()
	}
	go func() {
		var err error
		if tty {
			_, err = io.Copy(stdoutWriter, duplex.reader)
		} else {
			err = demultiplexEngineOutput(duplex.reader, stdoutWriter, stderrWriter)
		}
		if normalEngineStreamEnd(err) {
			err = nil
		}
		_ = stdoutWriter.CloseWithError(err)
		if stderrWriter != nil {
			_ = stderrWriter.CloseWithError(err)
		}
		process.pumpDone <- err
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = process.Close()
		case <-process.done:
		}
	}()
	return process
}

func (p *engineProcess) ProviderName() string { return p.provider }
func (p *engineProcess) Capabilities() ProcessCapabilities {
	return ProcessCapabilities{Stdin: true, Stdout: true, Stderr: !p.tty, TTY: p.tty, Resize: p.tty, Terminate: p.libpod}
}
func (p *engineProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *engineProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *engineProcess) Stderr() io.ReadCloser { return p.stderr }
func (*engineProcess) Signal(context.Context, ProcessSignal) error {
	return ErrControlUnsupported
}
func (p *engineProcess) Resize(ctx context.Context, size TerminalSize) error {
	if !p.tty || !p.libpod {
		return ErrControlUnsupported
	}
	if size.Rows == 0 || size.Cols == 0 {
		return errors.New("containerstream: terminal dimensions must be non-zero")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-p.done:
		return io.ErrClosedPipe
	default:
	}
	return p.endpoint.resizeExec(ctx, p.execID, size, true)
}

func (p *engineProcess) Wait() ProcessResult {
	p.waitOnce.Do(func() {
		pumpErr := <-p.pumpDone
		p.stateMu.Lock()
		closing := p.closing
		p.stateMu.Unlock()
		if closing && errors.Is(pumpErr, io.ErrClosedPipe) {
			pumpErr = nil
		}
		inspectContext, cancel := context.WithTimeout(p.ctx, engineInspectDeadline)
		defer cancel()
		exitCode, inspectErr := p.waitForInspect(inspectContext)
		p.result = ProcessResult{ExitCode: exitCode, Err: errors.Join(pumpErr, inspectErr)}
		p.endpoint.transport.CloseIdleConnections()
		close(p.done)
	})
	<-p.done
	return p.result
}

func (p *engineProcess) waitForInspect(ctx context.Context) (int, error) {
	for {
		running, exitCode, err := p.endpoint.inspectExec(ctx, p.execID, p.libpod)
		if err != nil {
			p.stateMu.Lock()
			closing := p.closing
			p.stateMu.Unlock()
			if closing && engineStatus(err, http.StatusNotFound) {
				return -1, nil
			}
			return -1, err
		}
		if !running {
			return exitCode, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (p *engineProcess) Close() error {
	p.closeOnce.Do(func() {
		p.stateMu.Lock()
		p.closing = true
		p.stateMu.Unlock()
		if p.libpod {
			cleanupContext, cancel := context.WithTimeout(context.Background(), engineCleanupDeadline)
			removeErr := p.endpoint.removeExec(cleanupContext, p.execID)
			cancel()
			if engineStatus(removeErr, http.StatusNotFound) {
				removeErr = nil
			}
			p.stateMu.Lock()
			p.closeErr = removeErr
			p.stateMu.Unlock()
		}
		_ = p.stdin.Close()
		_ = p.duplex.Close()
		_ = p.stdout.Close()
		_ = p.stderr.Close()
	})
	result := p.Wait()
	p.stateMu.Lock()
	closeErr := p.closeErr
	p.stateMu.Unlock()
	return errors.Join(closeErr, result.Err)
}

type engineFileStream struct {
	process    Process
	stdout     io.ReadCloser
	stderr     *boundedWriter
	stderrDone <-chan struct{}
	mu         sync.Mutex
	done       bool
	waitErr    error
}

func (s *engineFileStream) Read(payload []byte) (int, error) {
	n, err := s.stdout.Read(payload)
	if !errors.Is(err, io.EOF) {
		return n, err
	}
	if waitErr := s.wait(false); waitErr != nil {
		return n, waitErr
	}
	return n, io.EOF
}

func (s *engineFileStream) Close() error {
	_ = s.stdout.Close()
	return s.wait(true)
}

func (s *engineFileStream) wait(cancel bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return s.waitErr
	}
	s.done = true
	var result ProcessResult
	if cancel {
		s.waitErr = s.process.Close()
		result = ProcessResult{ExitCode: -1, Err: s.waitErr}
	} else {
		result = s.process.Wait()
		s.waitErr = errors.Join(result.Err, s.process.Close())
	}
	<-s.stderrDone
	if s.waitErr == nil && result.ExitCode != 0 {
		s.waitErr = fmt.Errorf("containerstream: Engine API cat exited with code %d: %s", result.ExitCode, s.stderr.String())
	}
	return s.waitErr
}

func demultiplexEngineOutput(reader io.Reader, stdout, stderr io.Writer) error {
	header := make([]byte, 8)
	buffer := make([]byte, 32<<10)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if length > maxEngineOutputFrame {
			return errors.New("containerstream: Engine API output frame exceeds 32 MiB")
		}
		var destination io.Writer
		switch header[0] {
		case 1:
			destination = stdout
		case 2:
			destination = stderr
		default:
			return fmt.Errorf("containerstream: invalid Engine API output stream %d", header[0])
		}
		remaining := int64(length)
		for remaining > 0 {
			chunk := int64(len(buffer))
			if remaining < chunk {
				chunk = remaining
			}
			read, err := io.ReadFull(reader, buffer[:int(chunk)])
			if read > 0 {
				if _, writeErr := destination.Write(buffer[:read]); writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
					return writeErr
				}
			}
			remaining -= int64(read)
			if err != nil {
				return err
			}
		}
	}
}

func readEngineError(reader io.Reader) string {
	payload, _ := io.ReadAll(io.LimitReader(reader, maxEngineAPIError))
	var response struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &response) == nil && strings.TrimSpace(response.Message) != "" {
		return strings.TrimSpace(response.Message)
	}
	return strings.TrimSpace(string(payload))
}

func normalEngineStreamEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func classifyEngineDialError(err error) error {
	if err == nil || errors.Is(err, ErrFastPathUnavailable) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: %v", ErrFastPathUnavailable, err)
	}
	return err
}

func validEngineAPIVersion(version string) bool {
	if version == "" || len(version) > 16 {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validLibpodAPIVersion(version string) bool {
	if version == "" || len(version) > 24 {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func libpodSupportsExecRemove(version string) bool {
	if !validLibpodAPIVersion(version) {
		return false
	}
	parts := strings.Split(version, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major > 4 || (major == 4 && minor >= 8)
}

func dockerEngineSockets(probe Probe) []string {
	if value, ok := probe.LookupEnv("DOCKER_HOST"); ok && strings.TrimSpace(value) != "" {
		if socket := unixSocketFromURL(value); socket != "" {
			return []string{socket}
		}
		return nil
	}
	return []string{"/var/run/docker.sock"}
}

func podmanEngineSockets(probe Probe) []string {
	if value, ok := probe.LookupEnv("CONTAINER_HOST"); ok && strings.TrimSpace(value) != "" {
		if socket := unixSocketFromURL(value); socket != "" {
			return []string{socket}
		}
		return nil
	}
	paths := make([]string, 0, 2)
	if runtimeDirectory, ok := probe.LookupEnv("XDG_RUNTIME_DIR"); ok {
		runtimeDirectory = strings.TrimSpace(runtimeDirectory)
		if safeEngineSocketPath(runtimeDirectory) {
			paths = append(paths, filepath.Join(filepath.Clean(runtimeDirectory), "podman", "podman.sock"))
		}
	}
	if len(paths) == 0 || paths[0] != "/run/podman/podman.sock" {
		paths = append(paths, "/run/podman/podman.sock")
	}
	return paths
}

func unixSocketFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "unix" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "" {
		return ""
	}
	path, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || !safeEngineSocketPath(path) {
		return ""
	}
	return filepath.Clean(path)
}

func safeEngineSocketPath(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && len(path) <= 4096 && filepath.IsAbs(path) && !strings.ContainsAny(path, "\x00\r\n")
}
