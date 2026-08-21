package containerstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type scriptedExecutionProvider struct {
	mu        sync.Mutex
	requests  []Request
	specs     []ProcessSpec
	processes []*scriptedProcess
}

func (p *scriptedExecutionProvider) Name() string { return "fake" }
func (p *scriptedExecutionProvider) OpenContainerStream(context.Context, Request) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("file")), nil
}
func (p *scriptedExecutionProvider) StartContainerProcess(_ context.Context, request Request, spec ProcessSpec) (Process, error) {
	process := newScriptedProcess()
	p.mu.Lock()
	p.requests = append(p.requests, request)
	p.specs = append(p.specs, spec)
	p.processes = append(p.processes, process)
	p.mu.Unlock()
	return process, nil
}

type scriptedProcess struct {
	stdinReader  *io.PipeReader
	stdinWriter  *io.PipeWriter
	stdoutReader *io.PipeReader
	stdoutWriter *io.PipeWriter
	stderrReader *io.PipeReader
	stderrWriter *io.PipeWriter

	mu      sync.Mutex
	signals []ProcessSignal
	sizes   []TerminalSize
	result  ProcessResult
	done    chan struct{}
	finish  sync.Once
}

func newScriptedProcess() *scriptedProcess {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	process := &scriptedProcess{
		stdinReader: stdinReader, stdinWriter: stdinWriter,
		stdoutReader: stdoutReader, stdoutWriter: stdoutWriter,
		stderrReader: stderrReader, stderrWriter: stderrWriter,
		done: make(chan struct{}),
	}
	go func() {
		payload, err := io.ReadAll(stdinReader)
		if err != nil {
			process.complete(ProcessResult{ExitCode: -1, Err: err})
			return
		}
		_, _ = stdoutWriter.Write(append([]byte("echo:"), payload...))
		_ = stdoutWriter.Close()
		_, _ = stderrWriter.Write([]byte("warning"))
		_ = stderrWriter.Close()
		process.complete(ProcessResult{ExitCode: 0})
	}()
	return process
}

func (p *scriptedProcess) ProviderName() string { return "fake" }
func (p *scriptedProcess) Capabilities() ProcessCapabilities {
	return ProcessCapabilities{Stdin: true, Stdout: true, Stderr: true, TTY: true, Signals: true, Resize: true}
}
func (p *scriptedProcess) Stdin() io.WriteCloser { return p.stdinWriter }
func (p *scriptedProcess) Stdout() io.ReadCloser { return p.stdoutReader }
func (p *scriptedProcess) Stderr() io.ReadCloser { return p.stderrReader }
func (p *scriptedProcess) Wait() ProcessResult {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result
}
func (p *scriptedProcess) Signal(_ context.Context, signal ProcessSignal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signals = append(p.signals, signal)
	return nil
}
func (p *scriptedProcess) Resize(_ context.Context, size TerminalSize) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sizes = append(p.sizes, size)
	return nil
}
func (p *scriptedProcess) Close() error {
	_ = p.stdinReader.Close()
	_ = p.stdinWriter.Close()
	_ = p.stdoutWriter.Close()
	_ = p.stderrWriter.Close()
	p.complete(ProcessResult{ExitCode: -1, Err: context.Canceled})
	return nil
}
func (p *scriptedProcess) complete(result ProcessResult) {
	p.finish.Do(func() {
		p.mu.Lock()
		p.result = result
		p.mu.Unlock()
		close(p.done)
	})
}

func newTestProcessFS(t *testing.T, stdinLimit int64) (*ProcessFS, *scriptedExecutionProvider) {
	t.Helper()
	provider := &scriptedExecutionProvider{}
	registry := NewRegistry()
	registry.MustRegister(provider)
	router, err := NewRouter(registry, Discoverer{}, RouterConfig{Provider: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := ProcessAuthorizerFunc(func(_ context.Context, _ ProcessIdentity, _ Request, request StartRequest) (ProcessSpec, error) {
		if request.Action != "copy" {
			return ProcessSpec{}, errors.New("denied action")
		}
		return ProcessSpec{
			Argv: append([]string{"/usr/bin/copy"}, request.Args...), Environment: request.Environment,
			TTY: request.TTY, MaxStdinBytes: stdinLimit,
		}, nil
	})
	fs, err := NewProcessFS(context.Background(), router, authorizer, ProcessFSConfig{
		NewSessionID: func() (string, error) { return "session-a", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fs, provider
}

func TestSyntheticProcessLifecycleAndStreams(t *testing.T) {
	fs, provider := newTestProcessFS(t, 5)
	session, err := fs.CreateSession(Request{
		Endpoint: "node-a", TargetID: "pod-a", ProviderHint: "fake",
		Options: map[string]string{"namespace": "jobs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status().State != ProcessCreated || len(session.Files()) != 5 {
		t.Fatalf("unexpected created session: %+v", session.Status())
	}
	rootURI, _ := session.URI("")
	ref, err := ParseProcessURI(rootURI)
	if err != nil || ref.SessionID != "session-a" || ref.ProviderHint != "fake" || ref.Options["namespace"] != "jobs" {
		t.Fatalf("ref=%+v err=%v", ref, err)
	}

	ctlURI, _ := session.URI(ProcessFileControl)
	writeControl(t, fs, ctlURI, ControlRequest{
		Protocol: ProcessControlProtocol, Operation: "start", Action: "copy",
		Args: []string{"private-argument-marker"}, Environment: map[string]string{"LANG": "private-environment-marker"}, TTY: true,
	})
	if status := session.Status(); status.State != ProcessRunning || status.Provider != "fake" || !status.Capabilities.Resize {
		t.Fatalf("unexpected running status: %+v", status)
	}

	writeControl(t, fs, ctlURI, ControlRequest{Protocol: ProcessControlProtocol, Operation: "signal", Signal: SignalINT})
	writeControl(t, fs, ctlURI, ControlRequest{Protocol: ProcessControlProtocol, Operation: "resize", Rows: 42, Cols: 120})

	stdoutURI, _ := session.URI(ProcessFileStdout)
	stderrURI, _ := session.URI(ProcessFileStderr)
	stdout, err := fs.OpenReader(context.Background(), stdoutURI)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := fs.OpenReader(context.Background(), stderrURI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.OpenReader(context.Background(), stdoutURI); !errors.Is(err, ErrProcessState) {
		t.Fatalf("second stdout open err=%v", err)
	}

	stdinURI, _ := session.URI(ProcessFileStdin)
	stdin, err := fs.OpenWriter(context.Background(), stdinURI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("!")); !errors.Is(err, ErrProcessLimit) {
		t.Fatalf("stdin limit err=%v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	stdoutPayload, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	stderrPayload, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdoutPayload) != "echo:hello" || string(stderrPayload) != "warning" {
		t.Fatalf("stdout=%q stderr=%q", stdoutPayload, stderrPayload)
	}

	status := waitForProcessState(t, session, ProcessExited)
	if status.ExitCode == nil || *status.ExitCode != 0 || status.StdinBytes != 5 {
		t.Fatalf("unexpected terminal status: %+v", status)
	}
	statusURI, _ := session.URI(ProcessFileStatus)
	statusReader, err := fs.OpenReader(context.Background(), statusURI)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ProcessStatus
	statusPayload, err := io.ReadAll(statusReader)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusPayload), "private-argument-marker") || strings.Contains(string(statusPayload), "private-environment-marker") {
		t.Fatalf("status leaked argv or environment: %s", statusPayload)
	}
	if err := json.Unmarshal(statusPayload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.State != ProcessExited || decoded.SessionID != session.ID() {
		t.Fatalf("decoded status=%+v", decoded)
	}

	provider.mu.Lock()
	process := provider.processes[0]
	spec := provider.specs[0]
	provider.mu.Unlock()
	process.mu.Lock()
	signals := append([]ProcessSignal(nil), process.signals...)
	sizes := append([]TerminalSize(nil), process.sizes...)
	process.mu.Unlock()
	if !reflect.DeepEqual(signals, []ProcessSignal{SignalINT}) || !reflect.DeepEqual(sizes, []TerminalSize{{Rows: 42, Cols: 120}}) {
		t.Fatalf("signals=%v sizes=%v", signals, sizes)
	}
	if !reflect.DeepEqual(spec.Argv, []string{"/usr/bin/copy", "private-argument-marker"}) || spec.Environment["LANG"] != "private-environment-marker" {
		t.Fatalf("authorized spec=%+v", spec)
	}
	if err := fs.RemoveSession(rootURI); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.OpenReader(context.Background(), statusURI); !errors.Is(err, ErrProcessNotFound) {
		t.Fatalf("read removed session err=%v", err)
	}
}

func TestSyntheticProcessControlIsStrictAndDirectional(t *testing.T) {
	fs, _ := newTestProcessFS(t, 32)
	session, err := fs.CreateSession(Request{Endpoint: "node-a", TargetID: "pod-a"})
	if err != nil {
		t.Fatal(err)
	}
	ctlURI, _ := session.URI(ProcessFileControl)
	statusURI, _ := session.URI(ProcessFileStatus)
	if _, err := fs.OpenReader(context.Background(), ctlURI); !errors.Is(err, ErrProcessPermission) {
		t.Fatalf("read ctl err=%v", err)
	}
	if _, err := fs.OpenWriter(context.Background(), statusURI); !errors.Is(err, ErrProcessPermission) {
		t.Fatalf("write status err=%v", err)
	}
	writer, err := fs.OpenWriter(context.Background(), ctlURI)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte(`{"protocol":"weaverssh.procctl.v1","op":"start","action":"copy","command":"/bin/sh"}`))
	if err := writer.Close(); err == nil || session.Status().State != ProcessCreated {
		t.Fatalf("unknown field err=%v status=%+v", err, session.Status())
	}
	writer, _ = fs.OpenWriter(context.Background(), ctlURI)
	_, _ = writer.Write([]byte(`{"protocol":"weaverssh.procctl.v1","op":"start","action":"copy","environment":{"API_TOKEN":"value"}}`))
	if err := writer.Close(); err == nil || session.Status().State != ProcessCreated {
		t.Fatalf("credential environment err=%v status=%+v", err, session.Status())
	}
	writeControl(t, fs, ctlURI, ControlRequest{Protocol: ProcessControlProtocol, Operation: "start", Action: "copy"})
	writer, _ = fs.OpenWriter(context.Background(), ctlURI)
	payload, _ := json.Marshal(ControlRequest{Protocol: ProcessControlProtocol, Operation: "start", Action: "copy"})
	_, _ = writer.Write(payload)
	if err := writer.Close(); !errors.Is(err, ErrProcessState) {
		t.Fatalf("second start err=%v", err)
	}
	writeControl(t, fs, ctlURI, ControlRequest{Protocol: ProcessControlProtocol, Operation: "close"})
}

func TestSyntheticProcessSessionLimit(t *testing.T) {
	provider := &scriptedExecutionProvider{}
	registry := NewRegistry()
	registry.MustRegister(provider)
	router, _ := NewRouter(registry, Discoverer{}, RouterConfig{Provider: "fake"})
	fs, err := NewProcessFS(context.Background(), router, ProcessAuthorizerFunc(func(context.Context, ProcessIdentity, Request, StartRequest) (ProcessSpec, error) {
		return ProcessSpec{Argv: []string{"/bin/true"}}, nil
	}), ProcessFSConfig{MaxSessions: 1, NewSessionID: func() (string, error) { return "same", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CreateSession(Request{Endpoint: "node-a", TargetID: "pod-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CreateSession(Request{Endpoint: "node-b", TargetID: "pod-b"}); !errors.Is(err, ErrProcessLimit) {
		t.Fatalf("session limit err=%v", err)
	}
}

func TestProcessFSFacadeSharesManagerRegistryAndCloseBoundary(t *testing.T) {
	provider := &scriptedExecutionProvider{}
	registry := NewRegistry()
	registry.MustRegister(provider)
	router, _ := NewRouter(registry, Discoverer{}, RouterConfig{Provider: "fake"})
	manager, err := NewProcessManager(context.Background(), router, ProcessAuthorizerFunc(func(context.Context, ProcessIdentity, Request, StartRequest) (ProcessSpec, error) {
		return ProcessSpec{Argv: []string{"/bin/true"}}, nil
	}), ProcessManagerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := NewProcessFSWithManager(manager, 0)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.CreateSession(ProcessIdentity{Principal: "broker-principal"}, Request{Endpoint: "node-a", TargetID: "pod-a"})
	if err != nil {
		t.Fatal(err)
	}
	statusURI, _ := session.URI(ProcessFileStatus)
	reader, err := fs.OpenReader(context.Background(), statusURI)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.OpenReader(context.Background(), statusURI); !errors.Is(err, ErrProcessNotFound) {
		t.Fatalf("closed manager lookup err=%v", err)
	}
	if _, err := manager.CreateSession(ProcessIdentity{}, Request{Endpoint: "node-a", TargetID: "pod-a"}); !errors.Is(err, ErrProcessState) {
		t.Fatalf("create after close err=%v", err)
	}
}

func TestRouterRejectsExecutionOnReadOnlyProvider(t *testing.T) {
	registry := NewRegistry()
	registry.MustRegister(staticProvider{name: "read-only", payload: "data"})
	router, err := NewRouter(registry, Discoverer{}, RouterConfig{Provider: "read-only"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = router.StartContainerProcess(context.Background(), Request{TargetID: "target"}, ProcessSpec{Argv: []string{"/bin/true"}})
	if !errors.Is(err, ErrExecutionUnsupported) {
		t.Fatalf("execution err=%v", err)
	}
}

func writeControl(t *testing.T, fs *ProcessFS, uri string, request ControlRequest) {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := fs.OpenWriter(context.Background(), uri)
	if err != nil {
		t.Fatal(err)
	}
	middle := len(payload) / 2
	if _, err := writer.Write(payload[:middle]); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload[middle:]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitForProcessState(t *testing.T, session *ProcessSession, want ProcessState) ProcessStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := session.Status()
		if status.State == want {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state=%s want=%s", session.Status().State, want)
	return ProcessStatus{}
}
