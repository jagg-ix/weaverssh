package p9svc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"weaverssh/containerstream"
	"weaverssh/internal/p9client"
)

type processFSTestProvider struct{}

func (*processFSTestProvider) Name() string { return "processfs-test" }
func (*processFSTestProvider) OpenContainerStream(context.Context, containerstream.Request) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}
func (*processFSTestProvider) StartContainerProcess(context.Context, containerstream.Request, containerstream.ProcessSpec) (containerstream.Process, error) {
	return newProcessFSTestProcess(), nil
}

type processFSTestProcess struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	stderrR *io.PipeReader
	stderrW *io.PipeWriter
	done    chan struct{}
	once    sync.Once
	result  containerstream.ProcessResult
}

func newProcessFSTestProcess() *processFSTestProcess {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	process := &processFSTestProcess{
		stdinR: stdinR, stdinW: stdinW, stdoutR: stdoutR, stdoutW: stdoutW,
		stderrR: stderrR, stderrW: stderrW, done: make(chan struct{}),
	}
	go func() {
		payload, err := io.ReadAll(stdinR)
		if err != nil {
			process.complete(containerstream.ProcessResult{ExitCode: -1, Err: err})
			return
		}
		_, _ = stdoutW.Write(append([]byte("out:"), payload...))
		_ = stdoutW.Close()
		_, _ = stderrW.Write([]byte("diagnostic"))
		_ = stderrW.Close()
		process.complete(containerstream.ProcessResult{ExitCode: 0})
	}()
	return process
}

func (*processFSTestProcess) ProviderName() string { return "processfs-test" }
func (*processFSTestProcess) Capabilities() containerstream.ProcessCapabilities {
	return containerstream.ProcessCapabilities{Stdin: true, Stdout: true, Stderr: true}
}
func (p *processFSTestProcess) Stdin() io.WriteCloser { return p.stdinW }
func (p *processFSTestProcess) Stdout() io.ReadCloser { return p.stdoutR }
func (p *processFSTestProcess) Stderr() io.ReadCloser { return p.stderrR }
func (p *processFSTestProcess) Wait() containerstream.ProcessResult {
	<-p.done
	return p.result
}
func (*processFSTestProcess) Signal(context.Context, containerstream.ProcessSignal) error {
	return containerstream.ErrControlUnsupported
}
func (*processFSTestProcess) Resize(context.Context, containerstream.TerminalSize) error {
	return containerstream.ErrControlUnsupported
}
func (p *processFSTestProcess) Close() error {
	_ = p.stdinR.Close()
	_ = p.stdinW.Close()
	_ = p.stdoutW.Close()
	_ = p.stderrW.Close()
	p.complete(containerstream.ProcessResult{ExitCode: -1, Err: context.Canceled})
	return nil
}
func (p *processFSTestProcess) complete(result containerstream.ProcessResult) {
	p.once.Do(func() {
		p.result = result
		close(p.done)
	})
}

func TestProcessFSServerServesSyntheticSessionOverTyped9P(t *testing.T) {
	registry := containerstream.NewRegistry()
	registry.MustRegister(&processFSTestProvider{})
	router, err := containerstream.NewRouter(registry, containerstream.Discoverer{}, containerstream.RouterConfig{Provider: "processfs-test"})
	if err != nil {
		t.Fatal(err)
	}
	var starts atomic.Int32
	authorizer := containerstream.ProcessAuthorizerFunc(func(_ context.Context, identity containerstream.ProcessIdentity, target containerstream.Request, request containerstream.StartRequest) (containerstream.ProcessSpec, error) {
		if identity.Principal != "alice@example.test" || identity.SourceNode != "workstation" || target.TargetID != "pod-a" || request.Action != "inspect" {
			return containerstream.ProcessSpec{}, containerstream.ErrProcessPermission
		}
		starts.Add(1)
		return containerstream.ProcessSpec{Argv: []string{"/usr/bin/inspect"}, MaxStdinBytes: 64}, nil
	})
	manager, err := containerstream.NewProcessManager(context.Background(), router, authorizer, containerstream.ProcessManagerConfig{
		NewSessionID: func() (string, error) { return "session-a", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	filesystem, err := containerstream.NewProcessFSWithManager(manager, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &ProcessFSServer{
		Filesystem: filesystem,
		ResolvePrincipal: func(containerstream.ProcessFSOpenMetadata) (string, error) {
			return "alice@example.test", nil
		},
	}
	raw, err := containerstream.NewProcessFSOpenMetadata("node-a", "vfs://container/node-a/pod-a/.wv/processes?provider=processfs-test")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := containerstream.BindProcessFSSource(raw, "workstation", "binding-a", strings.Repeat("a", 64), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeBound(context.Background(), serverTransport, bound) }()
	client, err := p9client.Attach(clientTransport)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := client.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries=%+v", entries)
	}
	statusPayload, err := client.ReadFile(containerstream.ProcessFileStatus)
	if err != nil {
		t.Fatal(err)
	}
	var status containerstream.ProcessStatus
	if err := json.Unmarshal(statusPayload, &status); err != nil {
		t.Fatal(err)
	}
	if status.SessionID != "session-a" || status.State != containerstream.ProcessCreated {
		t.Fatalf("created status=%+v", status)
	}

	control, err := client.OpenFile(containerstream.ProcessFileControl, p9client.OWRITE|p9client.OTRUNC)
	if err != nil {
		t.Fatal(err)
	}
	controlPayload, _ := json.Marshal(containerstream.ControlRequest{
		Protocol: containerstream.ProcessControlProtocol, Operation: "start", Action: "inspect",
	})
	if _, err := control.WriteAt(controlPayload, 0); err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	stdoutFile, err := client.OpenFile(containerstream.ProcessFileStdout, p9client.OREAD)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		payload []byte
		err     error
	}
	stdoutDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 64)
		count, readErr := stdoutFile.ReadAt(buffer, 0)
		stdoutDone <- readResult{payload: append([]byte(nil), buffer[:count]...), err: readErr}
	}()
	stdin, err := client.OpenFile(containerstream.ProcessFileStdin, p9client.OWRITE)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.WriteAt([]byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout []byte
	select {
	case result := <-stdoutDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		stdout = result.payload
	case <-time.After(2 * time.Second):
		t.Fatal("blocking stdout read prevented concurrent stdin delivery")
	}
	if err := stdoutFile.Close(); err != nil {
		t.Fatal(err)
	}
	stderr, err := client.ReadFile(containerstream.ProcessFileStderr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout, []byte("out:payload")) || !bytes.Equal(stderr, []byte("diagnostic")) {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessFS server did not stop after transport close")
	}

	// A transport failure with ctl still open must discard the transaction;
	// cleanup must never turn a partially delivered record into execution.
	serverTransport, clientTransport = net.Pipe()
	serverDone = make(chan error, 1)
	go func() { serverDone <- server.ServeBound(context.Background(), serverTransport, bound) }()
	client, err = p9client.Attach(clientTransport)
	if err != nil {
		t.Fatal(err)
	}
	uncommitted, err := client.OpenFile(containerstream.ProcessFileControl, p9client.OWRITE)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uncommitted.WriteAt(controlPayload, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessFS server did not stop with uncommitted ctl")
	}
	if starts.Load() != 1 {
		t.Fatalf("uncommitted ctl invoked authorizer: starts=%d", starts.Load())
	}
}

func TestProcessFSServerRejectsUnboundMetadata(t *testing.T) {
	raw, err := containerstream.NewProcessFSOpenMetadata("node-a", "vfs://container/node-a/pod-a/.wv/processes")
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	_ = clientSide.Close()
	server := &ProcessFSServer{Filesystem: &containerstream.ProcessFS{}}
	if err := server.ServeBound(context.Background(), serverSide, raw); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("error=%v", err)
	}
}
