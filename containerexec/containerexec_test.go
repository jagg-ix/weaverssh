package containerexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"weaverssh/containerstream"
)

type testProvider struct{ process *testProcess }

func (p *testProvider) Name() string { return "test" }
func (p *testProvider) OpenContainerStream(context.Context, containerstream.Request) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}
func (p *testProvider) StartContainerProcess(_ context.Context, _ containerstream.Request, _ containerstream.ProcessSpec) (containerstream.Process, error) {
	p.process = newTestProcess()
	return p.process, nil
}

type testProcess struct {
	stdinReader, stdoutReader, stderrReader *io.PipeReader
	stdinWriter, stdoutWriter, stderrWriter *io.PipeWriter
	done                                    chan struct{}
	once                                    sync.Once
	result                                  containerstream.ProcessResult
}

func newTestProcess() *testProcess {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	process := &testProcess{
		stdinReader: stdinReader, stdinWriter: stdinWriter,
		stdoutReader: stdoutReader, stdoutWriter: stdoutWriter,
		stderrReader: stderrReader, stderrWriter: stderrWriter, done: make(chan struct{}),
	}
	go func() {
		input, err := io.ReadAll(stdinReader)
		if err != nil {
			process.complete(containerstream.ProcessResult{ExitCode: -1, Err: err})
			return
		}
		_, _ = stdoutWriter.Write(append([]byte("out:"), input...))
		_ = stdoutWriter.Close()
		_, _ = stderrWriter.Write([]byte("diagnostic"))
		_ = stderrWriter.Close()
		process.complete(containerstream.ProcessResult{ExitCode: 7})
	}()
	return process
}

func (p *testProcess) ProviderName() string { return "test" }
func (p *testProcess) Capabilities() containerstream.ProcessCapabilities {
	return containerstream.ProcessCapabilities{Stdin: true, Stdout: true, Stderr: true, Signals: true}
}
func (p *testProcess) Stdin() io.WriteCloser { return p.stdinWriter }
func (p *testProcess) Stdout() io.ReadCloser { return p.stdoutReader }
func (p *testProcess) Stderr() io.ReadCloser { return p.stderrReader }
func (p *testProcess) Wait() containerstream.ProcessResult {
	<-p.done
	return p.result
}
func (p *testProcess) Signal(context.Context, containerstream.ProcessSignal) error { return nil }
func (p *testProcess) Resize(context.Context, containerstream.TerminalSize) error {
	return containerstream.ErrControlUnsupported
}
func (p *testProcess) Close() error {
	_ = p.stdinReader.Close()
	_ = p.stdinWriter.Close()
	_ = p.stdoutWriter.Close()
	_ = p.stderrWriter.Close()
	p.complete(containerstream.ProcessResult{ExitCode: -1, Err: context.Canceled})
	return nil
}
func (p *testProcess) complete(result containerstream.ProcessResult) {
	p.once.Do(func() {
		p.result = result
		close(p.done)
	})
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	provider := &testProvider{}
	registry := containerstream.NewRegistry()
	registry.MustRegister(provider)
	router, err := containerstream.NewRouter(registry, containerstream.Discoverer{}, containerstream.RouterConfig{Provider: "test"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := containerstream.ProcessAuthorizerFunc(func(_ context.Context, identity containerstream.ProcessIdentity, target containerstream.Request, request containerstream.StartRequest) (containerstream.ProcessSpec, error) {
		if identity.Principal != "principal-a" || identity.SourceNode != "origin" || target.TargetID != "pod-a" || request.Action != "inspect" {
			return containerstream.ProcessSpec{}, containerstream.ErrProcessPermission
		}
		return containerstream.ProcessSpec{Argv: append([]string{"/usr/bin/inspect"}, request.Args...), MaxStdinBytes: 64}, nil
	})
	manager, err := containerstream.NewProcessManager(context.Background(), router, authorizer, containerstream.ProcessManagerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return &Server{Manager: manager, ResolvePrincipal: func(OpenMetadata) (string, error) { return "principal-a", nil }}
}

func TestStreamingExecUsesBoundIdentityAndSharedProcessManager(t *testing.T) {
	server := newTestServer(t)
	raw, err := NewOpenMetadata("node-a")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(raw, "origin", "binding-a", strings.Repeat("a", 64), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	serverStream, clientStream := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeBound(context.Background(), serverStream, bound) }()
	var stdout, stderr bytes.Buffer
	exit, err := CallStream(context.Background(), clientStream, Request{
		TargetURI: "vfs://container/node-a/pod-a/proc/exec?provider=test", Action: "inspect", Args: []string{"arg-a"},
	}, strings.NewReader("payload"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if exit.ExitCode != 7 || stdout.String() != "out:payload" || stderr.String() != "diagnostic" {
		t.Fatalf("exit=%+v stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestStreamingExecRejectsCrossNodeContainerTarget(t *testing.T) {
	server := newTestServer(t)
	raw, _ := NewOpenMetadata("node-a")
	bound, _ := BindSource(raw, "origin", "binding-a", strings.Repeat("a", 64), "node-a")
	serverStream, clientStream := net.Pipe()
	go func() { _ = server.ServeBound(context.Background(), serverStream, bound) }()
	_, err := CallStream(context.Background(), clientStream, Request{
		TargetURI: "vfs://container/node-b/pod-a/proc/exec?provider=test", Action: "inspect",
	}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err=%v", err)
	}
}

func TestMetadataBindingCannotBeReboundToAnotherChain(t *testing.T) {
	raw, _ := NewOpenMetadata("node-a")
	bound, _ := BindSource(raw, "origin", "binding-a", strings.Repeat("a", 64), "node-a")
	if _, err := BindSource(bound, "other", "binding-b", strings.Repeat("b", 64), "node-b"); err == nil {
		t.Fatal("expected provenance mismatch")
	}
}

func TestMetadataRejectsNonHexBoundChain(t *testing.T) {
	raw := []byte(`{"protocol":"weaverssh.container-exec-open.v1","target_node":"node-a","source_node":"origin","source_binding":"binding","chain_sha256":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`)
	if _, err := ParseOpenMetadata(raw); err == nil {
		t.Fatal("non-hex provenance chain was accepted")
	}
}
