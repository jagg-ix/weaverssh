package terminalsession

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"weaverssh/containerstream"
)

type spawnerTestProvider struct {
	process *spawnerTestProcess
	spec    containerstream.ProcessSpec
}

func (*spawnerTestProvider) Name() string { return "terminable" }
func (*spawnerTestProvider) OpenContainerStream(context.Context, containerstream.Request) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (p *spawnerTestProvider) StartContainerProcess(_ context.Context, _ containerstream.Request, spec containerstream.ProcessSpec) (containerstream.Process, error) {
	p.spec = spec
	return p.process, nil
}

type spawnerTestWriteCloser struct{ bytes.Buffer }

func (*spawnerTestWriteCloser) Close() error { return nil }

type spawnerTestProcess struct {
	capabilities containerstream.ProcessCapabilities
	stdin        *spawnerTestWriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
	mu           sync.Mutex
	closed       bool
}

func newSpawnerTestProcess(capabilities containerstream.ProcessCapabilities) *spawnerTestProcess {
	return &spawnerTestProcess{
		capabilities: capabilities,
		stdin:        &spawnerTestWriteCloser{},
		stdout:       io.NopCloser(strings.NewReader("output")),
		stderr:       io.NopCloser(strings.NewReader("")),
	}
}

func (*spawnerTestProcess) ProviderName() string { return "terminable" }
func (p *spawnerTestProcess) Capabilities() containerstream.ProcessCapabilities {
	return p.capabilities
}
func (p *spawnerTestProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *spawnerTestProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *spawnerTestProcess) Stderr() io.ReadCloser { return p.stderr }
func (*spawnerTestProcess) Wait() containerstream.ProcessResult {
	return containerstream.ProcessResult{ExitCode: 0}
}
func (*spawnerTestProcess) Signal(context.Context, containerstream.ProcessSignal) error {
	return containerstream.ErrControlUnsupported
}
func (*spawnerTestProcess) Resize(context.Context, containerstream.TerminalSize) error {
	return nil
}
func (p *spawnerTestProcess) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}
func (p *spawnerTestProcess) wasClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func newSpawnerTestRouter(t *testing.T, process *spawnerTestProcess) (*containerstream.Router, *spawnerTestProvider) {
	t.Helper()
	provider := &spawnerTestProvider{process: process}
	registry := containerstream.NewRegistry()
	registry.MustRegister(provider)
	router, err := containerstream.NewRouter(registry, containerstream.Discoverer{}, containerstream.RouterConfig{Provider: provider.Name()})
	if err != nil {
		t.Fatal(err)
	}
	return router, provider
}

func TestContainerSpawnerRequiresExactProcessTermination(t *testing.T) {
	capabilities := containerstream.ProcessCapabilities{Stdin: true, Stdout: true, TTY: true, Resize: true}
	process := newSpawnerTestProcess(capabilities)
	router, _ := newSpawnerTestRouter(t, process)

	terminal, err := (ContainerSpawner{Router: router}).Spawn(context.Background(), containerstream.Request{
		ProviderHint: "terminable",
		TargetID:     "container-a",
		FilePath:     "/proc/exec",
	}, containerstream.ProcessSpec{Argv: []string{"/bin/sh"}})
	if terminal != nil || err == nil || !strings.Contains(err.Error(), "exact-process termination") {
		t.Fatalf("terminal=%v err=%v", terminal, err)
	}
	if !process.wasClosed() {
		t.Fatal("rejected process was not closed")
	}
}

func TestContainerSpawnerAcceptsTerminablePTY(t *testing.T) {
	capabilities := containerstream.ProcessCapabilities{Stdin: true, Stdout: true, TTY: true, Resize: true, Terminate: true}
	process := newSpawnerTestProcess(capabilities)
	router, provider := newSpawnerTestRouter(t, process)

	terminal, err := (ContainerSpawner{Router: router}).Spawn(context.Background(), containerstream.Request{
		ProviderHint: "terminable",
		TargetID:     "container-a",
		FilePath:     "/proc/exec",
	}, containerstream.ProcessSpec{Argv: []string{"/bin/sh"}})
	if err != nil {
		t.Fatal(err)
	}
	if terminal == nil || !provider.spec.TTY {
		t.Fatalf("terminal=%v tty=%v", terminal, provider.spec.TTY)
	}
	if _, err := terminal.WriteInput([]byte("input")); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Resize(context.Background(), TerminalSize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
