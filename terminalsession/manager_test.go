package terminalsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"weaverssh/containerstream"
)

type fakeAttachment struct {
	mu     sync.Mutex
	frames []Frame
	closed bool
	fail   bool
}

type blockingAttachment struct{}

func (blockingAttachment) Send(ctx context.Context, _ Frame) error { <-ctx.Done(); return ctx.Err() }
func (blockingAttachment) Close() error                            { return nil }

func (a *fakeAttachment) Send(_ context.Context, frame Frame) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.fail {
		return io.ErrClosedPipe
	}
	copyFrame := frame
	copyFrame.Payload = append([]byte(nil), frame.Payload...)
	a.frames = append(a.frames, copyFrame)
	return nil
}
func (a *fakeAttachment) Close() error { a.mu.Lock(); a.closed = true; a.mu.Unlock(); return nil }
func (a *fakeAttachment) snapshot() []Frame {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Frame(nil), a.frames...)
}

type fakeTerminal struct {
	provider string
	reader   *io.PipeReader
	writer   *io.PipeWriter
	wait     chan containerstream.ProcessResult
	inputMu  sync.Mutex
	input    bytes.Buffer
	resizeMu sync.Mutex
	resize   []TerminalSize
	close    sync.Once
}

func newFakeTerminal() *fakeTerminal {
	reader, writer := io.Pipe()
	return &fakeTerminal{provider: "fake", reader: reader, writer: writer, wait: make(chan containerstream.ProcessResult, 1)}
}
func (t *fakeTerminal) ProviderName() string { return t.provider }
func (t *fakeTerminal) WriteInput(payload []byte) (int, error) {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	return t.input.Write(payload)
}
func (t *fakeTerminal) Output() io.ReadCloser { return t.reader }
func (t *fakeTerminal) Resize(_ context.Context, size TerminalSize) error {
	t.resizeMu.Lock()
	t.resize = append(t.resize, size)
	t.resizeMu.Unlock()
	return nil
}
func (t *fakeTerminal) Wait() containerstream.ProcessResult { return <-t.wait }
func (t *fakeTerminal) Close() error {
	t.close.Do(func() {
		_ = t.writer.Close()
		_ = t.reader.Close()
		select {
		case t.wait <- containerstream.ProcessResult{ExitCode: -1, Err: io.ErrClosedPipe}:
		default:
		}
	})
	return nil
}

type fakeSpawner struct{ terminal *fakeTerminal }

func (s fakeSpawner) Spawn(context.Context, containerstream.Request, containerstream.ProcessSpec) (Terminal, error) {
	return s.terminal, nil
}

type manualTimer struct {
	mu      sync.Mutex
	stopped bool
	call    func()
}

func (t *manualTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (t *manualTimer) fire() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	call := t.call
	t.mu.Unlock()
	call()
}

func testIdentity() Identity {
	return Identity{Principal: "alice@example.test", SourceNode: "laptop", SourceBinding: "authenticated-binding", ChainSHA256: strings.Repeat("a", 64)}
}

func testRequest() OpenRequest {
	return OpenRequest{
		Protocol: ProtocolVersion, Operation: OperationConnect,
		TargetURI: "vfs://container/node-a/pod-a/dev/tty", Action: "shell",
		Rows: 40, Cols: 120, Term: "xterm-256color",
	}
}

func testAuthorizer() Authorizer {
	return AuthorizerFuncs{
		Open: func(context.Context, Identity, OpenRequest) (Grant, error) {
			return Grant{Process: containerstream.ProcessSpec{Argv: []string{"/bin/bash"}}, DetachTTL: time.Hour, ReplayBytes: 1024}, nil
		},
		Reattach: func(context.Context, Identity, Snapshot) error { return nil },
	}
}

func openTestSession(t *testing.T, manager *Manager, attachment *fakeAttachment) (Lease, string) {
	t.Helper()
	lease, err := manager.Connect(context.Background(), testIdentity(), testRequest(), attachment)
	if err != nil {
		t.Fatal(err)
	}
	frames := attachment.snapshot()
	if len(frames) != 1 || frames[0].Type != FrameReady {
		t.Fatalf("initial frames=%+v", frames)
	}
	var ready Ready
	if err := json.Unmarshal(frames[0].Payload, &ready); err != nil {
		t.Fatal(err)
	}
	if ready.State != StateActive || ready.ResumeToken == "" || ready.Generation != 1 {
		t.Fatalf("unexpected ready: %+v", ready)
	}
	return lease, ready.ResumeToken
}

func TestDetachReattachReplaysOutput(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	first := &fakeAttachment{}
	lease, token := openTestSession(t, manager, first)
	if _, err := terminal.writer.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(first.snapshot()) == 2 })
	if err := manager.Detach(lease, "network-drop"); err != nil {
		t.Fatal(err)
	}
	if _, err := terminal.writer.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { snapshot, _ := manager.Snapshot(lease.SessionID); return snapshot.ReplayCeiling == 2 })

	second := &fakeAttachment{}
	reattach := OpenRequest{Protocol: ProtocolVersion, Operation: OperationReattach, SessionID: lease.SessionID, ResumeToken: token, AfterSequence: 1}
	newLease, err := manager.Connect(context.Background(), testIdentity(), reattach, second)
	if err != nil {
		t.Fatal(err)
	}
	if newLease.Generation != 2 {
		t.Fatalf("generation=%d want=2", newLease.Generation)
	}
	frames := second.snapshot()
	if len(frames) != 2 || frames[0].Type != FrameReady || frames[1].Type != FrameOutput || frames[1].Sequence != 2 || frames[1].Flags&FlagReplay == 0 || string(frames[1].Payload) != "two" {
		t.Fatalf("unexpected reattach frames: %+v", frames)
	}
	if snapshot, _ := manager.Snapshot(lease.SessionID); snapshot.State != StateActive {
		t.Fatalf("state=%s want ACTIVE", snapshot.State)
	}
}

func TestActiveReattachPreemptsGhostConnection(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	oldAttachment := &fakeAttachment{}
	oldLease, token := openTestSession(t, manager, oldAttachment)
	newAttachment := &fakeAttachment{}
	newLease, err := manager.Connect(context.Background(), testIdentity(), OpenRequest{
		Protocol: ProtocolVersion, Operation: OperationReattach,
		SessionID: oldLease.SessionID, ResumeToken: token,
	}, newAttachment)
	if err != nil {
		t.Fatal(err)
	}
	if !oldAttachment.closed || newLease.Generation != oldLease.Generation+1 {
		t.Fatalf("old closed=%t generation=%d", oldAttachment.closed, newLease.Generation)
	}
	if err := manager.Input(oldLease, []byte("stale")); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale input error=%v", err)
	}
	if err := manager.Detach(oldLease, "old-handler-eof"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale detach error=%v", err)
	}
	if err := manager.Terminate(oldLease, "old-handler-terminate"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale terminate error=%v", err)
	}
	if err := manager.Input(newLease, []byte("current")); err != nil {
		t.Fatal(err)
	}
	terminal.inputMu.Lock()
	gotInput := terminal.input.String()
	terminal.inputMu.Unlock()
	if gotInput != "current" {
		t.Fatalf("input=%q want=current", gotInput)
	}
}

func TestInputLimitIsReservedBeforeProviderWrite(t *testing.T) {
	terminal := newFakeTerminal()
	authorizer := AuthorizerFuncs{
		Open: func(context.Context, Identity, OpenRequest) (Grant, error) {
			return Grant{Process: containerstream.ProcessSpec{Argv: []string{"/bin/bash"}, MaxStdinBytes: 3}}, nil
		},
		Reattach: func(context.Context, Identity, Snapshot) error { return nil },
	}
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: authorizer, Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	lease, _ := openTestSession(t, manager, &fakeAttachment{})
	if err := manager.Input(lease, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Input(lease, []byte("d")); err == nil || !strings.Contains(err.Error(), "stdin limit") {
		t.Fatalf("error=%v want stdin limit", err)
	}
}

func TestTerminateAcknowledgesBeforeClosingAttachment(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	attachment := &fakeAttachment{}
	lease, _ := openTestSession(t, manager, attachment)
	if err := manager.Terminate(lease, "client-terminate"); err != nil {
		t.Fatal(err)
	}
	frames := attachment.snapshot()
	if len(frames) != 2 || frames[1].Type != FrameExit {
		t.Fatalf("frames=%+v", frames)
	}
	var exit Exit
	if err := json.Unmarshal(frames[1].Payload, &exit); err != nil {
		t.Fatal(err)
	}
	if exit.ExitCode != -1 || exit.Reason != "client-terminate" || !attachment.closed {
		t.Fatalf("exit=%+v closed=%t", exit, attachment.closed)
	}
}

func TestProcessExitFollowsFinalOutput(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	attachment := &fakeAttachment{}
	lease, _ := openTestSession(t, manager, attachment)
	terminal.wait <- containerstream.ProcessResult{ExitCode: 7}
	if _, err := terminal.writer.Write([]byte("final output")); err != nil {
		t.Fatal(err)
	}
	if err := terminal.writer.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		frames := attachment.snapshot()
		return len(frames) == 3
	})
	frames := attachment.snapshot()
	if frames[1].Type != FrameOutput || frames[2].Type != FrameExit || string(frames[1].Payload) != "final output" {
		t.Fatalf("frames=%+v", frames)
	}
	var exit Exit
	if err := json.Unmarshal(frames[2].Payload, &exit); err != nil {
		t.Fatal(err)
	}
	if exit.ExitCode != 7 || exit.Reason != "process-exited" {
		t.Fatalf("exit=%+v", exit)
	}
	waitFor(t, func() bool {
		snapshot, ok := manager.Snapshot(lease.SessionID)
		return ok && snapshot.State == StateTerminated
	})
}

func TestTTLAndReattachHaveDeterministicWinner(t *testing.T) {
	t.Run("ttl wins", func(t *testing.T) {
		terminal := newFakeTerminal()
		var timer *manualTimer
		manager, err := NewManager(context.Background(), ManagerConfig{
			Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal},
			after: func(_ time.Duration, callback func()) stoppableTimer {
				timer = &manualTimer{call: callback}
				return timer
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer manager.Close()
		lease, token := openTestSession(t, manager, &fakeAttachment{})
		if err := manager.Detach(lease, "drop"); err != nil {
			t.Fatal(err)
		}
		timer.fire()
		_, err = manager.Connect(context.Background(), testIdentity(), OpenRequest{Protocol: ProtocolVersion, Operation: OperationReattach, SessionID: lease.SessionID, ResumeToken: token}, &fakeAttachment{})
		if !errors.Is(err, ErrTerminated) {
			t.Fatalf("reattach error=%v", err)
		}
	})

	t.Run("reattach wins", func(t *testing.T) {
		terminal := newFakeTerminal()
		var timer *manualTimer
		manager, err := NewManager(context.Background(), ManagerConfig{
			Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal},
			after: func(_ time.Duration, callback func()) stoppableTimer {
				timer = &manualTimer{call: callback}
				return timer
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer manager.Close()
		lease, token := openTestSession(t, manager, &fakeAttachment{})
		if err := manager.Detach(lease, "drop"); err != nil {
			t.Fatal(err)
		}
		oldTimer := timer
		if _, err := manager.Connect(context.Background(), testIdentity(), OpenRequest{Protocol: ProtocolVersion, Operation: OperationReattach, SessionID: lease.SessionID, ResumeToken: token}, &fakeAttachment{}); err != nil {
			t.Fatal(err)
		}
		oldTimer.fire()
		if snapshot, _ := manager.Snapshot(lease.SessionID); snapshot.State != StateActive {
			t.Fatalf("state=%s want ACTIVE", snapshot.State)
		}
	})
}

func TestReattachRequiresSameAuthenticatedOwner(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	lease, token := openTestSession(t, manager, &fakeAttachment{})
	other := testIdentity()
	other.Principal = "mallory@example.test"
	_, err = manager.Connect(context.Background(), other, OpenRequest{Protocol: ProtocolVersion, Operation: OperationReattach, SessionID: lease.SessionID, ResumeToken: token}, &fakeAttachment{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error=%v", err)
	}
}

func TestInitialReadyWriteTimeoutTerminatesProvisionedPTY(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{
		Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}, SendTimeout: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	lease, err := manager.Connect(context.Background(), testIdentity(), testRequest(), blockingAttachment{})
	if !errors.Is(err, context.DeadlineExceeded) || lease != (Lease{}) {
		t.Fatalf("lease=%+v error=%v", lease, err)
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, session := range manager.sessions {
		session.mu.Lock()
		state := session.state
		session.mu.Unlock()
		if state != StateTerminated {
			t.Fatalf("state=%s want TERMINATED", state)
		}
	}
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met")
}
