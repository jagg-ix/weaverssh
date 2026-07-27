package app

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type fakeRelaySession struct {
	writes    [][]byte
	writeErr  error
	closed    bool
	readErr   error
	readQueue [][]byte
}

func (s *fakeRelaySession) ReadMessage() (int, []byte, error) {
	if len(s.readQueue) == 0 {
		if s.readErr != nil {
			return 0, nil, s.readErr
		}
		return 0, nil, errors.New("no read queued")
	}
	msg := append([]byte(nil), s.readQueue[0]...)
	s.readQueue = s.readQueue[1:]
	return websocket.BinaryMessage, msg, nil
}

func (s *fakeRelaySession) WriteMessage(messageType int, data []byte) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.writes = append(s.writes, append([]byte(nil), data...))
	return nil
}

func (s *fakeRelaySession) Close() error {
	s.closed = true
	return nil
}

func TestRecoverBufferedWebSocketSessionDrainsBeforeRecovered(t *testing.T) {
	old := &fakeRelaySession{}
	next := &fakeRelaySession{}
	var attempts int
	_, decision := recoverBufferedWebSocketSession(
		old,
		drainReconnectPolicy{
			MaxReconnects:  2,
			InitialBackoff: time.Millisecond,
			Sleep:          func(time.Duration) {},
			Authenticated:  func() bool { return true },
		},
		func() (websocketRelaySession, error) {
			attempts++
			return next, nil
		},
		[][]byte{[]byte("alpha"), []byte("beta")},
	)

	if !old.closed {
		t.Fatal("old session was not closed before reconnect")
	}
	if attempts != 1 || decision.Attempts != 1 {
		t.Fatalf("attempts got reconnect=%d decision=%d want 1", attempts, decision.Attempts)
	}
	if decision.Outcome != drainReconnectRecovered {
		t.Fatalf("outcome=%s want %s", decision.Outcome, drainReconnectRecovered)
	}
	if decision.Accepted != 9 || decision.Delivered != 9 || decision.Buffered != 0 {
		t.Fatalf("custody accepted=%d delivered=%d buffered=%d want 9/9/0", decision.Accepted, decision.Delivered, decision.Buffered)
	}
	if !reflect.DeepEqual(next.writes, [][]byte{[]byte("alpha"), []byte("beta")}) {
		t.Fatalf("writes=%q want alpha,beta", next.writes)
	}
	assertAuditOrder(t, decision.Audit, "drainComplete", "reconnectSucceeded")
}

func TestRecoverBufferedWebSocketSessionFailsClosedAfterBoundedAttempts(t *testing.T) {
	var attempts int
	_, decision := recoverBufferedWebSocketSession(
		&fakeRelaySession{},
		drainReconnectPolicy{
			MaxReconnects:  2,
			InitialBackoff: time.Millisecond,
			Sleep:          func(time.Duration) {},
			Authenticated:  func() bool { return true },
		},
		func() (websocketRelaySession, error) {
			attempts++
			return nil, errors.New("transport still down")
		},
		[][]byte{[]byte("pending")},
	)

	if attempts != 2 || decision.Attempts != 2 {
		t.Fatalf("attempts got reconnect=%d decision=%d want 2", attempts, decision.Attempts)
	}
	if decision.Outcome != drainReconnectFailClosed {
		t.Fatalf("outcome=%s want %s", decision.Outcome, drainReconnectFailClosed)
	}
	if decision.Delivered != 0 || decision.Buffered != int64(len("pending")) {
		t.Fatalf("custody delivered=%d buffered=%d want 0/%d", decision.Delivered, decision.Buffered, len("pending"))
	}
	assertAuditOrder(t, decision.Audit, "drainComplete", "failClosed")
}

func TestRecoverBufferedWebSocketSessionBlocksUnauthenticatedReconnect(t *testing.T) {
	var attempts int
	_, decision := recoverBufferedWebSocketSession(
		&fakeRelaySession{},
		drainReconnectPolicy{
			MaxReconnects: 1,
			Sleep:         func(time.Duration) {},
			Authenticated: func() bool { return false },
		},
		func() (websocketRelaySession, error) {
			attempts++
			return &fakeRelaySession{}, nil
		},
		[][]byte{[]byte("pending")},
	)

	if attempts != 0 {
		t.Fatalf("unauthenticated reconnect attempted %d times", attempts)
	}
	if decision.Outcome != drainReconnectFailClosed {
		t.Fatalf("outcome=%s want failClosed", decision.Outcome)
	}
	assertAuditOrder(t, decision.Audit, "authRevoked", "failClosed")
}

func assertAuditOrder(t *testing.T, audit []string, before string, after string) {
	t.Helper()
	beforeIdx := -1
	afterIdx := -1
	for i, event := range audit {
		if event == before && beforeIdx == -1 {
			beforeIdx = i
		}
		if event == after && afterIdx == -1 {
			afterIdx = i
		}
	}
	if beforeIdx < 0 || afterIdx < 0 || beforeIdx >= afterIdx {
		t.Fatalf("audit order %q before %q not satisfied: %v", before, after, audit)
	}
}

type scriptedReadWriter struct {
	reads  [][]byte
	writes [][]byte
	mu     sync.Mutex
	closed bool
}

func (rw *scriptedReadWriter) Read(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.closed {
		return 0, io.EOF
	}
	if len(rw.reads) == 0 {
		return 0, io.EOF
	}
	n := copy(p, rw.reads[0])
	rw.reads = rw.reads[1:]
	return n, nil
}

func (rw *scriptedReadWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.closed {
		return 0, io.ErrClosedPipe
	}
	rw.writes = append(rw.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (rw *scriptedReadWriter) Close() error {
	rw.mu.Lock()
	rw.closed = true
	rw.mu.Unlock()
	return nil
}

type blockingRelaySession struct {
	mu       sync.Mutex
	writes   [][]byte
	writeErr error
	closed   chan struct{}
	once     sync.Once
}

func newBlockingRelaySession(writeErr error) *blockingRelaySession {
	return &blockingRelaySession{writeErr: writeErr, closed: make(chan struct{})}
}

func (s *blockingRelaySession) ReadMessage() (int, []byte, error) {
	<-s.closed
	return 0, nil, io.EOF
}

func (s *blockingRelaySession) WriteMessage(messageType int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.writes = append(s.writes, append([]byte(nil), data...))
	return nil
}

func (s *blockingRelaySession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *blockingRelaySession) writtenPayloads() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.writes))
	for i := range s.writes {
		out[i] = append([]byte(nil), s.writes[i]...)
	}
	return out
}

func TestRelayWebSocketReconnectsAndDrainsBufferedClientPayload(t *testing.T) {
	handler := &SOCKSHandler{relayStats: map[string]*RelayStats{}}
	stats := &RelayStats{StartTime: time.Now(), LastActivity: time.Now(), State: "RELAYING"}
	src := &scriptedReadWriter{reads: [][]byte{[]byte("hello")}}
	initial := newBlockingRelaySession(errors.New("simulated websocket drop"))
	reconnected := newBlockingRelaySession(nil)
	var reconnects int

	err := handler.relayWebSocket(src, initial, func() (websocketRelaySession, error) {
		reconnects++
		return reconnected, nil
	}, stats, "r5-websocket")
	if err != nil {
		t.Fatalf("relayWebSocket returned error: %v", err)
	}
	if reconnects != 1 {
		t.Fatalf("reconnects=%d want 1", reconnects)
	}
	if !reflect.DeepEqual(reconnected.writtenPayloads(), [][]byte{[]byte("hello")}) {
		t.Fatalf("reconnected writes=%q want hello", reconnected.writtenPayloads())
	}
	sent, received, state := stats.getStats()
	if sent != int64(len("hello")) || received != 0 || state != "CLOSED" {
		t.Fatalf("stats sent=%d received=%d state=%s want %d/0/CLOSED", sent, received, state, len("hello"))
	}
}

func TestDirectRelayClosesPeerOnHalfClose(t *testing.T) {
	handler := &SOCKSHandler{relayStats: map[string]*RelayStats{}}
	stats := &RelayStats{StartTime: time.Now(), LastActivity: time.Now(), State: "RELAYING"}
	clientRelaySide, clientPeer := net.Pipe()
	targetRelaySide, targetPeer := net.Pipe()
	defer clientPeer.Close()
	defer targetPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- handler.relay(clientRelaySide, targetRelaySide, stats, "r5-direct", "DIRECT")
	}()

	if _, err := clientPeer.Write([]byte("ping")); err != nil {
		t.Fatalf("write client payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(targetPeer, buf); err != nil {
		t.Fatalf("read target payload: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("target payload=%q want ping", buf)
	}
	_ = clientPeer.Close()
	_ = targetPeer.Close()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("relay returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct relay did not exit after half-close")
	}
}
