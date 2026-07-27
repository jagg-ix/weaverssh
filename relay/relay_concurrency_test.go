package relay

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"weaverssh/flowcontrol"

	"github.com/gorilla/websocket"
)

func TestRelayConcurrentPumpsAccountBytesAndShutdown(t *testing.T) {
	serverWS, clientWS, cleanup := websocketPair(t)
	defer cleanup()

	targetRelaySide, targetPeer := net.Pipe()
	defer targetPeer.Close()

	relay := NewRelay(serverWS)
	var sentCounter atomic.Int64
	var recvCounter atomic.Int64
	relay.SetByteCounters(
		func(n int) { sentCounter.Add(int64(n)) },
		func(n int) { recvCounter.Add(int64(n)) },
	)

	done := make(chan struct{})
	go func() {
		relay.Start(targetRelaySide)
		close(done)
	}()
	waitRelayActive(t, relay)

	wsToTarget := []byte("websocket-to-target")
	if err := clientWS.WriteMessage(websocket.BinaryMessage, wsToTarget); err != nil {
		t.Fatalf("write websocket payload: %v", err)
	}
	gotTarget := make([]byte, len(wsToTarget))
	if _, err := io.ReadFull(targetPeer, gotTarget); err != nil {
		t.Fatalf("read relayed target payload: %v", err)
	}
	if !bytes.Equal(gotTarget, wsToTarget) {
		t.Fatalf("target payload=%q want %q", gotTarget, wsToTarget)
	}

	targetToWS := []byte("target-to-websocket")
	if _, err := targetPeer.Write(targetToWS); err != nil {
		t.Fatalf("write target payload: %v", err)
	}
	messageType, gotWS, err := clientWS.ReadMessage()
	if err != nil {
		t.Fatalf("read relayed websocket payload: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("message type=%d want binary", messageType)
	}
	if !bytes.Equal(gotWS, targetToWS) {
		t.Fatalf("websocket payload=%q want %q", gotWS, targetToWS)
	}

	_ = clientWS.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	)
	waitRelayDone(t, done)

	_, _, bytesSent, bytesReceived, active := relay.GetStats()
	if active {
		t.Fatal("relay remained active after websocket close")
	}
	if bytesSent != int64(len(wsToTarget)) {
		t.Fatalf("bytesSent=%d want %d", bytesSent, len(wsToTarget))
	}
	if bytesReceived != int64(len(targetToWS)) {
		t.Fatalf("bytesReceived=%d want %d", bytesReceived, len(targetToWS))
	}
	if sentCounter.Load() != int64(len(wsToTarget)) {
		t.Fatalf("sent callback=%d want %d", sentCounter.Load(), len(wsToTarget))
	}
	if recvCounter.Load() != int64(len(targetToWS)) {
		t.Fatalf("recv callback=%d want %d", recvCounter.Load(), len(targetToWS))
	}
}

func TestRelayManagerCleanupRemovesOnlyFinishedRelays(t *testing.T) {
	manager := NewRelayManager()
	defer manager.Close()

	finished := NewRelay(nil)
	finished.mu.Lock()
	finished.hasStarted = true
	finished.isActive = false
	finished.mu.Unlock()

	pending := NewRelay(nil)
	active := NewRelay(nil)
	active.mu.Lock()
	active.hasStarted = true
	active.isActive = true
	active.bytesSent = 11
	active.bytesReceived = 7
	active.mu.Unlock()

	manager.AddRelay("finished", finished)
	manager.AddRelay("pending", pending)
	manager.AddRelay("active", active)
	manager.cleanupInactiveRelays()

	if _, ok := manager.GetRelay("finished"); ok {
		t.Fatal("finished relay was not cleaned up")
	}
	if _, ok := manager.GetRelay("pending"); !ok {
		t.Fatal("pending relay was removed before Start")
	}
	if _, ok := manager.GetRelay("active"); !ok {
		t.Fatal("active relay was removed")
	}
	if got := manager.GetActiveRelayCount(); got != 1 {
		t.Fatalf("active relay count=%d want 1", got)
	}
	sent, received := manager.GetTotalStats()
	if sent != 11 || received != 7 {
		t.Fatalf("total stats sent=%d received=%d want 11/7", sent, received)
	}
}

func TestRelayCountersCallbacksDoNotRunUnderRelayLock(t *testing.T) {
	relay := NewRelay(nil)
	sentCallback := make(chan struct{}, 1)
	recvCallback := make(chan struct{}, 1)

	relay.SetByteCounters(
		func(n int) {
			_, _, sent, _, _ := relay.GetStats()
			if sent != int64(n) {
				t.Errorf("sent stats inside callback=%d want %d", sent, n)
			}
			sentCallback <- struct{}{}
		},
		func(n int) {
			_, _, _, received, _ := relay.GetStats()
			if received != int64(n) {
				t.Errorf("received stats inside callback=%d want %d", received, n)
			}
			recvCallback <- struct{}{}
		},
	)

	relay.trackBytesSent(5)
	relay.trackBytesReceived(7)

	select {
	case <-sentCallback:
	case <-time.After(time.Second):
		t.Fatal("sent callback deadlocked under relay lock")
	}
	select {
	case <-recvCallback:
	case <-time.After(time.Second):
		t.Fatal("received callback deadlocked under relay lock")
	}
}

func TestRelayStartIsSingleUse(t *testing.T) {
	relay := NewRelay(nil)
	if !relay.beginStart() {
		t.Fatal("first beginStart should succeed")
	}
	if relay.beginStart() {
		t.Fatal("second beginStart should be rejected")
	}
	relay.markInactive()
	if relay.beginStart() {
		t.Fatal("finished relay must not be restarted")
	}
}

func websocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverConnCh := make(chan *websocket.Conn, 1)
	errCh := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		serverConnCh <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial websocket: %v", err)
	}

	select {
	case err := <-errCh:
		_ = clientConn.Close()
		server.Close()
		t.Fatalf("upgrade websocket: %v", err)
	case serverConn := <-serverConnCh:
		cleanup := func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
			server.Close()
		}
		return serverConn, clientConn, cleanup
	case <-time.After(3 * time.Second):
		_ = clientConn.Close()
		server.Close()
		t.Fatal("timed out waiting for websocket server connection")
	}
	return nil, nil, nil
}

func waitRelayActive(t *testing.T, relay *Relay) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, _, _, _, active := relay.GetStats()
		if active {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay did not become active")
}

func waitRelayDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after close")
	}
}

func TestRelayUsesFlowProfileReadChunkForWebSocketFrames(t *testing.T) {
	serverWS, clientWS, cleanup := websocketPair(t)
	defer cleanup()

	profile := flowcontrol.Profile{
		Name:                      "test",
		SSHSocketBufferBytes:      4096,
		X11PacketMaxBytes:         1024,
		WebSocketReadBufferBytes:  1024,
		WebSocketWriteBufferBytes: 1024,
		WebSocketFrameBytes:       1024,
		RelayReadBytes:            1024,
		QueueDepth:                4,
	}
	target := &profileReadSource{remaining: 2500}
	relay := NewRelayWithProfile(serverWS, profile)
	done := make(chan struct{})
	go func() {
		relay.Start(target)
		close(done)
	}()

	var frames []int
	for {
		_, payload, err := clientWS.ReadMessage()
		if err != nil {
			break
		}
		frames = append(frames, len(payload))
	}
	waitRelayDone(t, done)

	want := []int{1024, 1024, 452}
	if !reflect.DeepEqual(frames, want) {
		t.Fatalf("frames=%v want %v", frames, want)
	}
	if target.maxReadLen != profile.RelayReadBytes {
		t.Fatalf("max read len=%d want %d", target.maxReadLen, profile.RelayReadBytes)
	}
}

type profileReadSource struct {
	remaining  int
	maxReadLen int
}

func (s *profileReadSource) Read(p []byte) (int, error) {
	if len(p) > s.maxReadLen {
		s.maxReadLen = len(p)
	}
	if s.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > s.remaining {
		n = s.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = byte(i)
	}
	s.remaining -= n
	return n, nil
}

func (s *profileReadSource) Write(p []byte) (int, error) {
	return len(p), nil
}
