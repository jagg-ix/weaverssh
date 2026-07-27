package tunnel

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"weaverssh/flowcontrol"

	"github.com/gorilla/websocket"
)

func TestWebSocketReadWriterSplitsWritesAtFlowFrameBoundary(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	framesCh := make(chan []int, 1)
	errCh := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		var frames []int
		for len(frames) < 3 {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			frames = append(frames, len(msg))
		}
		framesCh <- frames
	}))
	defer server.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer client.Close()

	profile := flowcontrol.Profile{
		Name:                      "test",
		SSHSocketBufferBytes:      64,
		X11PacketMaxBytes:         16,
		WebSocketReadBufferBytes:  5,
		WebSocketWriteBufferBytes: 5,
		WebSocketFrameBytes:       5,
		RelayReadBytes:            5,
		QueueDepth:                4,
	}
	rw := NewWebSocketReadWriterWithProfile(client, profile)
	if n, err := rw.Write([]byte("abcdefghijkl")); err != nil || n != 12 {
		t.Fatalf("Write n=%d err=%v", n, err)
	}

	select {
	case frames := <-framesCh:
		if want := []int{5, 5, 2}; !reflect.DeepEqual(frames, want) {
			t.Fatalf("frames=%v want %v", frames, want)
		}
	case err := <-errCh:
		t.Fatalf("server error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for split frames")
	}
}
