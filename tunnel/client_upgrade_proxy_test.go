package tunnel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestClientUpgradeIgnoresEnvProxy verifies that ClientUpgrade performs the
// WebSocket handshake in place over the already-established connection and does
// NOT route through an HTTP(S)_PROXY from the environment. With the previous
// Proxy: http.ProxyFromEnvironment, a set proxy made gorilla emit a stray HTTP
// CONNECT over the X11-authenticated conn, breaking the upgrade.
func TestClientUpgradeIgnoresEnvProxy(t *testing.T) {
	// A real gorilla server upgrade + echo, mirroring the production server path.
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := ws.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	// A dead proxy that must be ignored. If ClientUpgrade honored it, the
	// handshake would attempt a CONNECT here and fail.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")

	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}

	ws, err := ClientUpgrade(conn)
	if err != nil {
		t.Fatalf("ClientUpgrade failed (should ignore env proxy): %v", err)
	}
	defer ws.Close()

	want := []byte("weaverssh-ping")
	if err := ws.WriteMessage(websocket.BinaryMessage, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, got, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}
