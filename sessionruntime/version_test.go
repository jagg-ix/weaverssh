package sessionruntime

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"weaverssh/tunnel"

	"github.com/gorilla/websocket"
)

func TestConnectRejectsPreFlowControlHello(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{tunnel.SessionSubprotocol},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = ws.WriteJSON(Hello{Protocol: "weaverssh.dynamic-session.v1", Binding: "legacy-binding"})
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{Subprotocols: []string{tunnel.SessionSubprotocol}}
	ws, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ConnectWebSocket(ws, Config{}); !errors.Is(err, ErrWrongProtocol) {
		t.Fatalf("ConnectWebSocket error=%v, want ErrWrongProtocol", err)
	}
}
