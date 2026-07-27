package sessionruntime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"weaverssh/sessionmux"
	"weaverssh/tunnel"

	"github.com/gorilla/websocket"
)

func TestSessionRuntimeOverNegotiatedWebSocket(t *testing.T) {
	serverResult := make(chan error, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{tunnel.SessionSubprotocol},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverResult <- err
			return
		}
		session, err := AcceptWebSocket(ws, Config{Binding: "bound-to-authenticated-x11-session"})
		if err != nil {
			serverResult <- err
			return
		}
		defer session.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := session.Mux.Accept(ctx)
		if err != nil {
			serverResult <- err
			return
		}
		defer stream.Close()
		buf := make([]byte, len("session-data"))
		if _, err := io.ReadFull(stream, buf); err != nil {
			serverResult <- err
			return
		}
		_, err = stream.Write(append([]byte("echo:"), buf...))
		serverResult <- err
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{Subprotocols: []string{tunnel.SessionSubprotocol}}
	ws, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ConnectWebSocket(ws, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.Binding != "bound-to-authenticated-x11-session" {
		t.Fatalf("binding=%q", client.Binding)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Mux.Open(ctx, sessionmux.ServiceEvents, []byte("runtime-test"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("session-data")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("echo:session-data"))
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo:session-data" {
		t.Fatalf("response=%q", response)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestConnectRejectsMissingSessionSubprotocol(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			defer ws.Close()
			_ = ws.WriteJSON(Hello{Protocol: ProtocolVersion, Binding: "binding"})
		}
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ConnectWebSocket(ws, Config{}); err == nil {
		t.Fatal("ConnectWebSocket accepted a WebSocket without the session subprotocol")
	}
}
