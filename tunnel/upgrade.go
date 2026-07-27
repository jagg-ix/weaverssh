package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"weaverssh/flowcontrol"

	"github.com/gorilla/websocket"
)

// SessionSubprotocol selects the portless, flow-controlled logical-session
// runtime after the SSH X11 authentication bootstrap has upgraded to WebSocket.
const SessionSubprotocol = "weaverssh.session.v2"

// ClientUpgrade upgrades an already-open TCP connection to WebSocket by
// using a custom Dialer that reuses the existing connection.
func ClientUpgrade(conn net.Conn) (*websocket.Conn, error) {
	return ClientUpgradeWithProfile(conn, flowcontrol.DefaultProfile())
}

// ClientUpgradeWithProfile upgrades an already-open TCP connection to
// WebSocket using explicit cross-layer buffer sizes. It preserves the legacy
// X11 relay behavior by requesting no WebSocket subprotocol.
func ClientUpgradeWithProfile(conn net.Conn, profile flowcontrol.Profile) (*websocket.Conn, error) {
	return clientUpgradeWithProfile(conn, profile, "/_x11ws", "")
}

// ClientUpgradeSession upgrades an already-open, X11-authenticated connection
// into the dynamic logical-session WebSocket subprotocol.
func ClientUpgradeSession(conn net.Conn) (*websocket.Conn, error) {
	return ClientUpgradeSessionWithProfile(conn, flowcontrol.DefaultProfile())
}

// ClientUpgradeSessionWithProfile is the profiled dynamic-session variant.
// The caller must already have completed the X11 setup/authentication exchange
// on conn; this function never dials another endpoint or allocates a port.
func ClientUpgradeSessionWithProfile(conn net.Conn, profile flowcontrol.Profile) (*websocket.Conn, error) {
	return clientUpgradeWithProfile(conn, profile, "/_session", SessionSubprotocol)
}

func clientUpgradeWithProfile(conn net.Conn, profile flowcontrol.Profile, path, subprotocol string) (*websocket.Conn, error) {
	used := false
	profile = profile.Normalized()
	if err := flowcontrol.ApplySocketOptions(conn, profile); err != nil {
		log.Printf("WebSocket upgrade socket option warning: %v", err)
	}
	d := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if used {
				// The Dialer should only call this once per Dial.
				return nil, errors.New("connection already used")
			}
			used = true
			return conn, nil
		},
		// No proxy: we upgrade in place over the already-established,
		// X11-authenticated connection (NetDialContext returns it directly).
		// http.ProxyFromEnvironment would make gorilla emit a stray HTTP
		// CONNECT over that conn when HTTP(S)_PROXY is set, corrupting the
		// stream, so it must be nil here.
		Proxy:             nil,
		EnableCompression: profile.WebSocketCompression,
		WriteBufferSize:   profile.WebSocketWriteBufferBytes,
		ReadBufferSize:    profile.WebSocketReadBufferBytes,
	}
	if subprotocol != "" {
		d.Subprotocols = []string{subprotocol}
	}

	// URL/Host are placeholders; the server-side upgrader accepts regardless.
	u := url.URL{Scheme: "ws", Host: "weaverssh", Path: path}
	ws, _, err := d.DialContext(context.Background(), u.String(), http.Header{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %w", err)
	}
	if subprotocol != "" && ws.Subprotocol() != subprotocol {
		_ = ws.Close()
		return nil, fmt.Errorf("websocket subprotocol mismatch: requested %q got %q", subprotocol, ws.Subprotocol())
	}
	return ws, nil
}

// ConfigureX11Handlers sets the X11 connection manager and security extension.
func ConfigureX11Handlers(connManager interface{}, securityExt interface{}) {
	if connManager != nil {
		log.Printf("Using connection manager for X11 connections")
	}

	if securityExt != nil {
		log.Printf("Using security extension for X11 authentication")
	}
}
