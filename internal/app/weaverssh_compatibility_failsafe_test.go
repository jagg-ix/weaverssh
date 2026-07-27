package app

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"weaverssh/tunnel"
)

func TestCompatibilityFailsafeRetriesThenQuarantines(t *testing.T) {
	client := &ClientConnection{authenticated: true}
	var attempts int
	var sleeps []time.Duration

	_, decision := upgradeToWebSocketWithFailsafe(
		client,
		CompatibilityFailsafePolicy{
			MaxUpgradeAttempts: 2,
			InitialBackoff:     10 * time.Millisecond,
			MaxBackoff:         50 * time.Millisecond,
			Sleep: func(d time.Duration) {
				sleeps = append(sleeps, d)
			},
		},
		func(net.Conn) (*websocket.Conn, error) {
			attempts++
			return nil, errors.New("malformed upgrade")
		},
	)

	if decision.Action != CompatibilityQuarantinePeer {
		t.Fatalf("action=%s want %s", decision.Action, CompatibilityQuarantinePeer)
	}
	if attempts != 2 || decision.Attempts != 2 {
		t.Fatalf("attempts got upgrade=%d decision=%d want 2", attempts, decision.Attempts)
	}
	if len(sleeps) != 1 || sleeps[0] != 10*time.Millisecond {
		t.Fatalf("sleeps=%v want [10ms]", sleeps)
	}
	if decision.Err == nil {
		t.Fatal("expected terminal error")
	}
}

func TestCompatibilityFailsafeSucceedsAfterRetry(t *testing.T) {
	client := &ClientConnection{authenticated: true}
	var attempts int

	_, decision := upgradeToWebSocketWithFailsafe(
		client,
		CompatibilityFailsafePolicy{
			MaxUpgradeAttempts: 3,
			InitialBackoff:     time.Millisecond,
			Sleep:              func(time.Duration) {},
		},
		func(net.Conn) (*websocket.Conn, error) {
			attempts++
			if attempts < 2 {
				return nil, errors.New("temporary upgrade mismatch")
			}
			return &websocket.Conn{}, nil
		},
	)

	if decision.Action != CompatibilityRecovered {
		t.Fatalf("action=%s want %s", decision.Action, CompatibilityRecovered)
	}
	if attempts != 2 || decision.Attempts != 2 {
		t.Fatalf("attempts got upgrade=%d decision=%d want 2", attempts, decision.Attempts)
	}
	if decision.Err != nil {
		t.Fatalf("unexpected err: %v", decision.Err)
	}
}

func TestCompatibilityFailsafeAllowsAuthenticatedRawX11Fallback(t *testing.T) {
	client := &ClientConnection{authenticated: true}

	_, decision := upgradeToWebSocketWithFailsafe(
		client,
		CompatibilityFailsafePolicy{
			MaxUpgradeAttempts:  1,
			AllowRawX11Fallback: true,
			Sleep:               func(time.Duration) {},
		},
		func(net.Conn) (*websocket.Conn, error) {
			return nil, errors.New("non-standard OpenSSH channel behavior")
		},
	)

	if decision.Action != CompatibilityFallbackRawX11 {
		t.Fatalf("action=%s want %s", decision.Action, CompatibilityFallbackRawX11)
	}
	if !decision.Authenticated {
		t.Fatal("fallback must preserve authenticated state")
	}
}

func TestCompatibilityFailsafeBlocksUnauthenticatedFallback(t *testing.T) {
	client := &ClientConnection{authenticated: false}
	decision := authenticatedRawX11FallbackDecision(client)

	if decision.Action != CompatibilityQuarantinePeer {
		t.Fatalf("action=%s want %s", decision.Action, CompatibilityQuarantinePeer)
	}
	if decision.Err == nil {
		t.Fatal("expected unauthenticated fallback error")
	}
}

func TestCompatibilityFailsafeFailsClosedOnStalledWebSocketUpgrade(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	result := make(chan CompatibilityDecision, 1)
	go func() {
		client := &ClientConnection{conn: serverConn, authenticated: true}
		_, decision := upgradeToWebSocketWithFailsafe(
			client,
			CompatibilityFailsafePolicy{
				MaxUpgradeAttempts: 1,
				AttemptTimeout:     20 * time.Millisecond,
				Sleep:              func(time.Duration) {},
			},
			upgradeToWebSocket,
		)
		result <- decision
	}()

	if _, err := clientConn.Write([]byte("GET ")); err != nil {
		t.Fatalf("write partial upgrade request: %v", err)
	}

	select {
	case decision := <-result:
		if decision.Action != CompatibilityQuarantinePeer {
			t.Fatalf("action=%s want %s", decision.Action, CompatibilityQuarantinePeer)
		}
		if decision.Err == nil {
			t.Fatal("expected timeout/fail-closed error")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled upgrade did not resolve to fail-closed")
	}
}

func TestRawWebSocketUpgradeInteroperatesWithTunnelClientUpgrade(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	type serverResult struct {
		msgType int
		payload string
		err     error
	}
	results := make(chan serverResult, 1)

	go func() {
		ws, err := upgradeToWebSocket(serverConn)
		if err != nil {
			results <- serverResult{err: err}
			return
		}
		defer ws.Close()

		msgType, payload, err := ws.ReadMessage()
		results <- serverResult{msgType: msgType, payload: string(payload), err: err}
	}()

	clientWS, err := tunnel.ClientUpgrade(clientConn)
	if err != nil {
		t.Fatalf("client upgrade failed: %v", err)
	}
	defer clientWS.Close()

	if err := clientWS.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}

	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("server websocket result error: %v", result.err)
		}
		if result.msgType != websocket.TextMessage || result.payload != "hello" {
			t.Fatalf("server got msgType=%d payload=%q, want text hello", result.msgType, result.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server websocket result")
	}
}
