package app

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
	"weaverssh/sessionruntime"
	"weaverssh/tunnel"
)

func TestDynamicSessionUsesX11ThenWebSocketThenMux(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network:   "tcp",
		X11Target:    "unused:0",
		AuthTimeout:  2 * time.Second,
		TrustedAuth:  true,
		Proof: authproof.RuntimeConfig{
			Mode:          authproof.ProofModeOff,
			SecurityLevel: authproof.SecurityLevelCompat,
		},
	}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	serverContext := make(chan DynamicSessionContext, 1)
	go func() {
		serverResult <- runtime.ServeDynamicSessionConn(ctx, serverConn, func(ctx context.Context, session *sessionruntime.Session, authority DynamicSessionContext) error {
			serverContext <- authority
			stream, err := session.Mux.Accept(ctx)
			if err != nil {
				return err
			}
			defer stream.Close()
			data := make([]byte, len("through-x11-session"))
			if _, err := io.ReadFull(stream, data); err != nil {
				return err
			}
			_, err = stream.Write(append([]byte("echo:"), data...))
			return err
		})
	}()

	client, err := OpenDynamicSessionConn(ctx, clientConn, DynamicSessionClientConfig{AuthCookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := client.Mux.Open(ctx, sessionmux.ServiceEvents, []byte("endpoint"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("through-x11-session")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("echo:through-x11-session"))
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo:through-x11-session" {
		t.Fatalf("response=%q", response)
	}

	authority := <-serverContext
	if !authority.X11Authenticated {
		t.Fatal("dynamic session was not bound to a successful X11 cookie match")
	}
	if authority.NegotiatedSubprotocol != tunnel.SessionSubprotocol {
		t.Fatalf("subprotocol=%q", authority.NegotiatedSubprotocol)
	}
	if strings.TrimSpace(authority.Binding) == "" || authority.Binding != client.Binding {
		t.Fatalf("server binding=%q client binding=%q", authority.Binding, client.Binding)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestDynamicSessionRejectsWrongX11CookieEvenInTrustedMode(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network:   "tcp",
		X11Target:    "unused:0",
		AuthTimeout:  time.Second,
		TrustedAuth:  true,
		Proof: authproof.RuntimeConfig{
			Mode:          authproof.ProofModeOff,
			SecurityLevel: authproof.SecurityLevelCompat,
		},
	}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- runtime.ServeDynamicSessionConn(ctx, serverConn, func(context.Context, *sessionruntime.Session, DynamicSessionContext) error {
			return nil
		})
	}()

	_, clientErr := OpenDynamicSessionConn(ctx, clientConn, DynamicSessionClientConfig{
		AuthCookie: "ffffffffffffffffffffffffffffffff",
	})
	if clientErr == nil {
		t.Fatal("wrong X11 cookie was accepted")
	}
	if serverErr := <-serverResult; serverErr == nil || !strings.Contains(serverErr.Error(), "X11 authentication failed") {
		t.Fatalf("server error=%v", serverErr)
	}
}
