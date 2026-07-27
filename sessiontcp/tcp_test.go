package sessiontcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestAllowlistIsDenyByDefaultAndMatchesExplicitRules(t *testing.T) {
	empty, err := ParseAllowlist("")
	if err != nil {
		t.Fatal(err)
	}
	req, err := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: "tcp", Address: "service.internal:443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.Authorize(req); !errors.Is(err, ErrDenied) {
		t.Fatalf("empty allowlist error=%v", err)
	}
	allow, err := ParseAllowlist("service.internal:443,127.0.0.1:*,*.corp.internal:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := allow.Authorize(req); err != nil {
		t.Fatalf("exact rule: %v", err)
	}
	loopback, _ := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: "tcp", Address: "127.0.0.1:8080"})
	if err := allow.Authorize(loopback); err != nil {
		t.Fatalf("host wildcard port: %v", err)
	}
	subdomain, _ := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: "tcp", Address: "api.corp.internal:443"})
	if err := allow.Authorize(subdomain); err != nil {
		t.Fatalf("suffix wildcard: %v", err)
	}
	apex, _ := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: "tcp", Address: "corp.internal:443"})
	if err := allow.Authorize(apex); !errors.Is(err, ErrDenied) {
		t.Fatalf("suffix wildcard unexpectedly matched apex: %v", err)
	}
	if err := allow.Authorize(Request{Protocol: ProtocolVersion, Network: "tcp", Address: "other.internal:443"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unexpected rule match: %v", err)
	}
}

func TestServerReportsDialSuccessBeforeRawRelay(t *testing.T) {
	allow, err := ParseAllowlist("service.internal:443")
	if err != nil {
		t.Fatal(err)
	}
	clientStream, serverStream := net.Pipe()
	targetServer, targetClient := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metadata, err := EncodeRequest("tcp", "service.internal:443")
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan string, 1)
	server := &Server{
		Authorize: allow.Authorize,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed <- "service.internal:443"
			return targetClient, nil
		},
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(ctx, serverStream, metadata) }()
	go func() {
		defer targetServer.Close()
		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(targetServer, buf); err == nil {
			_, _ = targetServer.Write(append([]byte("echo:"), buf...))
		}
	}()
	if err := readResult(clientStream); err != nil {
		t.Fatal(err)
	}
	if got := <-dialed; got != "service.internal:443" {
		t.Fatalf("dialed=%q", got)
	}
	if _, err := clientStream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(clientStream, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo:ping" {
		t.Fatalf("response=%q", response)
	}
	_ = clientStream.Close()
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not exit")
	}
}

func TestServerRejectsDestinationBeforeDial(t *testing.T) {
	clientStream, serverStream := net.Pipe()
	metadata, err := EncodeRequest("tcp", "blocked.internal:80")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	server := &Server{
		Authorize: Allowlist{}.Authorize,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("must not dial")
		},
	}
	go func() { _ = server.Serve(context.Background(), serverStream, metadata) }()
	if err := readResult(clientStream); err == nil {
		t.Fatal("denied destination reported success")
	}
	if called {
		t.Fatal("dialer was called for denied destination")
	}
	_ = clientStream.Close()
}

func TestServerRejectsMissingAuthorizationPolicy(t *testing.T) {
	clientStream, serverStream := net.Pipe()
	metadata, err := EncodeRequest("tcp", "service.internal:443")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	server := &Server{DialContext: func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not dial")
	}}
	go func() { _ = server.Serve(context.Background(), serverStream, metadata) }()
	if err := readResult(clientStream); err == nil {
		t.Fatal("missing policy reported success")
	}
	if called {
		t.Fatal("dialer was called without an authorization policy")
	}
	_ = clientStream.Close()
}
