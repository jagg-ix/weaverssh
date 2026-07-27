package sessioncontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/sessionmux"
)

func TestAuthorizedNodeCarriesP9WithoutListener(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte("registered node data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if _, err := registry.RegisterVerified(
		testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "p9-authorized-nonce"),
		[]sessionmux.ServiceID{sessionmux.ServiceFS},
	); err != nil {
		t.Fatal(err)
	}

	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	server, err := p9svc.New(p9svc.Config{Root: root, ReadOnly: false})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		target, acceptErr := AcceptTarget(ctx, right, registry, "endpoint")
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		if target.Node.ID != "endpoint" || target.Stream.Service() != sessionmux.ServiceFS {
			serverErr <- errors.New("authorized target did not resolve endpoint filesystem service")
			return
		}
		serverErr <- server.ServeTransport(target.Stream)
	}()

	stream, err := OpenTarget(ctx, left, "endpoint", sessionmux.ServiceFS, []byte("root=/"))
	if err != nil {
		t.Fatalf("open endpoint fs target: %v", err)
	}
	client, err := p9client.Attach(stream)
	if err != nil {
		t.Fatalf("attach 9P after target authorization: %v", err)
	}
	data, err := client.ReadFile("existing.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "registered node data\n" {
		t.Fatalf("existing.txt=%q", data)
	}
	if err := client.WriteFile("created.txt", []byte("no static port\n")); err != nil {
		t.Fatal(err)
	}
	created, err := os.ReadFile(filepath.Join(root, "created.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(created) != "no static port\n" {
		t.Fatalf("created.txt=%q", created)
	}
	if err := client.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("authorized 9P server did not stop after stream close")
	}
}
