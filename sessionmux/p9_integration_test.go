package sessionmux_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/sessionmux"
)

func TestP9OverLogicalFSStream(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello through the dynamic session\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{
		Role: sessionmux.RoleResponder,
		AllowedServices: map[sessionmux.ServiceID]bool{
			sessionmux.ServiceFS: true,
		},
	})
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
		stream, acceptErr := right.Accept(ctx)
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		if stream.Service() != sessionmux.ServiceFS {
			serverErr <- errors.New("accepted non-filesystem stream")
			return
		}
		if string(stream.Metadata()) != "endpoint" {
			serverErr <- errors.New("filesystem stream lost target-node metadata")
			return
		}
		serverErr <- server.ServeTransport(stream)
	}()

	stream, err := left.Open(ctx, sessionmux.ServiceFS, []byte("endpoint"))
	if err != nil {
		t.Fatalf("open fs stream: %v", err)
	}
	client, err := p9client.Attach(stream)
	if err != nil {
		t.Fatalf("attach 9P client to fs stream: %v", err)
	}

	entries, err := client.List("")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello.txt" {
		t.Fatalf("unexpected root entries: %+v", entries)
	}

	data, err := client.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("read hello.txt: %v", err)
	}
	if string(data) != "hello through the dynamic session\n" {
		t.Fatalf("hello.txt=%q", data)
	}

	if err := client.WriteFile("uploaded.txt", []byte("uploaded without a static port\n")); err != nil {
		t.Fatalf("write uploaded.txt: %v", err)
	}
	uploaded, err := os.ReadFile(filepath.Join(root, "uploaded.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(uploaded) != "uploaded without a static port\n" {
		t.Fatalf("uploaded.txt=%q", uploaded)
	}

	if err := client.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("close 9P client: %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("9P server over fs stream: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("9P server did not terminate after client closed the logical stream")
	}
}
