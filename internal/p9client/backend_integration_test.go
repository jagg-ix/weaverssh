package p9client

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"weaverssh/filebackend"
	"weaverssh/internal/p9svc"
)

func TestP9BackendEnforceHookPreventsCreate(t *testing.T) {
	root := t.TempDir()
	registry := filebackend.NewRegistry(nil)
	if err := registry.Register(filebackend.Hook{
		Operation: filebackend.OperationCreate,
		Phase: filebackend.PhaseBefore,
		Mode: filebackend.ModeEnforce,
		Handler: func(context.Context, filebackend.Event) error {
			return errors.New("create blocked by policy")
		},
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := filebackend.NewOSService(root, false, filebackend.NewMemoryStore(), registry)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	client, done := attachBackendTestClient(t, root, controller)
	defer client.Close()

	err = client.WriteFile("blocked.txt", []byte("secret"))
	if err == nil || !strings.Contains(err.Error(), "create blocked by policy") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "blocked.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("file exists despite hook veto: %v", statErr)
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	snapshot := controller.Describe().Core
	if snapshot.Operations[filebackend.OperationCreate] != 1 || snapshot.Errors == 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestP9BackendRecordsSuccessfulWrite(t *testing.T) {
	root := t.TempDir()
	controller, err := filebackend.NewOSService(root, false, filebackend.NewMemoryStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	client, done := attachBackendTestClient(t, root, controller)
	if err := client.WriteFile("written.txt", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(root, "written.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload=%q", payload)
	}
	snapshot := controller.Describe().Core
	if snapshot.Operations[filebackend.OperationCreate] == 0 || snapshot.Operations[filebackend.OperationWrite] == 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func attachBackendTestClient(t *testing.T, root string, controller filebackend.API) (*Client, <-chan error) {
	t.Helper()
	server, err := p9svc.New(p9svc.Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := p9svc.SetBackendAPI(server, controller); err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeTransport(serverConn) }()
	client, err := attach(clientConn)
	if err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		t.Fatal(err)
	}
	return client, done
}
