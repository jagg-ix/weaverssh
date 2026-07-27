package sessionfsops

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"weaverssh/filebackend"
)

func TestBackendHookVetoesPrepareReplace(t *testing.T) {
	root := t.TempDir()
	registry := filebackend.NewRegistry(nil)
	if err := registry.Register(filebackend.Hook{
		Operation: filebackend.OperationPrepareReplace,
		Phase: filebackend.PhaseBefore,
		Mode: filebackend.ModeEnforce,
		Handler: func(context.Context, filebackend.Event) error {
			return errors.New("replacement blocked")
		},
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := filebackend.NewOSService(root, false, filebackend.NewMemoryStore(), registry)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	server, err := NewServer(ServerConfig{Root: root, Backend: controller})
	if err != nil {
		t.Fatal(err)
	}
	client, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), serverSide) }()
	request := Request{Protocol: ProtocolVersion, ID: "blocked", Operation: OperationPrepareReplace, FinalPath: "final.txt", Mode: 0o600}
	if err := writeRequest(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := readResponse(client)
	if err == nil || response.Error == nil {
		t.Fatalf("response=%+v error=%v", response, err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary file created despite veto: %v", entries)
	}
}

func TestBackendCoreRecordsPrepareAndAbort(t *testing.T) {
	root := t.TempDir()
	controller, err := filebackend.NewOSService(root, false, filebackend.NewMemoryStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	server, err := NewServer(ServerConfig{Root: root, Backend: controller})
	if err != nil {
		t.Fatal(err)
	}
	result := callServerForTest(t, server, Request{Protocol: ProtocolVersion, ID: "prepare", Operation: OperationPrepareReplace, FinalPath: "final.txt", Mode: 0o600})
	if result.TempPath == "" {
		t.Fatal("missing temporary path")
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(result.TempPath))); err != nil {
		t.Fatal(err)
	}
	callServerForTest(t, server, Request{Protocol: ProtocolVersion, ID: "abort", Operation: OperationAbortReplace, TempPath: result.TempPath})
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(result.TempPath))); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains: %v", err)
	}
	snapshot := controller.Describe().Core
	if snapshot.Operations[filebackend.OperationPrepareReplace] != 1 || snapshot.Operations[filebackend.OperationAbortReplace] != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func callServerForTest(t *testing.T, server *Server, request Request) Result {
	t.Helper()
	client, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), serverSide) }()
	if err := writeRequest(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := readResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return response.Result
}
