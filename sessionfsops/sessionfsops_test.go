package sessionfsops

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPrepareCommitPreservesFinalUntilRenameAndKeepsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows os.Rename does not replace an existing destination atomically")
	}
	root := t.TempDir()
	final := filepath.Join(root, "final.bin")
	if err := os.WriteFile(final, []byte("old-complete-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	prepared := callServer(t, server, Request{
		Operation: OperationPrepareReplace,
		FinalPath: "final.bin",
		Mode: 0o644,
		PreserveExistingMode: true,
	})
	if prepared.TempPath == "" || prepared.AppliedMode != 0o600 || !prepared.ReplacedExisting {
		t.Fatalf("prepared=%+v", prepared)
	}
	before, err := os.ReadFile(final)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != "old-complete-content" {
		t.Fatalf("final changed before commit: %q", before)
	}
	temp := filepath.Join(root, filepath.FromSlash(prepared.TempPath))
	if err := os.WriteFile(temp, []byte("new-complete-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	callServer(t, server, Request{
		Operation: OperationCommitReplace,
		TempPath: prepared.TempPath,
		FinalPath: "final.bin",
	})
	after, err := os.ReadFile(final)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "new-complete-content" {
		t.Fatalf("final=%q", after)
	}
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temporary still exists: %v", err)
	}
}

func TestAbortRemovesPreparedTemporaryAndLeavesFinal(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "final.txt")
	if err := os.WriteFile(final, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	prepared := callServer(t, server, Request{Operation: OperationPrepareReplace, FinalPath: "final.txt", Mode: 0o644})
	callServer(t, server, Request{Operation: OperationAbortReplace, TempPath: prepared.TempPath})
	payload, err := os.ReadFile(final)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "stable" {
		t.Fatalf("final=%q", payload)
	}
	if _, err := os.Stat(filepath.Join(root, prepared.TempPath)); !os.IsNotExist(err) {
		t.Fatalf("temporary still exists: %v", err)
	}
}

func TestPrepareUsesRequestedModeForNewDestination(t *testing.T) {
	root := t.TempDir()
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	prepared := callServer(t, server, Request{
		Operation: OperationPrepareReplace,
		FinalPath: "new.bin",
		Mode: 0o640,
		PreserveExistingMode: true,
	})
	if prepared.AppliedMode != 0o640 || prepared.ReplacedExisting {
		t.Fatalf("prepared=%+v", prepared)
	}
	info, err := os.Stat(filepath.Join(root, prepared.TempPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%o want 640", info.Mode().Perm())
	}
}

func TestReadOnlyAndPathPolicyRejectMutations(t *testing.T) {
	root := t.TempDir()
	readOnly, err := NewServer(ServerConfig{Root: root, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	response := callServerResponse(t, readOnly, Request{Operation: OperationPrepareReplace, FinalPath: "file"})
	if response.Error == nil || response.Error.Code != "read_only" {
		t.Fatalf("response=%+v", response)
	}

	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"../escape", "/", "dir\\file", ""} {
		response = callServerResponse(t, server, Request{Operation: OperationPrepareReplace, FinalPath: invalid})
		if response.Error == nil {
			t.Fatalf("path %q unexpectedly accepted", invalid)
		}
	}
}

func TestCommitRequiresServerTemporaryInSameDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	prepared := callServer(t, server, Request{Operation: OperationPrepareReplace, FinalPath: "a/final", Mode: 0o644})
	response := callServerResponse(t, server, Request{
		Operation: OperationCommitReplace,
		TempPath: prepared.TempPath,
		FinalPath: "b/final",
	})
	if response.Error == nil || !strings.Contains(response.Error.Message, "share one directory") {
		t.Fatalf("response=%+v", response)
	}
	response = callServerResponse(t, server, Request{
		Operation: OperationCommitReplace,
		TempPath: "a/not-owned",
		FinalPath: "a/final",
	})
	if response.Error == nil {
		t.Fatalf("unowned temporary accepted: %+v", response)
	}
}

func callServer(t *testing.T, server *Server, request Request) Result {
	t.Helper()
	response := callServerResponse(t, server, request)
	if response.Error != nil {
		t.Fatalf("operation error: %+v", response.Error)
	}
	return response.Result
}

func callServerResponse(t *testing.T, server *Server, request Request) Response {
	t.Helper()
	client, service := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, service) }()
	request.Protocol = ProtocolVersion
	request.ID = "test-request"
	if err := writeRequest(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := readResponseRaw(client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
	return response
}

func readResponseRaw(reader net.Conn) (Response, error) {
	payload, err := readMessage(reader)
	if err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.Unmarshal(payload, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}
