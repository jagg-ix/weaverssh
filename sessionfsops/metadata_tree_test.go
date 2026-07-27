package sessionfsops

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func callServerOverPipe(t *testing.T, server *Server, request Request) Result {
	t.Helper()
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), left) }()
	request.ID = "request-1"; request.Protocol = ProtocolVersion
	if err := writeRequest(right, request); err != nil { t.Fatal(err) }
	response, err := readResponse(right); if err != nil { t.Fatal(err) }
	_ = right.Close()
	if err := <-done; err != nil { t.Fatal(err) }
	return response.Result
}

func TestLstatAndPagedListPreserveSymlinkIdentity(t *testing.T) {
	if runtime.GOOS == "windows" { t.Skip("symlink test requires portable local symlink creation") }
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(root, "dir", "target.txt"), []byte("target"), 0o640); err != nil { t.Fatal(err) }
	if err := os.Symlink("target.txt", filepath.Join(root, "dir", "link.txt")); err != nil { t.Fatal(err) }
	server, err := NewServer(ServerConfig{Root: root}); if err != nil { t.Fatal(err) }
	metadata := callServerOverPipe(t, server, Request{Operation: OperationLstat, FinalPath: "dir/link.txt"}).Metadata
	if metadata == nil || metadata.Type != "symlink" || metadata.LinkTarget != "target.txt" { t.Fatalf("metadata=%+v", metadata) }
	first := callServerOverPipe(t, server, Request{Operation: OperationList, FinalPath: "dir", Limit: 1})
	if len(first.Entries) != 1 || first.NextCursor == "" { t.Fatalf("first page=%+v", first) }
	second := callServerOverPipe(t, server, Request{Operation: OperationList, FinalPath: "dir", Cursor: first.NextCursor, Limit: 1})
	if len(second.Entries) != 1 || second.Entries[0].Name == first.Entries[0].Name { t.Fatalf("second page=%+v", second) }
}

func TestTreePrepareCommitReplaceAndMetadata(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "tree")
	if err := os.Mkdir(final, 0o755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(final, "old.txt"), []byte("old"), 0o600); err != nil { t.Fatal(err) }
	server, err := NewServer(ServerConfig{Root: root}); if err != nil { t.Fatal(err) }
	prepared := callServerOverPipe(t, server, Request{Operation: OperationPrepareTree, FinalPath: "tree", Mode: 0o750, ReplaceExisting: true})
	if prepared.TempPath == "" { t.Fatal("missing staged tree path") }
	staged := filepath.Join(root, filepath.FromSlash(prepared.TempPath))
	if err := os.WriteFile(filepath.Join(staged, "new.txt"), []byte("new"), 0o600); err != nil { t.Fatal(err) }
	result := callServerOverPipe(t, server, Request{Operation: OperationCommitTree, TempPath: prepared.TempPath, FinalPath: "tree", ReplaceExisting: true})
	if !result.ReplacedExisting { t.Fatalf("commit result=%+v", result) }
	if _, err := os.Stat(filepath.Join(final, "old.txt")); !os.IsNotExist(err) { t.Fatalf("old tree remains: %v", err) }
	if payload, err := os.ReadFile(filepath.Join(final, "new.txt")); err != nil || string(payload) != "new" { t.Fatalf("new payload=%q err=%v", payload, err) }
	when := time.Unix(1700000000, 123)
	callServerOverPipe(t, server, Request{Operation: OperationSetMetadata, FinalPath: "tree/new.txt", Mode: 0o640, ModTimeUnixNano: when.UnixNano()})
	info, err := os.Stat(filepath.Join(final, "new.txt")); if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0o640 || info.ModTime().Unix() != when.Unix() { t.Fatalf("metadata mode=%o mtime=%s", info.Mode().Perm(), info.ModTime()) }
}

func TestAbortTreeRejectsOrdinaryDirectory(t *testing.T) {
	root := t.TempDir(); if err := os.Mkdir(filepath.Join(root, "ordinary"), 0o755); err != nil { t.Fatal(err) }
	server, err := NewServer(ServerConfig{Root: root}); if err != nil { t.Fatal(err) }
	left, right := net.Pipe(); done := make(chan error, 1); go func() { done <- server.Serve(context.Background(), left) }()
	request := Request{Protocol: ProtocolVersion, ID: "request-2", Operation: OperationAbortTree, TempPath: "ordinary"}
	if err := writeRequest(right, request); err != nil { t.Fatal(err) }
	if _, err := readResponse(right); err == nil { t.Fatal("ordinary directory abort accepted") }
	_ = right.Close(); _ = <-done
	if _, err := os.Stat(filepath.Join(root, "ordinary")); err != nil { t.Fatal("ordinary directory removed") }
}
