package sessionfsops

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrepareRejectsExistingSymlinkDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires additional Windows privileges")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "final")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	response := callServerResponse(t, server, Request{Operation: OperationPrepareReplace, FinalPath: "final", Mode: 0o644})
	if response.Error == nil {
		t.Fatalf("symlink destination unexpectedly accepted: %+v", response)
	}
}

func TestCommitRejectsFinalChangedToSymlinkAfterPrepare(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires additional Windows privileges")
	}
	root := t.TempDir()
	final := filepath.Join(root, "final")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(final, []byte("old-final"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("target-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	prepared := callServer(t, server, Request{
		Operation: OperationPrepareReplace,
		FinalPath: "final",
		Mode: 0o644,
		PreserveExistingMode: true,
	})
	if err := os.WriteFile(filepath.Join(root, prepared.TempPath), []byte("new-final"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", final); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	response := callServerResponse(t, server, Request{
		Operation: OperationCommitReplace,
		TempPath: prepared.TempPath,
		FinalPath: "final",
	})
	if response.Error == nil {
		t.Fatalf("symlink race unexpectedly committed: %+v", response)
	}
	targetPayload, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetPayload) != "target-content" {
		t.Fatalf("symlink target changed: %q", targetPayload)
	}
	callServer(t, server, Request{Operation: OperationAbortReplace, TempPath: prepared.TempPath})
}
