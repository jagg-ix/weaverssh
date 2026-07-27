package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTransactionalRemoteTreeCopyPreservesMetadataAndReplacesTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink preservation test requires local symlink support")
	}
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	sourceTree := filepath.Join(sourceRoot, "tree")
	if err := os.MkdirAll(filepath.Join(sourceTree, "nested", "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("transactional-resume\n"), 10000)
	payloadPath := filepath.Join(sourceTree, "nested", "payload.bin")
	if err := os.WriteFile(payloadPath, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1700000000, 0)
	if err := os.Chtimes(payloadPath, when, when); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload.bin", filepath.Join(sourceTree, "nested", "payload.link")); err != nil {
		t.Fatal(err)
	}

	oldTree := filepath.Join(destinationRoot, "incoming", "tree")
	if err := os.MkdirAll(oldTree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldTree, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := cmdSessionCopyTransactional([]string{
		"-r", "--replace-tree",
		"source-node:/tree",
		"destination-node:/incoming/",
	}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("copy code=%d stderr=%s", code, stderr.String())
	}

	copiedPath := filepath.Join(oldTree, "nested", "payload.bin")
	copied, err := os.ReadFile(copiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, payload) {
		t.Fatalf("copied bytes=%d want=%d", len(copied), len(payload))
	}
	if _, err := os.Stat(filepath.Join(oldTree, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old tree survived replacement: %v", err)
	}
	linkTarget, err := os.Readlink(filepath.Join(oldTree, "nested", "payload.link"))
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != "payload.bin" {
		t.Fatalf("link target=%q", linkTarget)
	}
	info, err := os.Stat(copiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 || info.ModTime().Unix() != when.Unix() {
		t.Fatalf("metadata mode=%o mtime=%s", info.Mode().Perm(), info.ModTime())
	}

	entries, err := os.ReadDir(filepath.Join(destinationRoot, "incoming"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wv-tree-") {
			t.Fatalf("hidden transaction directory leaked: %s", entry.Name())
		}
	}
}

func TestTransactionalRemoteTreeCopyRejectsDescendantDestination(t *testing.T) {
	sourceRoot, _, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(sourceRoot, "tree", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cmdSessionCopyTransactional([]string{
		"-r", "--replace-tree",
		"source-node:/tree",
		"source-node:/tree/child/",
	}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "into itself") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}
