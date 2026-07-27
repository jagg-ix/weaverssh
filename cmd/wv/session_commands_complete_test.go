package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompleteSessionFileCommandsRecursiveRoundTripStatAndRemove(t *testing.T) {
	remoteRoot, cleanup := startSessionFileTestBroker(t)
	defer cleanup()

	localSource := filepath.Join(t.TempDir(), "source-tree")
	if err := os.MkdirAll(filepath.Join(localSource, "nested", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("recursive-session-copy\n"), 5000)
	if err := os.WriteFile(filepath.Join(localSource, "nested", "payload.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := cmdSessionCopyComplete([]string{"-r", localSource, "origin:/uploaded"}, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("upload code=%d stderr=%s", code, stderr.String())
	}
	remotePayload, err := os.ReadFile(filepath.Join(remoteRoot, "uploaded", "nested", "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remotePayload, payload) {
		t.Fatalf("remote bytes=%d want=%d", len(remotePayload), len(payload))
	}
	if info, err := os.Stat(filepath.Join(remoteRoot, "uploaded", "nested", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory info=%v err=%v", info, err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := cmdSessionStatComplete([]string{"--json", "origin:/uploaded/nested/payload.bin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("stat code=%d stderr=%s", code, stderr.String())
	}
	var stat sessionStatResult
	if err := json.Unmarshal(stdout.Bytes(), &stat); err != nil {
		t.Fatalf("decode stat: %v output=%s", err, stdout.String())
	}
	if stat.Node != "origin" || stat.Type != "file" || stat.Size != uint64(len(payload)) {
		t.Fatalf("stat=%+v", stat)
	}

	localDestination := filepath.Join(t.TempDir(), "downloaded")
	stdout.Reset()
	stderr.Reset()
	if code := cmdSessionCopyComplete([]string{"--recursive", "origin:/uploaded", localDestination}, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("download code=%d stderr=%s", code, stderr.String())
	}
	downloaded, err := os.ReadFile(filepath.Join(localDestination, "nested", "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, payload) {
		t.Fatalf("downloaded bytes=%d want=%d", len(downloaded), len(payload))
	}

	stderr.Reset()
	if code := cmdSessionRemoveComplete([]string{"-r", "origin:/uploaded"}, false, &stderr); code != 0 {
		t.Fatalf("rm code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(remoteRoot, "uploaded")); !os.IsNotExist(err) {
		t.Fatalf("uploaded directory still exists: %v", err)
	}
}

func TestCompleteSessionCopyRequiresRecursiveAndRejectsLocalSymlink(t *testing.T) {
	_, cleanup := startSessionFileTestBroker(t)
	defer cleanup()
	localDir := filepath.Join(t.TempDir(), "directory")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdSessionCopyComplete([]string{localDir, "origin:/copy"}, bytes.NewReader(nil), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "use -r") {
		t.Fatalf("directory code=%d stderr=%s", code, stderr.String())
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(localDir, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(localDir, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	stderr.Reset()
	if code := cmdSessionCopyComplete([]string{"-r", localDir, "origin:/copy"}, bytes.NewReader(nil), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "refusing to follow local symlink") {
		t.Fatalf("symlink code=%d stderr=%s", code, stderr.String())
	}
}

func TestCompleteSessionRmdirRequiresDirectory(t *testing.T) {
	remoteRoot, cleanup := startSessionFileTestBroker(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(remoteRoot, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := cmdSessionRemoveComplete([]string{"origin:/empty"}, true, &stderr); code != 0 {
		t.Fatalf("rmdir code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(remoteRoot, "empty")); !os.IsNotExist(err) {
		t.Fatalf("empty directory still exists: %v", err)
	}
}

func TestRecursiveRemoteToRemoteCopy(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(sourceRoot, "tree", "nested", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("remote-tree\n"), 6000)
	if err := os.WriteFile(filepath.Join(sourceRoot, "tree", "nested", "payload.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destinationRoot, "receiving"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{"-r", "source-node:/tree", "destination-node:/receiving/"}, &stderr)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	copied, err := os.ReadFile(filepath.Join(destinationRoot, "receiving", "tree", "nested", "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, payload) {
		t.Fatalf("copied bytes=%d want=%d", len(copied), len(payload))
	}
	if info, err := os.Stat(filepath.Join(destinationRoot, "receiving", "tree", "nested", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory info=%v err=%v", info, err)
	}
}
