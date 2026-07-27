package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteCopyFailureLeavesFinalUnchangedAndRemovesTemp(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()
	if err := os.WriteFile(filepath.Join(sourceRoot, "source.bin"), bytes.Repeat([]byte("source"), 10000), 0o644); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(destinationRoot, "final.bin")
	if err := os.WriteFile(finalPath, []byte("old-final-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}

	originalCopy := remoteCopyStream
	remoteCopyStream = func(dst io.Writer, src io.Reader, buffer []byte) (int64, error) {
		payload := make([]byte, 4096)
		n, readErr := src.Read(payload)
		if n > 0 {
			if _, writeErr := dst.Write(payload[:n]); writeErr != nil {
				return int64(n), writeErr
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return int64(n), readErr
		}
		return int64(n), errors.New("injected transfer failure")
	}
	defer func() { remoteCopyStream = originalCopy }()

	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/source.bin",
		"destination-node:/final.bin",
	}, &stderr)
	if !handled || code != 1 || !strings.Contains(stderr.String(), "injected transfer failure") {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	afterPayload, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterPayload) != "old-final-content" {
		t.Fatalf("final changed after failure: %q", afterPayload)
	}
	after, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode changed from %o to %o", before.Mode().Perm(), after.Mode().Perm())
	}
	entries, err := os.ReadDir(destinationRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wv-replace-") {
			t.Fatalf("temporary file leaked: %s", entry.Name())
		}
	}
}

func TestRemoteCopySuccessLeavesNoReplacementTemp(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()
	if err := os.WriteFile(filepath.Join(sourceRoot, "source.bin"), []byte("complete"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/source.bin",
		"destination-node:/final.bin",
	}, &stderr)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	entries, err := os.ReadDir(destinationRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wv-replace-") {
			t.Fatalf("temporary file leaked: %s", entry.Name())
		}
	}
}
