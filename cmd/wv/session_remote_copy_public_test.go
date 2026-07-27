package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicRemoteCopySupportsNamespaceAndArgumentTerminator(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	payload := bytes.Repeat([]byte("public-remote-copy\n"), 10000)
	if err := os.WriteFile(filepath.Join(sourceRoot, "input.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdFileVerbWithAliases("cp", []string{
		"--",
		"node:source-node:/input.bin",
		"node:destination-node:/output.bin",
	}); code != 0 {
		t.Fatalf("wv cp code=%d", code)
	}
	copied, err := os.ReadFile(filepath.Join(destinationRoot, "output.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, payload) {
		t.Fatalf("copied bytes=%d want=%d", len(copied), len(payload))
	}
}
