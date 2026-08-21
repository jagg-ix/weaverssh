package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"weaverssh/containerstream"
)

func TestContainerProviderCommandsAreInCompletionCatalog(t *testing.T) {
	for _, command := range []string{"container-provider", "orchestration", "stream-provider", "terminal", "term", "console"} {
		if !containsString(topLevelCommands, command) {
			t.Fatalf("topLevelCommands missing %q", command)
		}
	}
}

func TestContainerProviderStatusForcedJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cmdContainerProviderStatus([]string{"--provider", "docker", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var discovery containerstream.Discovery
	if err := json.Unmarshal(stdout.Bytes(), &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery.Selected != containerstream.ProviderDocker {
		t.Fatalf("selected=%q", discovery.Selected)
	}
}

func TestContainerStreamCatUsesSelectedAdapter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "docker")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'container-bytes'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	var stdout, stderr bytes.Buffer
	code := cmdContainerStreamCat([]string{"--provider", "docker", "vfs://container/local/api-1/var/data.bin"}, &stdout, &stderr)
	if code != 0 || stdout.String() != "container-bytes" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestContainerStreamCatRejectsTraversal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cmdContainerStreamCat([]string{"--provider", "docker", "vfs://container/local/api-1/../secret"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "path escapes") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
