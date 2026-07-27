package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/sessionbroker"
	"weaverssh/sessionfsops"
	"weaverssh/sessionmux"
)

func TestRemoteToRemoteCopyStreamsBetweenDistinctNodes(t *testing.T) {
	sourceRoot, destinationRoot, opened, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	if err := os.MkdirAll(filepath.Join(sourceRoot, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destinationRoot, "incoming"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("remote-to-remote-stream\n"), 30000)
	sourcePath := filepath.Join(sourceRoot, "data", "result.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/data/result.bin",
		"destination-node:/incoming/",
	}, &stderr)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}

	copied, err := os.ReadFile(filepath.Join(destinationRoot, "incoming", "result.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, payload) {
		t.Fatalf("copied bytes=%d want=%d", len(copied), len(payload))
	}
	original, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, payload) {
		t.Fatal("source changed during remote-to-remote copy")
	}

	first, second := <-opened, <-opened
	if first != "source-node" || second != "destination-node" {
		t.Fatalf("opened nodes=%q,%q", first, second)
	}
}

func TestRemoteToRemoteCopyResolvesExistingDestinationDirectory(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	if err := os.WriteFile(filepath.Join(sourceRoot, "artifact.txt"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destinationRoot, "results"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/artifact.txt",
		"destination-node:/results",
	}, &stderr)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	payload, err := os.ReadFile(filepath.Join(destinationRoot, "results", "artifact.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "artifact" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestRemoteToRemoteCopyTruncatesExistingFileWithoutReplacingMode(t *testing.T) {
	sourceRoot, destinationRoot, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	if err := os.WriteFile(filepath.Join(sourceRoot, "new.txt"), []byte("new-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(destinationRoot, "existing.txt")
	if err := os.WriteFile(destinationPath, []byte("old-content-that-is-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/new.txt",
		"destination-node:/existing.txt",
	}, &stderr)
	if !handled || code != 0 {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	after, err := os.Stat(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode changed from %o to %o", before.Mode().Perm(), after.Mode().Perm())
	}
	payload, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "new-content" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestRemoteToRemoteCopyRejectsSameFile(t *testing.T) {
	sourceRoot, _, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()

	filePath := filepath.Join(sourceRoot, "same.txt")
	if err := os.WriteFile(filePath, []byte("preserve-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/same.txt",
		"source-node:/same.txt",
	}, &stderr)
	if !handled || code != 2 || !strings.Contains(stderr.String(), "same session file") {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
	payload, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "preserve-me" {
		t.Fatalf("source was truncated: %q", payload)
	}
}

func TestRemoteToRemoteCopyRejectsDirectoryAndRelativeNodes(t *testing.T) {
	sourceRoot, _, _, cleanup := startRemoteCopyTestBroker(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(sourceRoot, "directory"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	handled, code := trySessionRemoteCopy([]string{
		"source-node:/directory",
		"destination-node:/copy",
	}, &stderr)
	if !handled || code != 2 || !strings.Contains(stderr.String(), "recursive directory") {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}

	stderr.Reset()
	handled, code = trySessionRemoteCopy([]string{
		"self:/file",
		"destination-node:/copy",
	}, &stderr)
	if !handled || code != 2 || !strings.Contains(stderr.String(), "concrete signed node IDs") {
		t.Fatalf("handled=%t code=%d stderr=%s", handled, code, stderr.String())
	}
}

func TestResolveRemoteCopyDestination(t *testing.T) {
	client := fakeRemoteCopyStatClient{entries: map[string]p9client.DirEntry{
		"directory": {Name: "directory", IsDir: true},
	}}
	cases := []struct {
		destination sessionPath
		want        string
	}{
		{destination: sessionPath{Path: "directory"}, want: "directory/file.bin"},
		{destination: sessionPath{Path: "missing"}, want: "missing"},
		{destination: sessionPath{Path: "directory", TrailingSlash: true}, want: "directory/file.bin"},
		{destination: sessionPath{}, want: "file.bin"},
	}
	for _, test := range cases {
		got, err := resolveRemoteCopyDestination(client, test.destination, "file.bin")
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("destination=%+v got=%q want=%q", test.destination, got, test.want)
		}
	}
}

type fakeRemoteCopyStatClient struct {
	entries map[string]p9client.DirEntry
}

func (f fakeRemoteCopyStatClient) Stat(name string) (p9client.DirEntry, error) {
	entry, ok := f.entries[name]
	if !ok {
		return p9client.DirEntry{}, errors.New("not found")
	}
	return entry, nil
}

func startRemoteCopyTestBroker(t *testing.T) (string, string, <-chan string, func()) {
	t.Helper()
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	sourceServer, err := p9svc.New(p9svc.Config{Root: sourceRoot, ReadOnly: false})
	if err != nil {
		t.Fatal(err)
	}
	destinationServer, err := p9svc.New(p9svc.Config{Root: destinationRoot, ReadOnly: false})
	if err != nil {
		t.Fatal(err)
	}
	sourceOps, err := sessionfsops.NewServer(sessionfsops.ServerConfig{Root: sourceRoot})
	if err != nil {
		t.Fatal(err)
	}
	destinationOps, err := sessionfsops.NewServer(sessionfsops.ServerConfig{Root: destinationRoot})
	if err != nil {
		t.Fatal(err)
	}
	servers := map[string]*p9svc.Server{
		"source-node":      sourceServer,
		"destination-node": destinationServer,
	}
	operationServers := map[string]*sessionfsops.Server{
		"source-node":      sourceOps,
		"destination-node": destinationOps,
	}

	ctx, cancel := context.WithCancel(context.Background())
	socket := filepath.Join(t.TempDir(), "session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	opened := make(chan string, 32)
	broker := &sessionbroker.Server{Open: func(_ context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
		if request.Service != sessionmux.ServiceFS {
			return nil, errors.New("unexpected service")
		}
		server, ok := servers[request.Node]
		if !ok {
			return nil, errors.New("unknown node")
		}
		opened <- request.Node
		client, service := net.Pipe()
		switch {
		case len(request.Data) == 0:
			go func() { _ = server.ServeTransport(service) }()
		case sessionfsops.IsMetadata(request.Data):
			operations := operationServers[request.Node]
			go func() { _ = operations.Serve(ctx, service) }()
		default:
			_ = client.Close()
			_ = service.Close()
			return nil, errors.New("unexpected filesystem metadata")
		}
		return client, nil
	}}
	brokerErr := make(chan error, 1)
	go func() { brokerErr <- broker.Serve(ctx, listener) }()

	statePath := filepath.Join(t.TempDir(), "session.json")
	if err := sessionbroker.WriteState(statePath, sessionbroker.State{
		PID:       os.Getpid(),
		Socket:    socket,
		Binding:   "remote-copy-test-binding",
		Node:      "command-node",
		StartedAt: time.Now(),
	}); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(sessionbroker.EnvSocket, "")

	cleanup := func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-brokerErr:
			if err != nil {
				t.Errorf("broker shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("broker did not stop")
		}
	}
	return sourceRoot, destinationRoot, opened, cleanup
}
