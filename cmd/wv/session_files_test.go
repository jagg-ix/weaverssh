package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/internal/p9svc"
	"weaverssh/sessionbroker"
)

func TestParseSessionPath(t *testing.T) {
	tests := []struct {
		input   string
		matched bool
		node    string
		path    string
		wantErr bool
	}{
		{input: "endpoint:/var/log/app.log", matched: true, node: "endpoint", path: "var/log/app.log"},
		{input: "origin:/", matched: true, node: "origin", path: ""},
		{input: "[node-v6]:/data", matched: true, node: "node-v6", path: "data"},
		{input: "vfs://data", matched: false},
		{input: "vfs::endpoint:/data", matched: false},
		{input: "./local:file", matched: false},
		{input: `C:\\temp\\file`, matched: false},
		{input: "endpoint:~/file", matched: true, wantErr: true},
		{input: "user@endpoint:/file", matched: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, matched, err := parseSessionPath(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if matched != test.matched {
				t.Fatalf("matched=%t want %t", matched, test.matched)
			}
			if matched && (got.Node != test.node || got.Path != test.path) {
				t.Fatalf("got=%+v want node=%q path=%q", got, test.node, test.path)
			}
		})
	}
}

func TestBrokerAwareFileCommands(t *testing.T) {
	root, cleanup := startSessionFileTestBroker(t)
	defer cleanup()

	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello through broker\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := cmdSessionCat([]string{"origin:/hello.txt"}, &stdout, &stderr); code != 0 {
		t.Fatalf("cat code=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "hello through broker\n" {
		t.Fatalf("cat output=%q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := cmdSessionLS([]string{"origin:/"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ls code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "hello.txt") {
		t.Fatalf("ls output=%q", stdout.String())
	}

	stderr.Reset()
	if code := cmdSessionMkdir([]string{"-p", "origin:/nested/path"}, &stderr); code != 0 {
		t.Fatalf("mkdir code=%d stderr=%s", code, stderr.String())
	}
	if info, err := os.Stat(filepath.Join(root, "nested", "path")); err != nil || !info.IsDir() {
		t.Fatalf("mkdir result info=%v err=%v", info, err)
	}

	localSource := filepath.Join(t.TempDir(), "upload.txt")
	large := bytes.Repeat([]byte("streamed-data-"), 10000)
	if err := os.WriteFile(localSource, large, 0o640); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := cmdSessionCP([]string{localSource, "origin:/nested/path/"}, bytes.NewReader(nil), io.Discard, &stderr); code != 0 {
		t.Fatalf("upload code=%d stderr=%s", code, stderr.String())
	}
	uploaded, err := os.ReadFile(filepath.Join(root, "nested", "path", "upload.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploaded, large) {
		t.Fatalf("uploaded bytes=%d want %d", len(uploaded), len(large))
	}

	download := filepath.Join(t.TempDir(), "download.txt")
	stderr.Reset()
	if code := cmdSessionCP([]string{"origin:/nested/path/upload.txt", download}, bytes.NewReader(nil), io.Discard, &stderr); code != 0 {
		t.Fatalf("download code=%d stderr=%s", code, stderr.String())
	}
	downloaded, err := os.ReadFile(download)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, large) {
		t.Fatalf("downloaded bytes=%d want %d", len(downloaded), len(large))
	}

	stderr.Reset()
	if code := cmdSessionRM([]string{"origin:/nested/path/upload.txt"}, &stderr); code != 0 {
		t.Fatalf("rm code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "nested", "path", "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("removed file stat err=%v", err)
	}

	stderr.Reset()
	if code := cmdSessionCP([]string{"origin:/hello.txt", "endpoint:/hello.txt"}, bytes.NewReader(nil), io.Discard, &stderr); code != 2 {
		t.Fatalf("node-to-node code=%d stderr=%s", code, stderr.String())
	}
}

func startSessionFileTestBroker(t *testing.T) (string, func()) {
	t.Helper()
	root := t.TempDir()
	server, err := p9svc.New(p9svc.Config{Root: root, ReadOnly: false})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	socket := filepath.Join(t.TempDir(), "session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	broker := &sessionbroker.Server{Open: func(context.Context, sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
		client, service := net.Pipe()
		go func() { _ = server.ServeTransport(service) }()
		return client, nil
	}}
	brokerErr := make(chan error, 1)
	go func() { brokerErr <- broker.Serve(ctx, listener) }()

	statePath := filepath.Join(t.TempDir(), "session.json")
	if err := sessionbroker.WriteState(statePath, sessionbroker.State{
		PID:       os.Getpid(),
		Socket:    socket,
		Binding:   "test-binding",
		Node:      "endpoint",
		StartedAt: time.Now(),
	}); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(sessionbroker.EnvSocket, "")

	return root, func() {
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
}
