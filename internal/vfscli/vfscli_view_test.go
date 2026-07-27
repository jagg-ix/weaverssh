package vfscli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"weaverssh/internal/p9svc"
	"weaverssh/internal/vfs"
	"weaverssh/pubsub"
)

func startVFSCLITestServer(t *testing.T, root string, readOnly bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := p9svc.New(p9svc.Config{Root: root, Addr: ln.Addr().String(), ReadOnly: readOnly})
	if err != nil {
		t.Fatalf("p9svc.New: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestCpFromVFSUsesViewRenameAndHideRules(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "docs", "api"))
	mustMkdirAll(t, filepath.Join(root, "docs", "private"))
	mustMkdirAll(t, filepath.Join(root, "docs", ".git"))
	mustWrite(t, filepath.Join(root, "docs", "api", "readme.md"), "visible\n")
	mustWrite(t, filepath.Join(root, "docs", "private", "secret.txt"), "hidden\n")
	mustWrite(t, filepath.Join(root, "docs", ".git", "config"), "hidden\n")

	t.Setenv(vfs.EnvEndpoint, startVFSCLITestServer(t, root, true))
	t.Setenv(vfs.EnvViewConfig, filepath.Join(t.TempDir(), "view.json"))
	if err := vfs.SaveView(vfs.ViewConfig{Version: vfs.ViewVersion, Rules: []vfs.ViewRule{
		{Action: vfs.ViewActionHide, Match: ".git"},
		{Action: vfs.ViewActionHide, Match: "docs/private"},
		{Action: vfs.ViewActionRename, Match: "docs", To: "Documentation"},
	}}); err != nil {
		t.Fatalf("SaveView: %v", err)
	}

	dst := t.TempDir()
	if err := cmdCp([]string{"-r", "vfs://Documentation", dst}); err != nil {
		t.Fatalf("cmdCp: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "Documentation", "api", "readme.md"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(got) != "visible\n" {
		t.Fatalf("copied file = %q, want visible", got)
	}
	for _, hidden := range []string{
		filepath.Join(dst, "Documentation", "private"),
		filepath.Join(dst, "Documentation", ".git"),
	} {
		if _, err := os.Stat(hidden); !os.IsNotExist(err) {
			t.Fatalf("hidden path copied: %s err=%v", hidden, err)
		}
	}
}

func TestCpWritesFileTransferEvents(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "abc")
	t.Setenv(vfs.EnvEndpoint, startVFSCLITestServer(t, root, true))
	t.Setenv(vfs.EnvViewConfig, filepath.Join(t.TempDir(), "missing-view.json"))

	eventsPath := filepath.Join(t.TempDir(), "transfer-events.ndjson")
	dst := filepath.Join(t.TempDir(), "a.txt")
	if err := cmdCp([]string{"-events", eventsPath, "vfs://a.txt", dst}); err != nil {
		t.Fatalf("cmdCp: %v", err)
	}
	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("event line count=%d data=%s", len(lines), data)
	}
	events := map[string]pubsub.Event{}
	for i, line := range lines {
		event, err := pubsub.DecodeEvent([]byte(line))
		if err != nil {
			t.Fatalf("decode event %d: %v", i, err)
		}
		events[event.Type] = event
	}
	started := events["file_transfer_started"]
	completed := events["file_transfer_completed"]
	if started.Type != "file_transfer_started" || completed.Type != "file_transfer_completed" {
		t.Fatalf("unexpected event types: %s %s", started.Type, completed.Type)
	}
	if completed.Component != pubsub.ComponentVFS || completed.Fields["direction"] != string(pubsub.TransferVfsToLocal) || completed.Fields["bytes"] != "3" {
		t.Fatalf("unexpected completed event: %+v", completed)
	}
	if completed.Fields["source"] != "vfs://a.txt" || completed.Fields["destination"] != dst {
		t.Fatalf("unexpected transfer endpoints: %+v", completed.Fields)
	}
	opened := events[string(pubsub.FileOpened)]
	read := events[string(pubsub.FileRead)]
	written := events[string(pubsub.FileWritten)]
	if opened.Fields["path"] != "vfs://a.txt" || read.Fields["path"] != "vfs://a.txt" {
		t.Fatalf("unexpected source file events: opened=%+v read=%+v", opened, read)
	}
	if written.Fields["path"] != dst || written.Fields["bytes"] != "3" {
		t.Fatalf("unexpected destination file event: %+v", written)
	}
}

func TestVFSCommandsWriteInfrastructureEvents(t *testing.T) {
	root := t.TempDir()
	t.Setenv(vfs.EnvEndpoint, startVFSCLITestServer(t, root, false))
	t.Setenv(vfs.EnvViewConfig, filepath.Join(t.TempDir(), "missing-view.json"))
	eventsPath := filepath.Join(t.TempDir(), "infra-events.ndjson")
	t.Setenv(envInfraEvents, eventsPath)

	if err := cmdLs([]string{"vfs://"}); err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	if err := cmdMkdir([]string{"vfs://newdir"}); err != nil {
		t.Fatalf("cmdMkdir: %v", err)
	}
	if err := cmdRm([]string{"vfs://newdir"}); err != nil {
		t.Fatalf("cmdRm: %v", err)
	}

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	events := map[string]pubsub.Event{}
	for i, line := range lines {
		event, err := pubsub.DecodeEvent([]byte(line))
		if err != nil {
			t.Fatalf("decode event %d: %v", i, err)
		}
		events[event.Type] = event
	}
	for _, eventType := range []string{string(pubsub.FileListed), string(pubsub.FileMkdir), string(pubsub.FileRemoved)} {
		if events[eventType].Type != eventType {
			t.Fatalf("missing %s in events: %+v", eventType, events)
		}
	}
	if events[string(pubsub.FileMkdir)].Fields["path"] != "vfs://newdir" {
		t.Fatalf("unexpected mkdir event: %+v", events[string(pubsub.FileMkdir)])
	}
	if events[string(pubsub.FileRemoved)].Fields["path"] != "vfs://newdir" {
		t.Fatalf("unexpected removed event: %+v", events[string(pubsub.FileRemoved)])
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
