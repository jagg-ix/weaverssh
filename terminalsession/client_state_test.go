package terminalsession

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testClientState() ClientState {
	now := time.Unix(100, 0).UTC()
	return ClientState{
		Version: ClientStateVersion, Node: "laptop", SessionID: "session-a",
		ResumeToken: "secondary-secret", CreatedAt: now, UpdatedAt: now,
	}
}

func TestClientStateRoundTripIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	state := testClientState()
	if err := SaveClientState(path, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want=600", info.Mode().Perm())
	}
	loaded, err := LoadClientState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ResumeToken != state.ResumeToken || loaded.SessionID != state.SessionID {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestClientStateRejectsExposedOrSymlinkedSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission and symlink checks")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "session.json")
	if err := SaveClientState(path, testClientState()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientState(path); err == nil {
		t.Fatal("world-readable resume state loaded")
	}
	link := filepath.Join(directory, "session-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveClientState(link, testClientState()); err == nil {
		t.Fatal("resume state symlink overwritten")
	}
}
