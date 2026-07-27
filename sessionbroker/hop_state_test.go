package sessionbroker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHopStateRoundTrip(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "session.json")
	want := HopState{
		PreviousNode: "workstation-42",
		HopChain:     "encoded-hop-chain",
		Depth:        2,
	}
	if err := WriteHopState(statePath, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(HopStatePath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	got, err := ReadHopState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got.PreviousNode != want.PreviousNode || got.HopChain != want.HopChain || got.Depth != want.Depth {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
	if err := RemoveHopState(statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(HopStatePath(statePath)); !os.IsNotExist(err) {
		t.Fatalf("removed sidecar stat=%v", err)
	}
}

func TestActiveHopStateUsesConfiguredStatePath(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "custom-session.json")
	if err := WriteHopState(statePath, HopState{PreviousNode: "jump-a", HopChain: "chain", Depth: 1}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvState, statePath)
	got, err := ActiveHopState()
	if err != nil {
		t.Fatal(err)
	}
	if got.PreviousNode != "jump-a" || got.Depth != 1 {
		t.Fatalf("got=%+v", got)
	}
}
