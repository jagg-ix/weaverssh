package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestCompleteConnectionProfileLifecycle(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnectionsComplete([]string{"set", "development", "--host", "dev.example", "--user", "alice", "--active"}); rc != 0 {
		t.Fatalf("set rc=%d", rc)
	}
	if rc := cmdConnectionsComplete([]string{"set", "production", "--host", "prod.example", "--user", "deploy"}); rc != 0 {
		t.Fatalf("second set rc=%d", rc)
	}
	if rc := cmdConnectionsComplete([]string{"rename", "development", "workbench", "--json"}); rc != 0 {
		t.Fatalf("rename rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Active != "workbench" {
		t.Fatalf("active=%q want workbench", store.Active)
	}
	if profile, _, ok := findProfile(store, "workbench"); !ok || profile.SSHHost != "dev.example" || profile.SSHUser != "alice" {
		t.Fatalf("renamed profile=%+v ok=%t", profile, ok)
	}
	if _, _, ok := findProfile(store, "development"); ok {
		t.Fatal("old profile name still exists")
	}

	rc, output := captureStdout(t, func() int {
		return cmdConnectionsComplete([]string{"show", "workbench", "--json"})
	})
	if rc != 0 {
		t.Fatalf("show rc=%d output=%s", rc, output)
	}
	var shown ConnProfile
	if err := json.Unmarshal([]byte(output), &shown); err != nil || shown.Name != "workbench" {
		t.Fatalf("shown=%+v err=%v output=%s", shown, err, output)
	}

	if rc := cmdConnectionsComplete([]string{"clear"}); rc != 0 {
		t.Fatalf("clear rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Active != "" || len(store.Profiles) != 2 {
		t.Fatalf("clear should preserve profiles: %+v", store)
	}

	if rc := cmdConnectionsComplete([]string{"remove", "workbench"}); rc != 0 {
		t.Fatalf("remove rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Profiles) != 1 || store.Profiles[0].Name != "production" {
		t.Fatalf("remaining profiles=%+v", store.Profiles)
	}
}

func TestCompleteConnectionProfileRenameRejectsCollision(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnectionsComplete([]string{"set", "one", "--host", "one.example"}); rc != 0 {
		t.Fatalf("set one rc=%d", rc)
	}
	if rc := cmdConnectionsComplete([]string{"set", "two", "--host", "two.example"}); rc != 0 {
		t.Fatalf("set two rc=%d", rc)
	}
	if rc := cmdConnectionsComplete([]string{"rename", "one", "two"}); rc != 1 {
		t.Fatalf("collision rc=%d want 1", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := findProfile(store, "one"); !ok {
		t.Fatal("collision removed source profile")
	}
}
