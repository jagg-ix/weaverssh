package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/sessionbroker"
)

func TestVerifyRemoteCopyStateRejectsSessionChange(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "session.json")
	initial := sessionbroker.State{
		PID:       os.Getpid(),
		Socket:    filepath.Join(t.TempDir(), "session.sock"),
		Binding:   "binding-a",
		Node:      "jump-a",
		StartedAt: time.Now(),
	}
	if err := sessionbroker.WriteState(statePath, initial); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(sessionbroker.EnvSocket, "")
	if err := verifyRemoteCopyState(initial); err != nil {
		t.Fatal(err)
	}

	changed := initial
	changed.Binding = "binding-b"
	changed.StartedAt = time.Now().Add(time.Second)
	if err := sessionbroker.WriteState(statePath, changed); err != nil {
		t.Fatal(err)
	}
	if err := verifyRemoteCopyState(initial); err == nil || !strings.Contains(err.Error(), "active session changed") {
		t.Fatalf("error=%v", err)
	}
}
