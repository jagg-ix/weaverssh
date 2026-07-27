package main

import "testing"

func TestFlowCommandDispatch(t *testing.T) {
	if !hasCommand("flow") || !hasCommand("buffer") || !hasCommand("buffers") {
		t.Fatalf("flow aliases missing from top-level command registry: %v", topLevelCommands)
	}
	if rc := cmdFlow([]string{"profiles"}); rc != 0 {
		t.Fatalf("flow profiles rc=%d", rc)
	}
	if rc := cmdFlow([]string{"validate", "--profile", "balanced"}); rc != 0 {
		t.Fatalf("flow validate rc=%d", rc)
	}
	if rc := cmdFlow([]string{"plan", "--profile", "realtime", "--bandwidth-mbps", "1000", "--rtt", "10ms"}); rc != 0 {
		t.Fatalf("flow plan rc=%d", rc)
	}
	if rc := cmdFlow([]string{"optimize", "--policy", "latency", "--payload-bytes", "512", "--bandwidth-mbps", "100", "--rtt", "20ms"}); rc != 0 {
		t.Fatalf("flow optimize rc=%d", rc)
	}
	if rc := cmdFlow([]string{"optimize", "--policy", "bad"}); rc != 1 {
		t.Fatalf("bad optimize policy rc=%d want 1", rc)
	}
	if rc := cmdFlow([]string{"optimize", "--no-realtime", "--no-bulk"}); rc != 2 {
		t.Fatalf("conflicting route disables rc=%d want 2", rc)
	}
	if rc := cmdFlow([]string{"plan", "--profile", "bad"}); rc != 2 {
		t.Fatalf("bad profile rc=%d want 2", rc)
	}
}

func hasCommand(name string) bool {
	for _, got := range topLevelCommands {
		if got == name {
			return true
		}
	}
	return false
}
