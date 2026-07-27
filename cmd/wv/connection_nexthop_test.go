package main

import "testing"

func TestChainIndexOf(t *testing.T) {
	nodes := []string{"workstation", "jump", "group:computes"}
	if got := chainIndexOf(nodes, "jump"); got != 1 {
		t.Fatalf("jump index = %d, want 1", got)
	}
	if got := chainIndexOf(nodes, "workstation"); got != 0 {
		t.Fatalf("workstation index = %d, want 0", got)
	}
	// A selector step is never matched as a concrete self.
	if got := chainIndexOf(nodes, "computes"); got != -1 {
		t.Fatalf("selector matched as concrete: index = %d, want -1", got)
	}
	if got := chainIndexOf(nodes, "missing"); got != -1 {
		t.Fatalf("missing index = %d, want -1", got)
	}
}

func TestSSHDestination(t *testing.T) {
	if d, err := sshDestination(ConnProfile{Name: "x", SSHHost: "h", SSHUser: "u"}); err != nil || d != "u@h" {
		t.Fatalf("dest=%q err=%v, want u@h", d, err)
	}
	if d, err := sshDestination(ConnProfile{Name: "x", SSHHost: "h"}); err != nil || d != "h" {
		t.Fatalf("dest=%q err=%v, want h", d, err)
	}
	if _, err := sshDestination(ConnProfile{Name: "x"}); err == nil {
		t.Fatal("expected error for a profile with no ssh_host")
	}
}
