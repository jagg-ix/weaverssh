package main

import "testing"

func TestInstrumentTopLevelCommandRegistered(t *testing.T) {
	if !containsString(topLevelCommands, "instrument") {
		t.Fatalf("topLevelCommands missing instrument: %v", topLevelCommands)
	}
	if !containsString(topLevelCommands, "observe") {
		t.Fatalf("topLevelCommands missing observe alias: %v", topLevelCommands)
	}
	if containsString(topLevelCommands, "ebpf") {
		t.Fatalf("topLevelCommands should not expose ebpf as primary command: %v", topLevelCommands)
	}
}

func TestInstrumentPlanAndProbeCommands(t *testing.T) {
	if rc := cmdInstrument([]string{"providers"}); rc != 0 {
		t.Fatalf("instrument providers rc=%d", rc)
	}
	if rc := cmdInstrument([]string{"probes", "--provider", "ebpf"}); rc != 0 {
		t.Fatalf("instrument probes rc=%d", rc)
	}
	if rc := cmdInstrument([]string{"plan", "--provider", "ebpf", "--profile", "socket", "--chain", "origin,node1,node2"}); rc != 0 {
		t.Fatalf("instrument plan rc=%d", rc)
	}
	if rc := cmdInstrument([]string{"plan", "--provider", "dtrace"}); rc != 2 {
		t.Fatalf("bad provider rc=%d want 2", rc)
	}
	if rc := cmdInstrument([]string{"plan", "--profile", "bad"}); rc != 2 {
		t.Fatalf("bad profile rc=%d want 2", rc)
	}
	if rc := cmdInstrument([]string{"script", "--provider", "ebpf", "--format", "bpftrace", "--profile", "minimal"}); rc != 0 {
		t.Fatalf("instrument script rc=%d", rc)
	}
}
