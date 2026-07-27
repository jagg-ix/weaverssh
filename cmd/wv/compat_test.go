package main

import (
	"strings"
	"testing"
)

func TestCompatCommandRegistered(t *testing.T) {
	if !containsString(topLevelCommands, "compat") {
		t.Fatalf("topLevelCommands missing compat: %v", topLevelCommands)
	}
	if !containsString(topLevelCommands, "compatibility") {
		t.Fatalf("topLevelCommands missing compatibility alias: %v", topLevelCommands)
	}
}

func TestCompatSupportedKinds(t *testing.T) {
	cases := [][]string{
		{"--kind", "s3", "--endpoint", "s3://bucket/prefix", "--region", "us-east-1"},
		{"https", "--endpoint", "https://api.example.com/hook"},
		{"check", "--kind", "mqtt", "--endpoint", "mqtts://broker.example.com:8883"},
		{"hadoop", "--endpoint", "hdfs://namenode.example.com:8020/data"},
	}
	for _, tc := range cases {
		rc, out := captureStdout(t, func() int { return cmdCompat(tc) })
		if rc != 0 {
			t.Fatalf("cmdCompat(%v) rc=%d out=%s", tc, rc, out)
		}
		if !strings.Contains(out, "data-plane:    weaverssh") {
			t.Fatalf("compatibility output should identify weaverssh as data-plane owner, got:\n%s", out)
		}
	}
}

func TestCompatRejectsInsecureRemoteMQTT(t *testing.T) {
	if rc := cmdCompat([]string{"mqtt", "--endpoint", "mqtt://broker.example.com:1883"}); rc != 2 {
		t.Fatalf("expected insecure remote mqtt:// to fail with rc=2, got %d", rc)
	}
	if rc := cmdCompat([]string{"mqtt", "--endpoint", "mqtt://127.0.0.1:1883"}); rc != 0 {
		t.Fatalf("expected loopback mqtt:// to be accepted, got %d", rc)
	}
}

func TestCompatListJSON(t *testing.T) {
	rc, out := captureStdout(t, func() int { return cmdCompat([]string{"list", "--json"}) })
	if rc != 0 {
		t.Fatalf("list --json rc=%d", rc)
	}
	for _, want := range []string{"s3", "https-tls", "mqtt", "hadoop"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list --json missing %q: %s", want, out)
		}
	}
}

func TestCompatPlanCommandRemoved(t *testing.T) {
	if rc := cmdCompat([]string{"plan", "--kind", "s3", "--endpoint", "s3://bucket/prefix"}); rc != 2 {
		t.Fatalf("expected removed plan command to fail with rc=2, got %d", rc)
	}
}
