package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"weaverssh/socketengine"
)

func TestSocketEngineInitAndInspect(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "socket-engine.json")
	if code := cmdSocketEngineComplete([]string{
		"init",
		"--listen", "tcp://127.0.0.1:19081",
		"--node", "node-a",
		"--target", "127.0.0.1:22",
		"--out", configPath,
	}); code != 0 {
		t.Fatalf("socket-engine init code=%d", code)
	}
	config, err := socketengine.LoadConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := socketengine.Inspect(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].Node != "node-a" || plan.Routes[0].Address != "127.0.0.1:22" {
		t.Fatalf("plan=%+v", plan)
	}
	rc, output := captureStdout(t, func() int {
		return cmdSocketEngineComplete([]string{"inspect", configPath, "--json"})
	})
	if rc != 0 {
		t.Fatalf("socket-engine inspect rc=%d output=%s", rc, output)
	}
	var decoded socketengine.Plan
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("decode plan: %v output=%s", err, output)
	}
	if len(decoded.Routes) != 1 || decoded.Routes[0].Listen != "tcp://127.0.0.1:19081" {
		t.Fatalf("decoded plan=%+v", decoded)
	}
}

func TestSocketEngineInitRejectsNonLoopbackByDefault(t *testing.T) {
	if code := cmdSocketEngineComplete([]string{
		"init",
		"--listen", "tcp://0.0.0.0:19081",
		"--node", "node-a",
		"--target", "127.0.0.1:22",
	}); code != 2 {
		t.Fatalf("non-loopback init code=%d want 2", code)
	}
}
