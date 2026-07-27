package filebackend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadHooksFileRunsBoundedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "event.json")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > \"$OUTPUT_FILE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := HookFileConfig{
		Version: HookConfigVersion,
		Hooks: []CommandHookConfig{{
			Operation: OperationWrite,
			Command: []string{script},
			Mode: ModeEnforce,
			Environment: map[string]string{"OUTPUT_FILE": output},
		}},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadHooksFile(configPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Run(context.Background(), Event{Operation: OperationWrite, Phase: PhaseBefore, Path: "file"}); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(stored, &event); err != nil {
		t.Fatal(err)
	}
	if event.Operation != OperationWrite || event.Phase != PhaseBefore || event.Path != "file" {
		t.Fatalf("event=%+v", event)
	}
}

func TestLoadHooksFileRejectsRelativeExecutable(t *testing.T) {
	dir := t.TempDir()
	config := HookFileConfig{
		Version: HookConfigVersion,
		Hooks: []CommandHookConfig{{Operation: OperationRead, Command: []string{"hook"}}},
	}
	payload, _ := json.Marshal(config)
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHooksFile(path, nil); err == nil {
		t.Fatal("expected relative executable rejection")
	}
}
