package extension

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadFileRunsCommandHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat is unavailable")
	}
	temp := t.TempDir()
	output := filepath.Join(temp, "event.json")
	script := filepath.Join(temp, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n/bin/cat > \"$OUTPUT_FILE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temp, "extensions.json")
	config := FileConfig{
		Version: ConfigVersion,
		Extensions: []CommandExtensionConfig{{
			Name: "audit", Version: "1",
			Hooks: []CommandHookConfig{{
				Point: PointSessionReady,
				Command: []string{script},
				Mode: ModeEnforce,
				Environment: map[string]string{"OUTPUT_FILE": output},
			}},
		}},
	}
	payload, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadFile(configPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	event := NewEvent(PointSessionReady)
	event.SessionBinding = "binding"
	if err := registry.Run(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(stored, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Point != PointSessionReady || decoded.SessionBinding != "binding" {
		t.Fatalf("decoded event=%+v", decoded)
	}
}

func TestLoadFileRejectsRelativeExecutable(t *testing.T) {
	temp := t.TempDir()
	configPath := filepath.Join(temp, "extensions.json")
	config := FileConfig{
		Version: ConfigVersion,
		Extensions: []CommandExtensionConfig{{
			Name: "audit", Version: "1",
			Hooks: []CommandHookConfig{{Point: PointSessionReady, Command: []string{"hook"}}},
		}},
	}
	payload, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(configPath, nil); err == nil {
		t.Fatal("expected relative executable rejection")
	}
}
