package main

import (
	"os"
	"path/filepath"
	"testing"

	"weaverssh/storageadapter"
)

func TestStorageEnginesIncludeDefaultProviders(t *testing.T) {
	engines := storageadapter.Engines()
	seen := map[string]bool{}
	for _, engine := range engines { seen[engine] = true }
	if !seen["memory"] || !seen["file"] {
		t.Fatalf("engines=%v", engines)
	}
}

func TestLoadStorageConfigOperandResolvesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "storage.json")
	if err := os.WriteFile(path, []byte(`{"version":"weaverssh.storage.v1","engine":"file","path":"state.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, rest, err := loadStorageConfigOperand([]string{path, "--json"}, "storage status")
	if err != nil { t.Fatal(err) }
	if config.Engine != "file" || config.Path != filepath.Join(dir, "state.json") || len(rest) != 1 || rest[0] != "--json" {
		t.Fatalf("config=%+v rest=%v", config, rest)
	}
}

func TestReadStorageValueBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(path, []byte("too-large"), 0o600); err != nil { t.Fatal(err) }
	if _, err := readStorageValue("", path, 3); err == nil {
		t.Fatal("oversized value accepted")
	}
	value, err := readStorageValue("literal", "", 32)
	if err != nil || string(value) != "literal" { t.Fatalf("value=%q err=%v", value, err) }
}
