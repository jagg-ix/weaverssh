package originruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeConfigRejectsUnknownFieldInValidJSON(t *testing.T) {
	_, _, err := DecodeConfig(strings.NewReader(`{"version":"weaverssh.origin-runtime.v1","name":"x","kind":"native","guest_root":"/x","host_root":"/x","unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadConfigFileResolvesRelativeHostPaths(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	artifacts := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "runtime.json")
	payload := `{
  "version": "weaverssh.origin-runtime.v1",
  "name": "relative-runtime",
  "kind": "native",
  "guest_root": "/workspace",
  "host_root": "workspace",
  "path_mappings": [{"host": "artifacts", "guest": "/artifacts"}]
}`
	if err := os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	config, digest, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.HostRoot != workspace || config.PathMappings[0].Host != artifacts || !validSHA256(digest) {
		t.Fatalf("config=%+v digest=%s", config, digest)
	}
}

func TestConfigValidationRejectsRelativeGuestRoot(t *testing.T) {
	config := Config{Version: ConfigVersion, Name: "relative", Kind: KindNative, GuestRoot: "workspace", HostRoot: t.TempDir()}
	if err := config.Validate(); err == nil {
		t.Fatal("relative guest_root was accepted")
	}
}
