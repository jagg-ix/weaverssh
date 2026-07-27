package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"weaverssh/originruntime"
)

func writeNativeOriginRuntimeConfig(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	config := originruntime.Config{
		Version: originruntime.ConfigVersion, Name: "test-origin", Kind: originruntime.KindNative,
		GuestRoot: "/workspace", HostRoot: root,
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, root
}

func TestOriginRuntimeValidateDescribeAndMap(t *testing.T) {
	configPath, root := writeNativeOriginRuntimeConfig(t)
	if code := cmdOriginRuntimeValidate([]string{"--config", configPath}); code != 0 {
		t.Fatalf("validate code=%d", code)
	}
	if code := cmdOriginRuntimeDescribe([]string{"--config", configPath, "--json"}); code != 0 {
		t.Fatalf("describe code=%d", code)
	}
	if code := cmdOriginRuntimeMap([]string{"--config", configPath, "--to-guest", filepath.Join(root, "a.txt")}); code != 0 {
		t.Fatalf("map code=%d", code)
	}
	if code := cmdOriginRuntimeMap([]string{"--config", configPath, "--to-host", "/workspace/a.txt"}); code != 0 {
		t.Fatalf("reverse map code=%d", code)
	}
}

func TestOriginRuntimeEnvironmentDefaultsToWeaverSSHVariables(t *testing.T) {
	t.Setenv("WEAVERSSH_TRANSFER_ID", "transfer-a")
	t.Setenv("TENANT_ID", "tenant-a")
	values, err := originRuntimeEnvironment(false, []string{"TENANT_ID"}, []string{"MODE=safe"})
	if err != nil {
		t.Fatal(err)
	}
	if values["WEAVERSSH_TRANSFER_ID"] != "transfer-a" || values["TENANT_ID"] != "tenant-a" || values["MODE"] != "safe" {
		t.Fatalf("values=%v", values)
	}
}

func TestExtractOriginRuntimeConfigRemovesOnlyWrapperFlag(t *testing.T) {
	t.Setenv(originruntime.EnvConfig, "")
	config, remaining, err := extractOriginRuntimeConfig([]string{"--origin-runtime-config", "runtime.json", "--recursive", "--", "ssh", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if config != "runtime.json" || strings.Join(remaining, " ") != "--recursive -- ssh host" {
		t.Fatalf("config=%q remaining=%q", config, remaining)
	}
	if !containsSessionHostRoot([]string{"--root=/srv", "--", "ssh"}) {
		t.Fatal("root option was not detected")
	}
	if containsSessionHostRoot([]string{"--", "ssh", "--root=/guest"}) {
		t.Fatal("child argument was mistaken for session-host root")
	}
}

func TestReadOnlyRuntimeRejectsWriteRequestHelper(t *testing.T) {
	if !explicitlyDisablesReadOnly([]string{"--read-only=false", "--", "ssh"}) {
		t.Fatal("explicit write request was not detected")
	}
	if explicitlyDisablesReadOnly([]string{"--", "ssh", "--read-only=false"}) {
		t.Fatal("child argument was mistaken for session-host option")
	}
}
