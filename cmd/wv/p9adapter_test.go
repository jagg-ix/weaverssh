package main

import (
	"path/filepath"
	"testing"
)

func Test9PAdapterCommandRegistered(t *testing.T) {
	if !containsString(topLevelCommands, "9p-adapter") {
		t.Fatalf("topLevelCommands missing 9p-adapter: %v", topLevelCommands)
	}
	if !containsString(topLevelCommands, "9p-provider") {
		t.Fatalf("topLevelCommands missing 9p-provider alias: %v", topLevelCommands)
	}
}

func Test9PAdapterPlanExternalTCP(t *testing.T) {
	rc := cmd9PAdapter([]string{"plan", "--kind", "external-tcp-9p", "--endpoint", "127.0.0.1:5640"})
	if rc != 0 {
		t.Fatalf("9p-adapter plan external rc=%d", rc)
	}
}

func Test9PAdapterPlanQEMUVirtFS(t *testing.T) {
	rc := cmd9PAdapter([]string{"plan", "--kind", "qemu-virtfs", "--source", "/srv/share", "--mount-tag", "hostshare", "--mount-point", "/mnt/hostshare"})
	if rc != 0 {
		t.Fatalf("9p-adapter plan qemu rc=%d", rc)
	}
}

func Test9PAdapterUseExternalTCPWritesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEAVERSSH_VFS_CONFIG_DIR", filepath.Join(dir, "cfgdir"))
	t.Setenv("WEAVERSSH_VFS_CONFIG", filepath.Join(dir, "vfs.json"))
	rc := cmd9PAdapter([]string{"use", "--name", "external", "--kind", "external-tcp-9p", "--endpoint", "127.0.0.1:15640", "--socks", "127.0.0.1:11080"})
	if rc != 0 {
		t.Fatalf("9p-adapter use rc=%d", rc)
	}
	if rc := cmd9PAdapter([]string{"status"}); rc != 0 {
		t.Fatalf("9p-adapter status rc=%d", rc)
	}
}

func Test9PAdapterRejectsQEMUUseWithoutSource(t *testing.T) {
	rc := cmd9PAdapter([]string{"plan", "--kind", "qemu-virtfs", "--mount-tag", "hostshare"})
	if rc != 2 {
		t.Fatalf("9p-adapter qemu missing source rc=%d want 2", rc)
	}
}
