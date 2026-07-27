package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// sampleScan mirrors the shape of `connection-wizard-scan -format json`.
const sampleScan = `{
  "ok": true,
  "source": "local",
  "profile": {
    "name": "linode-b",
    "description": "Linode test box",
    "ssh_host": "203.0.113.10",
    "ssh_user": "kb",
    "ssh_port": 22,
    "identity_file": "/Users/me/.ssh/id_ed25519",
    "repo_root": "/repo/weaverssh",
    "adapter": "openSSH",
    "credential_provider": "identityFile",
    "ninep_port": 5640,
    "tags": ["wizard","linode"]
  },
  "credential_choices": [
    {"index":1,"kind":"identity_system","id":"sshAgent","label":"ssh-agent","state":"ok","detail":"loaded","path":"/tmp/agent.sock","source":"SSH_AUTH_SOCK"},
    {"index":3,"kind":"key_file","id":"identityFile","label":"SSH key file","state":"ok","path":"/Users/me/.ssh/id_ed25519"}
  ],
  "assessment": {
    "ok": false,
    "state": "needs_setup",
    "summary": "Setup required: ssh_host",
    "next_action": "Enter the remote host or import a connection profile.",
    "credential_provider": "sshAgent",
    "identity_file": "/Users/me/.ssh/id_ed25519",
    "identity_files": ["/Users/me/.ssh/a.key","/Users/me/.ssh/id_ed25519"],
    "ssh_configs": ["/etc/ssh/ssh_config"],
    "missing": ["ssh_host"]
  },
  "ssh_config_sources": [
    {"index":1,"path":"/etc/ssh/ssh_config","scope":"system","reason":"system-wide ssh_config","exists":true}
  ],
  "config_dir": "/Users/me/.weaverssh-service-dock",
  "profiles_dir": "/Users/me/.weaverssh-service-dock/profiles",
  "store_path": "/Users/me/.weaverssh-service-dock/connections.json"
}`

func TestParseScan(t *testing.T) {
	s, err := parseScan([]byte(sampleScan))
	if err != nil {
		t.Fatalf("parseScan: %v", err)
	}
	if !s.OK {
		t.Error("ok should be true")
	}
	if s.Profile.Name != "linode-b" || s.Profile.SSHHost != "203.0.113.10" || s.Profile.SSHUser != "kb" {
		t.Fatalf("profile fields wrong: %+v", s.Profile)
	}
	if s.Profile.SSHPort != 22 || s.Profile.IdentityFile != "/Users/me/.ssh/id_ed25519" {
		t.Fatalf("profile port/identity wrong: %+v", s.Profile)
	}
	if len(s.CredentialChoices) != 2 || s.CredentialChoices[0].ID != "sshAgent" || s.CredentialChoices[1].Path != "/Users/me/.ssh/id_ed25519" {
		t.Fatalf("credential choices wrong: %+v", s.CredentialChoices)
	}
	if s.Assessment.OK || s.Assessment.State != "needs_setup" || len(s.Assessment.IdentityFiles) != 2 {
		t.Fatalf("assessment wrong: %+v", s.Assessment)
	}
	if len(s.Assessment.Missing) != 1 || s.Assessment.Missing[0] != "ssh_host" {
		t.Fatalf("assessment.missing wrong: %+v", s.Assessment.Missing)
	}
	if len(s.SSHConfigSources) != 1 || !s.SSHConfigSources[0].Exists {
		t.Fatalf("ssh config sources wrong: %+v", s.SSHConfigSources)
	}
	if s.StorePath == "" || s.ProfilesDir == "" {
		t.Fatalf("store/profiles paths missing")
	}
}

func TestOrDash(t *testing.T) {
	if orDash("") != "-" || orDash("x") != "x" {
		t.Fatal("orDash wrong")
	}
}

func TestLoadConnStoreTreatsEmptyFileAsEmptyStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "connections.json")
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", storePath)
	if err := os.WriteFile(storePath, nil, 0o600); err != nil {
		t.Fatalf("write empty store: %v", err)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("load empty store: %v", err)
	}
	if len(store.Profiles) != 0 || len(store.Chains) != 0 || store.Active != "" || store.ActiveChain != "" {
		t.Fatalf("empty store should be zero value: %+v", store)
	}
}

func TestConnectionsSetUseAndCurrentProfile(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "connections.json")
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", storePath)

	rc := cmdConnections([]string{
		"set", "linode-a",
		"--host", "203.0.113.10",
		"--user", "kb",
		"--identity-file", "/Users/me/.ssh/id_ed25519",
		"--description", "first linode",
		"--tag", "linode",
		"-l", "env=prod",
		"--set-label", "role=jump",
		"--active",
	})
	if rc != 0 {
		t.Fatalf("connections set rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore: %v", err)
	}
	if store.Active != "linode-a" || len(store.Profiles) != 1 {
		t.Fatalf("store after set wrong: %+v", store)
	}
	profile := store.Profiles[0]
	if profile.SSHHost != "203.0.113.10" || profile.SSHUser != "kb" || profile.SSHPort != 22 {
		t.Fatalf("profile SSH fields wrong: %+v", profile)
	}
	if profile.IdentityFile != "/Users/me/.ssh/id_ed25519" || profile.NinePPort != 5640 {
		t.Fatalf("profile defaults wrong: %+v", profile)
	}
	if profile.Version != connLatestVersion || len(profile.Capabilities) == 0 {
		t.Fatalf("profile version/capabilities wrong: %+v", profile)
	}
	if len(profile.Tags) != 1 || profile.Tags[0] != "linode" {
		t.Fatalf("profile tags wrong: %+v", profile.Tags)
	}
	if profile.Labels["env"] != "prod" || profile.Labels["role"] != "jump" {
		t.Fatalf("profile labels wrong: %+v", profile.Labels)
	}

	rc = cmdConnections([]string{"set", "--host", "203.0.113.20", "--user", "root", "linode-b"})
	if rc != 0 {
		t.Fatalf("connections set with flags-before-name rc=%d", rc)
	}
	rc = cmdConnections([]string{"use", "linode-b"})
	if rc != 0 {
		t.Fatalf("connections use rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore after use: %v", err)
	}
	if store.Active != "linode-b" || len(store.Profiles) != 2 {
		t.Fatalf("store after use wrong: %+v", store)
	}
	current, err := activeOrNamedProfile(store, "")
	if err != nil {
		t.Fatalf("activeOrNamedProfile: %v", err)
	}
	if current.Name != "linode-b" || current.SSHHost != "203.0.113.20" {
		t.Fatalf("current profile wrong: %+v", current)
	}

	rc = cmdConnections([]string{"set", "linode-b", "--identity-file", "/Users/me/.ssh/linode-b.key"})
	if rc != 0 {
		t.Fatalf("connections partial update rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore after partial update: %v", err)
	}
	updated, _, ok := findProfile(store, "linode-b")
	if !ok {
		t.Fatal("linode-b missing after partial update")
	}
	if updated.SSHHost != "203.0.113.20" || updated.SSHUser != "root" {
		t.Fatalf("partial update should preserve SSH fields: %+v", updated)
	}
	if updated.IdentityFile != "/Users/me/.ssh/linode-b.key" {
		t.Fatalf("partial update did not set identity file: %+v", updated)
	}
}

func TestConnectionsUseRejectsMissingProfile(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnections([]string{"use", "missing"}); rc != 1 {
		t.Fatalf("missing profile use rc=%d want 1", rc)
	}
}

func TestConnectionsRejectUnknownSubcommand(t *testing.T) {
	if rc := cmdConnections([]string{"bogus"}); rc != 2 {
		t.Fatalf("unknown subcommand rc=%d want 2", rc)
	}
}

func TestConnectionAliasIsTopLevelCommand(t *testing.T) {
	if !slices.Contains(topLevelCommands, "connection") {
		t.Fatal("topLevelCommands should include singular connection alias")
	}
}

func TestConnectionVersionRegistry(t *testing.T) {
	versions := supportedConnectionVersions()
	if !slices.Contains(versions, connVersionV1) || !slices.Contains(versions, connVersionV2) {
		t.Fatalf("expected v1 and v2 in registry: %v", versions)
	}
	v2, ok := connectionVersionSpec(connVersionV2)
	if !ok {
		t.Fatal("missing v2 spec")
	}
	var hasReport bool
	for _, cap := range v2.Capabilities {
		if cap.ID == "connection.capability.report" && cap.Native {
			hasReport = true
		}
	}
	if !hasReport {
		t.Fatalf("v2 should expose native capability report: %+v", v2.Capabilities)
	}
}

func TestConnectionsCapabilitiesCommand(t *testing.T) {
	if rc := cmdConnections([]string{"capabilities", "--version", connVersionV2}); rc != 0 {
		t.Fatalf("capabilities command rc=%d", rc)
	}
	if rc := cmdConnections([]string{"capabilities", "--version", "bad"}); rc != 1 {
		t.Fatalf("bad capabilities version rc=%d want 1", rc)
	}
}

func TestConnectionsDowngradeRequiresAllowLossAndUpgradeRestoresCapabilities(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "connections.json")
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", storePath)

	if rc := cmdConnections([]string{"set", "linode-a", "--host", "203.0.113.10", "--active"}); rc != 0 {
		t.Fatalf("set rc=%d", rc)
	}
	if rc := cmdConnections([]string{"downgrade", "linode-a", "--to", connVersionV1}); rc != 1 {
		t.Fatalf("downgrade without allow-loss rc=%d want 1", rc)
	}
	if rc := cmdConnections([]string{"downgrade", "linode-a", "--to", connVersionV1, "--allow-loss"}); rc != 0 {
		t.Fatalf("downgrade with allow-loss rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("load after downgrade: %v", err)
	}
	downgraded, _, ok := findProfile(store, "linode-a")
	if !ok {
		t.Fatal("linode-a missing after downgrade")
	}
	if downgraded.Version != connVersionV1 {
		t.Fatalf("version after downgrade=%q", downgraded.Version)
	}
	for _, cap := range downgraded.Capabilities {
		if cap.ID == "connection.capability.report" {
			t.Fatalf("v1 downgrade should drop v2 capability: %+v", downgraded.Capabilities)
		}
	}

	if rc := cmdConnections([]string{"upgrade", "linode-a", "--to", connVersionV2}); rc != 0 {
		t.Fatalf("upgrade rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatalf("load after upgrade: %v", err)
	}
	upgraded, _, ok := findProfile(store, "linode-a")
	if !ok {
		t.Fatal("linode-a missing after upgrade")
	}
	if upgraded.Version != connVersionV2 {
		t.Fatalf("version after upgrade=%q", upgraded.Version)
	}
	if len(upgraded.Capabilities) <= len(downgraded.Capabilities) {
		t.Fatalf("upgrade should restore newer capabilities: before=%d after=%d", len(downgraded.Capabilities), len(upgraded.Capabilities))
	}
}

func TestConnectionsMigrateDryRunDoesNotWrite(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "connections.json")
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", storePath)
	if rc := cmdConnections([]string{"set", "dry", "--host", "127.0.0.1", "--active"}); rc != 0 {
		t.Fatalf("set rc=%d", rc)
	}
	if rc := cmdConnections([]string{"downgrade", "dry", "--to", connVersionV1, "--allow-loss", "--dry-run"}); rc != 0 {
		t.Fatalf("dry-run downgrade rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("load after dry-run: %v", err)
	}
	profile, _, ok := findProfile(store, "dry")
	if !ok {
		t.Fatal("dry profile missing")
	}
	if profile.Version != connVersionV2 {
		t.Fatalf("dry-run should not change version, got %q", profile.Version)
	}
}
