package connectionscan

import (
	"path/filepath"
	"testing"
)

func hasHost(entries []SSHClientConfig, host string) (SSHClientConfig, bool) {
	for _, e := range entries {
		if e.HostName == host {
			return e, true
		}
	}
	return SSHClientConfig{}, false
}

func TestSSHConfigFromSpecPath(t *testing.T) {
	entries, err := SSHConfigFromSpec("testdata/mesh.sshconfig")
	if err != nil {
		t.Fatal(err)
	}
	compute, ok := hasHost(entries, "10.0.0.5")
	if !ok {
		t.Fatalf("compute host not parsed from fixture: %+v", entries)
	}
	if compute.User != "builder" || compute.ProxyJump != "jump" {
		t.Fatalf("compute entry wrong: %+v", compute)
	}
	if _, ok := hasHost(entries, "bastion.example.net"); !ok {
		t.Fatalf("jump/bastion host not parsed")
	}
}

func TestSSHConfigFromSpecDefaultsMerge(t *testing.T) {
	entries, err := SSHConfigFromSpec("path:testdata/defaults.sshconfig")
	if err != nil {
		t.Fatal(err)
	}
	// Host * defaults (User=defaultuser) fold into concrete hosts, and the
	// wildcard "Host *" itself is not emitted as a connectable entry.
	db, ok := hasHost(entries, "db.internal")
	if !ok || db.User != "defaultuser" {
		t.Fatalf("defaults not merged into db: %+v ok=%v", db, ok)
	}
	for _, e := range entries {
		for _, a := range e.HostAliases {
			if a == "*" {
				t.Fatalf("wildcard host leaked as an entry: %+v", e)
			}
		}
	}
}

func TestSSHConfigFromSpecExec(t *testing.T) {
	abs, err := filepath.Abs("testdata/mesh.sshconfig")
	if err != nil {
		t.Fatal(err)
	}
	// exec: a program supplies the config on stdout (the "library"/dynamic source).
	entries, err := SSHConfigFromSpec("exec:cat " + abs)
	if err != nil {
		t.Fatalf("exec source: %v", err)
	}
	if _, ok := hasHost(entries, "10.0.0.5"); !ok {
		t.Fatalf("exec source did not yield the fixture hosts: %+v", entries)
	}
}

func TestSSHConfigFromSpecErrors(t *testing.T) {
	if _, err := SSHConfigFromSpec("path:testdata/does-not-exist"); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := SSHConfigFromSpec("exec:"); err == nil {
		t.Fatal("expected error for empty exec command")
	}
}

func TestDiscoverFromSpecProfiles(t *testing.T) {
	t.Setenv("WEAVERSSH_DISABLE_SYSTEM_KNOWN_HOSTS", "1")
	t.Setenv("HOME", t.TempDir()) // isolate ~/.ssh/known_hosts
	res, err := DiscoverFrom("testdata/mesh.sshconfig")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range res.Profiles {
		if p.Host == "10.0.0.5" && p.Source == "ssh-config" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DiscoverFrom did not surface the fixture profile: %+v", res.Profiles)
	}
}
