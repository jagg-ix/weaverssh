package connectionscan

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes content to path, creating parent dirs, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findProfile(profiles []DiscoveredProfile, host string) (DiscoveredProfile, bool) {
	for _, p := range profiles {
		if p.Host == host {
			return p, true
		}
	}
	return DiscoveredProfile{}, false
}

func TestDiscoverAcrossSources(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("WEAVERSSH_DISABLE_SYSTEM_SSH_CONFIG", "1")
	t.Setenv("WEAVERSSH_DISABLE_SYSTEM_KNOWN_HOSTS", "1")

	// 1. OpenSSH ssh_config with an Include.
	writeFile(t, filepath.Join(home, ".ssh", "config"), `
Host myserver
    HostName server.example.com
    User admin
    Port 2200
    IdentityFile ~/.ssh/id_work

Include ~/.ssh/config.d/*.conf
`)
	writeFile(t, filepath.Join(home, ".ssh", "config.d", "extra.conf"), `
Host included-host
    HostName extra.example.com
    User svc
`)

	// 2. known_hosts (plain + [host]:port form + a hashed entry that must be skipped).
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), `
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA
[gitlab.example.com]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAA
|1|abc=|def= ssh-ed25519 AAAAhashedhostmustbeskipped
`)

	// 3. PuTTY sessions from a JSON fixture (registry-independent path).
	puttyJSON := filepath.Join(home, "putty.json")
	writeFile(t, puttyJSON, `{"sessions":[{"name":"work-box","host_name":"putty.example.com","user":"root","port":22}]}`)
	t.Setenv("WEAVERSSH_PUTTY_SESSIONS_JSON", puttyJSON)

	res := Discover()

	// ssh_config Host block
	p, ok := findProfile(res.Profiles, "server.example.com")
	if !ok {
		t.Fatalf("ssh_config host not discovered; profiles=%+v", res.Profiles)
	}
	if p.User != "admin" || p.Port != 2200 || p.Source != "ssh-config" {
		t.Fatalf("ssh_config profile wrong: %+v", p)
	}
	if p.IdentityFile == "" {
		t.Fatalf("expected identity file resolved, got empty: %+v", p)
	}

	// Include resolution
	if _, ok := findProfile(res.Profiles, "extra.example.com"); !ok {
		t.Fatalf("included ssh_config host not discovered; profiles=%+v", res.Profiles)
	}

	// known_hosts plain + bracket:port
	if _, ok := findProfile(res.Profiles, "github.com"); !ok {
		t.Fatalf("known_hosts plain host not discovered")
	}
	if gp, ok := findProfile(res.Profiles, "gitlab.example.com"); !ok || gp.Port != 2222 {
		t.Fatalf("known_hosts [host]:port not discovered correctly: %+v ok=%v", gp, ok)
	}

	// hashed known_hosts entry must not surface
	for _, kh := range res.KnownHosts {
		if kh.Host == "" || kh.Host[0] == '|' {
			t.Fatalf("hashed known_hosts entry leaked: %+v", kh)
		}
	}

	// PuTTY session
	if pp, ok := findProfile(res.Profiles, "putty.example.com"); !ok || pp.User != "root" || pp.Source != "putty" {
		t.Fatalf("putty session not discovered correctly: %+v ok=%v", pp, ok)
	}
}

func TestDiscoverEmptyHomeIsClean(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("WEAVERSSH_DISABLE_SYSTEM_SSH_CONFIG", "1")
	t.Setenv("WEAVERSSH_DISABLE_SYSTEM_KNOWN_HOSTS", "1")
	res := Discover()
	if len(res.Profiles) != 0 {
		t.Fatalf("expected no profiles from empty home, got %+v", res.Profiles)
	}
}
