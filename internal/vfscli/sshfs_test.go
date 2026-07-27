package vfscli

import (
	"strings"
	"testing"
)

func TestBuildSshfsArgs(t *testing.T) {
	args := buildSshfsArgs(sshfsOptions{
		remote:      "user@host:/srv",
		mountpoint:  "/mnt/r",
		readOnly:    true,
		volumeName:  "remote",
		extraOpts:   []string{"cache_timeout=20"},
		passthrough: []string{"-d"},
	}, "ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p")

	joined := strings.Join(args, " ")
	wantSubstrings := []string{
		"user@host:/srv /mnt/r",
		"ProxyCommand=ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p",
		"-o reconnect",
		"-o ServerAliveInterval=15",
		"-o ro",
		"-o volname=remote",
		"-o cache_timeout=20",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(joined, w) {
			t.Errorf("args missing %q\n got: %s", w, joined)
		}
	}
	// First two tokens must be the positional remote + mountpoint.
	if args[0] != "user@host:/srv" || args[1] != "/mnt/r" {
		t.Fatalf("positional order wrong: %v", args[:2])
	}
	// Passthrough comes last, verbatim.
	if args[len(args)-1] != "-d" {
		t.Fatalf("passthrough not last: %v", args)
	}
}

func TestBuildSshfsArgsNoProxy(t *testing.T) {
	args := buildSshfsArgs(sshfsOptions{remote: "u@h:/p", mountpoint: "/m"}, "")
	if strings.Contains(strings.Join(args, " "), "ProxyCommand") {
		t.Fatalf("expected no ProxyCommand when conn empty: %v", args)
	}
}

func TestResolveConnector(t *testing.T) {
	if c, err := resolveConnector("", ""); err != nil || c != "" {
		t.Fatalf("empty socks => direct: c=%q err=%v", c, err)
	}
	// Custom template: %s expands to the proxy, ssh tokens are preserved.
	c, err := resolveConnector("connect-via %s then %h:%p", "10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if c != "connect-via 10.0.0.1:1080 then %h:%p" {
		t.Fatalf("template substitution wrong: %q", c)
	}
	// Auto path: whatever connector is found must reference the proxy and the
	// ssh host/port tokens (skip if neither connector exists in PATH).
	if c, err := resolveConnector("", "127.0.0.1:1080"); err == nil {
		if !strings.Contains(c, "127.0.0.1:1080") || !strings.Contains(c, "%h") || !strings.Contains(c, "%p") {
			t.Fatalf("auto connector malformed: %q", c)
		}
	}
}

func TestShellJoinQuotesSpaces(t *testing.T) {
	got := shellJoin([]string{"sshfs", "u@h:/p", "-o", "ProxyCommand=nc -X 5 -x a:1 %h %p"})
	if !strings.Contains(got, "'ProxyCommand=nc -X 5 -x a:1 %h %p'") {
		t.Fatalf("spaced token not quoted: %s", got)
	}
}
