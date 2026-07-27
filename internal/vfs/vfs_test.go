package vfs

import (
	"path/filepath"
	"testing"
)

func TestIsVFS(t *testing.T) {
	cases := map[string]bool{
		"vfs://":            true,
		"vfs://a/b.txt":     true,
		"vfs:///x":          true,
		"vfs::origin:/x":    true,
		"node2:/var/log/x":  true,
		"origin:~/app.log":  true,
		"kb@node1:/tmp/x":   true,
		"./local":           false,
		"/abs/path":         false,
		"http://host/thing": false,
	}
	for in, want := range cases {
		if got := IsVFS(in); got != want {
			t.Errorf("IsVFS(%q)=%v want %v", in, got, want)
		}
	}
}

func TestParsePath(t *testing.T) {
	t.Setenv(EnvOriginNode, "workstation")
	t.Setenv(EnvEndpointNode, "linode-b")
	t.Setenv(EnvChainNodes, "workstation,linode-a,linode-b")
	ok := map[string]string{
		"vfs://":                      "",
		"vfs:///":                     "",
		"vfs://workinfo.txt":          "workinfo.txt",
		"vfs://region-a/":             "region-a",
		"vfs:///docs/note":            "docs/note",
		"vfs://a/b/c":                 "a/b/c",
		"vfs::origin:/logdir/node":    ".wv/nodes/workstation/logdir/node",
		"vfs::endpoint:/tmp/out.bin":  ".wv/nodes/linode-b/tmp/out.bin",
		"vfs::node/linode-a:/var/log": ".wv/nodes/linode-a/var/log",
		"node2:/var/log/app-4g.log":   ".wv/nodes/node2/var/log/app-4g.log",
		"origin:~/app-4g.log":         ".wv/nodes/workstation/~/app-4g.log",
		"kb@node1:relative/file":      ".wv/nodes/kb@node1/relative/file",
	}
	for in, want := range ok {
		got, err := ParsePath(in)
		if err != nil {
			t.Errorf("ParsePath(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParsePath(%q)=%q want %q", in, got, want)
		}
	}
	for _, bad := range []string{"local", "./build:artifact", "/tmp/a:b", `C:\tmp\x`, "ssh://host/path", "vfs://../escape", "vfs://a/../../b", "vfs:::/missing-node", "vfs::bad/node:/x"} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("ParsePath(%q) expected error", bad)
		}
	}
}

func TestEndpointDefaults(t *testing.T) {
	t.Setenv(EnvEndpoint, "")
	t.Setenv(EnvSocks, "")
	ep, socks := Endpoint()
	if ep != DefaultEndpoint || socks != "" {
		t.Fatalf("Endpoint()=%q,%q want %q,\"\"", ep, socks, DefaultEndpoint)
	}
	t.Setenv(EnvEndpoint, "10.0.0.1:9999")
	t.Setenv(EnvSocks, "127.0.0.1:1080")
	ep, socks = Endpoint()
	if ep != "10.0.0.1:9999" || socks != "127.0.0.1:1080" {
		t.Fatalf("Endpoint()=%q,%q want overrides", ep, socks)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEAVERSSH_VFS_CONFIG", filepath.Join(dir, "vfs.json"))
	want := Config{Root: "/srv/shared", Listen: "127.0.0.1:5640"}
	if err := SaveConfig(want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != want {
		t.Fatalf("LoadConfig=%+v want %+v", got, want)
	}
}

func TestResolveNodeRefUsesAliasesAndEnvironment(t *testing.T) {
	t.Setenv(EnvOriginNode, "origin-box")
	t.Setenv(EnvCurrentNode, "edge-hop")
	t.Setenv(EnvEndpointNode, "target-box")
	for in, want := range map[string]string{
		"origin":   "origin-box",
		"self":     "edge-hop",
		"local":    "edge-hop",
		"endpoint": "target-box",
		"target":   "target-box",
	} {
		got, err := ResolveNodeRef(in)
		if err != nil {
			t.Fatalf("ResolveNodeRef(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ResolveNodeRef(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseSCPStyleNodePath(t *testing.T) {
	t.Setenv(EnvOriginNode, "laptop")
	np, ok, err := ParseSCPStyleNodePath("origin:~/app-4g.log")
	if err != nil {
		t.Fatalf("ParseSCPStyleNodePath: %v", err)
	}
	if !ok {
		t.Fatal("expected SCP-style node reference")
	}
	if np.Node != "laptop" || np.Path != "~/app-4g.log" || np.NamespacePath != ".wv/nodes/laptop/~/app-4g.log" {
		t.Fatalf("unexpected parsed node path: %+v", np)
	}
	if _, ok, err := ParseSCPStyleNodePath("/var/log/app-4g.log"); err != nil || ok {
		t.Fatalf("local absolute path should not parse as SCP-style: ok=%v err=%v", ok, err)
	}
}

func TestIPAddressNodePaths(t *testing.T) {
	// IPv4 needs no brackets; IPv6 must be bracketed ([addr]); user@ is allowed.
	ok := map[string]string{
		"192.0.2.10:/var/log/app.log":     ".wv/nodes/192.0.2.10/var/log/app.log",
		"kb@192.0.2.10:/tmp/x":            ".wv/nodes/kb@192.0.2.10/tmp/x",
		"[2001:db8::1]:/var/log":          ".wv/nodes/2001:db8::1/var/log",
		"user@[fe80::1]:~/app.log":        ".wv/nodes/user@fe80::1/~/app.log",
		"vfs::[2001:db8::1]:/tmp/out.bin": ".wv/nodes/2001:db8::1/tmp/out.bin",
		"vfs::192.0.2.5:/etc/hosts":       ".wv/nodes/192.0.2.5/etc/hosts",
	}
	for in, want := range ok {
		if !IsVFS(in) {
			t.Errorf("IsVFS(%q)=false want true", in)
		}
		got, err := ParsePath(in)
		if err != nil {
			t.Errorf("ParsePath(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParsePath(%q)=%q want %q", in, got, want)
		}
	}
	// Unbracketed IPv6 and malformed brackets must not be mistaken for VFS refs.
	for _, bad := range []string{"[2001:db8::1:/nopath", "[]:/x", "/tmp/a:b", "./x:y", `C:\tmp\x`} {
		if IsVFS(bad) {
			t.Errorf("IsVFS(%q)=true want false", bad)
		}
	}
}
