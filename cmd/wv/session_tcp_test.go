package main

import (
	"testing"

	"weaverssh/authproof"
)

func TestSessionProxyLoopbackPolicy(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:1080", "localhost:9000"} {
		if !isLoopbackListen(address) {
			t.Fatalf("expected loopback: %s", address)
		}
	}
	for _, address := range []string{"0.0.0.0:1080", "[::]:1080", "192.0.2.1:1080", ":1080"} {
		if isLoopbackListen(address) {
			t.Fatalf("unexpected loopback: %s", address)
		}
	}
}

func TestParseNodeCapabilitiesRequiresExplicitKnownServices(t *testing.T) {
	capabilities, err := parseNodeCapabilities("socks.proxy,vfs.mesh")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, capability := range capabilities {
		seen[capability] = true
	}
	for _, required := range []string{
		authproof.CapabilityNodeContext,
		authproof.CapabilitySocksProxy,
		authproof.CapabilityVFSMesh,
	} {
		if !seen[required] {
			t.Fatalf("missing capability %s in %v", required, capabilities)
		}
	}
	if _, err := parseNodeCapabilities("exec.shell"); err == nil {
		t.Fatal("unsupported capability was accepted")
	}
}
