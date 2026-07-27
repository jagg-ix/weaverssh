package main

import "testing"

func TestCompleteTopLevelCommandCatalog(t *testing.T) {
	present := make(map[string]bool, len(topLevelCommands))
	for _, command := range topLevelCommands {
		if present[command] {
			t.Fatalf("duplicate command %q", command)
		}
		present[command] = true
	}
	for _, command := range []string{
		"ssh-agent", "session-host", "attach", "api", "mapreduce", "keygen",
		"connect", "session-proxy", "socks-connect", "socks-bind", "socks-udp",
		"socks-policy", "socket-engine", "chain", "stat", "rmdir", "view", "serve",
		"umount", "libvirt-xml", "authproof", "proof", "reconnect-identity",
		"reconnect-id",
	} {
		if !present[command] {
			t.Errorf("command %q missing from completion catalog", command)
		}
	}
}
