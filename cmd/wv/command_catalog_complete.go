package main

import "sort"

var completeTopLevelCommands = []string{
	"9p-adapter", "9p-provider", "agent", "api", "api-contract", "attach", "audit", "authproof", "buffer",
	"buffers", "build", "cat", "chain", "chains", "chrono", "clock", "compat", "compatibility", "compliance",
	"completion", "compute", "connect", "connection", "connections", "connectivity", "container-provider", "context", "contracts", "cp",
	"cryptfs", "cryptsetup", "deps", "dependencies", "events", "evidence", "exec", "file-crypt", "flow", "grpc-mqtt", "grpc-mqtt-proof", "help", "install", "instrument",
	"keygen", "libvirt-xml", "ls", "luks", "luks-volume", "map-reduce", "mapreduce", "mcp", "mkdir", "mqtt-grpc", "mqtt-grpc-engine", "mqtt-grpc-proof",
	"mount", "node-context", "notary", "observe", "opa", "orchestration", "origin-env", "origin-runtime", "policy", "policy-admin", "policy-runtime", "policyctl", "proof", "proxy", "pubsub",
	"push-agent", "reconnect-id", "reconnect-identity", "rego", "relay", "rmdir", "rm",
	"rules", "serve", "server", "session-host", "session-proxy", "share", "socks",
	"socks-bind", "socks-connect", "socks-policy", "socks-udp", "socket-engine", "sockets",
	"ssh-agent", "sshfs", "stat", "status", "storage", "storage-adapter", "stream-provider", "transfer", "umount", "union-vfs", "unmount", "version",
	"terminal", "term", "console",
	"vfs-compose", "vfs-crypt", "vfs-provider", "view", "x11",
}

func init() {
	seen := make(map[string]bool, len(topLevelCommands)+len(completeTopLevelCommands))
	for _, command := range topLevelCommands { seen[command] = true }
	for _, command := range completeTopLevelCommands { if !seen[command] { topLevelCommands = append(topLevelCommands, command); seen[command] = true } }
	sort.Strings(topLevelCommands)
}
