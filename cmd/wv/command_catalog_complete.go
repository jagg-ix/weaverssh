package main

import "sort"

var completeTopLevelCommands = []string{
	"9p-adapter", "9p-provider", "agent", "api", "api-contract", "attach", "audit", "authproof", "buffer",
	"buffers", "build", "cat", "chain", "chains", "chrono", "clock", "compat", "compatibility", "compliance",
	"completion", "compute", "connect", "connection", "connections", "connectivity", "context", "contracts", "cp",
	"cryptfs", "cryptsetup", "deps", "dependencies", "events", "evidence", "exec", "file-crypt", "flow", "grpc-mqtt", "grpc-mqtt-proof", "help", "install", "instrument",
	"keygen", "libvirt-xml", "ls", "luks", "luks-volume", "map-reduce", "mapreduce", "mcp", "mkdir", "mqtt-grpc", "mqtt-grpc-engine", "mqtt-grpc-proof",
	"mount", "node-context", "notary", "observe", "opa", "origin-env", "origin-runtime", "policy", "policy-admin", "policy-runtime", "policyctl", "proof", "proxy", "pubsub",
	"push-agent", "reconnect-id", "reconnect-identity", "rego", "relay", "rmdir", "rm",
	"rules", "serve", "server", "session-host", "session-proxy", "share", "socks",
	"socks-bind", "socks-connect", "socks-policy", "socks-udp", "socket-engine", "sockets",
	"ssh-agent", "sshfs", "stat", "status", "storage", "storage-adapter", "transfer", "umount", "union-vfs", "unmount", "version",
	"vfs-compose", "vfs-crypt", "vfs-provider", "view", "x11",
}

func init() {
	seen := make(map[string]bool, len(topLevelCommands)+len(completeTopLevelCommands))
	for _, command := range topLevelCommands { seen[command] = true }
	for _, command := range completeTopLevelCommands { if !seen[command] { topLevelCommands = append(topLevelCommands, command); seen[command] = true } }
	sort.Strings(topLevelCommands)
}
