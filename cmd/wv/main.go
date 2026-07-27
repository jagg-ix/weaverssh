// Command wv is the unified weaverssh front door.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"weaverssh/internal/app"
)

var (
	buildVersion string
	buildRelease string
	buildCommit string
	buildDirty string
	buildDate string
	buildTarget string
)

var vfsVerbs = map[string]bool{"view": true, "mount": true, "unmount": true, "umount": true, "sshfs": true, "status": true, "serve": true, "libvirt-xml": true}

func main() {
	args := os.Args[1:]
	if len(args) == 0 { printHelp(); os.Exit(2) }
	if strings.HasPrefix(args[0], "-") {
		switch args[0] { case "-h", "--help": printHelp(); return; case "-v", "--version": fmt.Println(versionString()); return; default: runApp("wv", app.RunWV, args); return }
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "agent": runApp("wv agent", app.RunAgent, rest)
	case "ssh-agent": os.Exit(cmdSSHAgent(rest))
	case "agent-bridge", "ssh-agent-bridge", "pageant-bridge": os.Exit(cmdAgentBridge(rest))
	case "authproof", "proof": os.Exit(cmdAuthproof(rest))
	case "reconnect-identity", "reconnect-id": os.Exit(cmdReconnectIdentity(rest))
	case "session-host": runSessionHostWithOriginRuntime(rest)
	case "attach": os.Exit(cmdAttach(rest))
	case "api": os.Exit(cmdSessionAPI(rest))
	case "api-contract", "contracts": os.Exit(cmdAPIContract(rest))
	case "origin-runtime", "origin-env": os.Exit(cmdOriginRuntime(rest))
	case "connectivity": os.Exit(cmdConnectivity(rest))
	case "mapreduce", "map-reduce", "compute": os.Exit(cmdMapReduceComplete(rest))
	case "exec": os.Exit(cmdSessionExec(rest))
	case "keygen": os.Exit(cmdKeygen(rest))
	case "connect": os.Exit(cmdConnect(rest))
	case "storage", "storage-adapter": os.Exit(cmdStorage(rest))
	case "session-proxy": os.Exit(cmdSessionProxy(rest))
	case "socks-connect": os.Exit(cmdSocksConnect(rest))
	case "socks-bind": os.Exit(cmdSocksBind(rest))
	case "socks-udp": os.Exit(cmdSocksUDP(rest))
	case "socks-policy": os.Exit(cmdSocksPolicyRuntimeComplete(rest))
	case "socket-engine", "sockets": os.Exit(cmdSocketEngineComplete(rest))
	case "proxy", "socks":
		rest = renameFlag(rest, "--target", "-agent"); rest = renameFlag(rest, "-target", "-agent"); runApp("wv proxy", app.RunSocks, rest)
	case "relay", "x11": runApp("wv relay", app.RunWV, rest)
	case "server": runApp("wv server", app.RunServer, rest)
	case "ls", "cat", "cp", "mkdir", "rm", "rmdir", "stat": os.Exit(cmdFileVerbComplete(verb, rest))
	case "mount": os.Exit(cmdMountComplete(rest))
	case "share":
		if len(rest) == 0 { fmt.Fprintln(os.Stderr, "usage: wv share DIR [--rw] [-listen ADDR]"); os.Exit(2) }
		dir := rest[0]; out := []string{"setroot"}
		for _, value := range rest[1:] { if value == "--rw" || value == "-rw" { out = append(out, "-read-write") } else { out = append(out, value) } }
		out = append(out, dir); os.Exit(runVFSCommand(out))
	case "connection", "connections": os.Exit(cmdConnectionsComplete(rest))
	case "chain", "chains": os.Exit(cmdChains(rest))
	case "pubsub": os.Exit(cmdPubSub(rest))
	case "compat", "compatibility": os.Exit(cmdCompat(rest))
	case "node-context", "context":
		if len(rest) > 0 && rest[0] == "sign-services" { os.Exit(cmdNodeContextSignServices(rest[1:])) }
		os.Exit(cmdNodeContext(rest))
	case "rules", "policy": os.Exit(cmdRulesComplete(rest))
	case "9p-adapter", "9p-provider", "vfs-provider": os.Exit(cmd9PAdapter(rest))
	case "instrument", "observe": os.Exit(cmdInstrument(rest))
	case "flow", "buffer", "buffers": os.Exit(cmdFlow(rest))
	case "status":
		if statusRequestsNodeSelection(rest) { os.Exit(cmdNodeStatus(rest)) }
		os.Exit(runVFSCommand(append([]string{"status"}, rest...)))
	case "install": os.Exit(deployInstall(rest))
	case "push-agent": os.Exit(pushAgent(rest))
	case "deps", "dependencies": os.Exit(cmdDeps(rest))
	case "build": os.Exit(cmdBuild(rest))
	case "completion": os.Exit(completion(rest))
	case "version", "--version", "-v": fmt.Println(versionString())
	case "help", "--help", "-h": printHelp()
	default:
		if vfsVerbs[verb] { os.Exit(runVFSCommand(args)) }
		fmt.Fprintf(os.Stderr, "wv: unknown command %q\nRun 'wv help' for usage.\n", verb); os.Exit(2)
	}
}

func runApp(prog string, fn func(), rest []string) { os.Args = append([]string{prog}, rest...); fn() }
func renameFlag(args []string, from, to string) []string { out := make([]string, len(args)); for index, value := range args { if value == from { out[index] = to } else if strings.HasPrefix(value, from+"=") { out[index] = to + strings.TrimPrefix(value, from) } else { out[index] = value } }; return out }

func versionString() string {
	version := strings.TrimSpace(buildVersion)
	if release := strings.TrimSpace(buildRelease); version != "" && release != "" { version += "-" + release }
	var details []string
	for _, entry := range [][2]string{{"commit", buildCommit}, {"dirty", buildDirty}, {"date", buildDate}, {"target", buildTarget}} { if value := strings.TrimSpace(entry[1]); value != "" { details = append(details, entry[0]+"="+value) } }
	if version != "" { if len(details) > 0 { return "weaverssh " + version + " (" + strings.Join(details, " ") + ")" }; return "weaverssh " + version }
	if info, ok := debug.ReadBuildInfo(); ok { if value := info.Main.Version; value != "" && value != "(devel)" { return "weaverssh " + value } }
	return "weaverssh (dev)"
}

func printHelp() {
	fmt.Print(`wv — weaverssh: a user-space data bus over SSH

Usage:
  wv <command> [options]

Dynamic session and credentials:
  keygen              Generate Ed25519 keys
  ssh-agent           Inspect and manage OpenSSH agent identities
  agent-bridge        Bridge a local ssh-agent socket to another agent (Windows OpenSSH/Pageant)
  authproof           Issue and verify short-lived runtime grants
  reconnect-identity  Issue and verify reconnect identities
  session-host        Allocate an isolated X display and serve capabilities
  attach              Attach through DISPLAY and publish a stable broker
  api                 Query the in-band session API
  api-contract        Validate and evolve standard API description contracts
  origin-runtime      Resolve native, WSL, Docker, Kubernetes, or VM environments
  connectivity        Diagnose optional SSH network underlays

Routed operations:
  exec                Run a named action on a signed node
  connect             Open routed TCP
  session-proxy       SOCKS5 CONNECT, BIND, and UDP ASSOCIATE listener
  socks-connect       Proof-authenticated SOCKS5 CONNECT client
  socks-bind          Proof-authenticated SOCKS5 BIND client
  socks-udp           Proof-authenticated SOCKS5 UDP client
  socks-policy        Manage proof principals, destinations, and capabilities
  socket-engine       Multi-listener engine with authenticated status/reload/stop

Policy:
  rules               Evaluate deterministic native policy rules and pipelines

Storage:
  storage             Inspect, query, mutate, and migrate registered storage engines

Files:
  ls NODE:/PATH
  cat NODE:/PATH
  stat [--json] NODE:/PATH
  cp [-r] [--replace-tree] [--no-preserve-metadata] SOURCE DESTINATION
  mkdir [-p] NODE:/PATH
  rm [-r] NODE:/PATH
  rmdir NODE:/PATH
  mount NODE:/ MOUNTPOINT

Transactional recursive copy preserves safe symlinks and mode/mtime metadata.
File payloads resume by offset across replacement transport generations.

Configuration and compute:
  mapreduce rules connection chain pubsub compat node-context api-contract
  origin-runtime 9p-adapter instrument flow deps install push-agent build completion

Infrastructure compatibility:
  agent proxy relay server share mount unmount sshfs status

Run 'wv <command> -h' for command-specific flags.
`)
}
