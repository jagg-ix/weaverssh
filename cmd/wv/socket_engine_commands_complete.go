package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/socketengine"
)

func cmdSocketEngineComplete(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "init", "initialize":
			return cmdSocketEngineInit(args[1:])
		case "inspect", "show", "plan":
			return cmdSocketEngineInspect(args[1:])
		case "serve", "supervise", "run-controlled":
			return cmdSocketEngineServe(args[1:])
		case "status":
			return cmdSocketEngineControl("status", args[1:])
		case "reload":
			return cmdSocketEngineControl("reload", args[1:])
		case "stop":
			return cmdSocketEngineControl("stop", args[1:])
		case "help", "-h", "--help":
			printSocketEngineUsage()
			fmt.Fprint(os.Stdout, `
Configuration lifecycle:
  init [--out FILE]               emit a valid loopback-only starter config
  inspect CONFIG.json [--json]    validate and display the normalized plan

Authenticated runtime control:
  serve --config FILE [--control PATH] [--token-file FILE]
  status [--control PATH] [--token-file FILE]
  reload [--config FILE] [--control PATH] [--token-file FILE]
  stop [--control PATH] [--token-file FILE]
`)
			return 0
		}
	}
	return cmdSocketEngine(args)
}

func cmdSocketEngineInit(args []string) int {
	fs := flag.NewFlagSet("socket-engine init", flag.ContinueOnError)
	out := fs.String("out", "", "write starter configuration to file")
	force := fs.Bool("force", false, "replace existing output")
	listen := fs.String("listen", "tcp://127.0.0.1:1081", "starter listener URL")
	node := fs.String("node", "compute-node", "starter target node")
	target := fs.String("target", "127.0.0.1:22", "starter target HOST:PORT")
	name := fs.String("name", "ssh", "starter route name")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socket-engine init [--listen URL] [--node NODE] [--target HOST:PORT] [--out FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil { return 2 }
	if fs.NArg() != 0 { fs.Usage(); return 2 }
	config := socketengine.Config{
		Version: socketengine.ConfigVersion, LoadBalance: "least-connections",
		MaxConnections: 1024, QueueDepth: 32, ErrorQueueDepth: 128,
		ReadBufferBytes: 64 << 10, DialTimeout: "30s", TCPKeepAlive: "30s",
		ShutdownTimeout: "10s", RemoveStaleUnix: true, UnixMode: "0600",
		Routes: []socketengine.Route{{Name: strings.TrimSpace(*name), Listen: strings.TrimSpace(*listen), Node: strings.TrimSpace(*node), Network: "tcp", Address: strings.TrimSpace(*target)}},
	}
	if _, err := socketengine.Inspect(config); err != nil { fmt.Fprintf(os.Stderr, "socket-engine init: %v\n", err); return 2 }
	if strings.TrimSpace(*out) == "" {
		if err := emitJSONArtifact(os.Stdout, config); err != nil { fmt.Fprintf(os.Stderr, "socket-engine init: %v\n", err); return 1 }
		return 0
	}
	if err := writeJSONArtifact(*out, config, 0o644, *force); err != nil { fmt.Fprintf(os.Stderr, "socket-engine init: %v\n", err); return 1 }
	fmt.Printf("socket-engine init: wrote %s\n", *out)
	return 0
}

func cmdSocketEngineInspect(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("socket-engine inspect", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit normalized JSON plan")
	if err := fs.Parse(parseArgs); err != nil { return 2 }
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 { fmt.Fprintln(os.Stderr, "usage: wv socket-engine inspect CONFIG.json [--json]"); return 2 }
	config, err := socketengine.LoadConfigFile(operands[0])
	if err != nil { fmt.Fprintf(os.Stderr, "socket-engine inspect: %v\n", err); return 1 }
	plan, err := socketengine.Inspect(config)
	if err != nil { fmt.Fprintf(os.Stderr, "socket-engine inspect: %v\n", err); return 1 }
	if *jsonOut { return printJSON(plan) }
	fmt.Printf("socket engine plan\nversion: %s\nlisteners: %d\nload-balance: %s\nmax-connections: %d\n", plan.Version, len(plan.Addresses), plan.LoadBalance, plan.MaxConnections)
	for _, route := range plan.Routes { fmt.Printf("- %s %s -> %s %s/%s max=%d\n", route.Name, route.Listen, route.Node, route.Network, route.Address, route.MaxConnections) }
	return 0
}
