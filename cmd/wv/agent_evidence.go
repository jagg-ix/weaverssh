package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"weaverssh/evidencebinding"
	"weaverssh/internal/app"
	"weaverssh/socketcontrol"
)

func cmdAgentEvidence(args []string) int {
	if len(args) == 0 {
		printAgentEvidenceUsage()
		return 2
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "serve":
		runApp("wv agent-evidence serve", app.RunAgentEvidence, args[1:])
		return 0
	case "status":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceStatus, args[1:])
	case "verify":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceVerify, args[1:])
	case "export":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceExport, args[1:])
	case "help", "-h", "--help":
		printAgentEvidenceUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "wv agent-evidence: unknown action %q\n", args[0])
		printAgentEvidenceUsage()
		return 2
	}
}

func cmdAgentEvidenceControl(action string, args []string) int {
	fs := flag.NewFlagSet("agent-evidence "+action, flag.ContinueOnError)
	network, address, tokenFile := defaultAgentEvidenceClientConfig()
	fs.StringVar(&network, "control-network", network, "control network: unix or tcp")
	fs.StringVar(&address, "control", address, "agent evidence control socket/address")
	fs.StringVar(&tokenFile, "token-file", tokenFile, "HMAC control token file")
	timeout := fs.Duration("timeout", 15*time.Second, "control call timeout")
	limit := fs.Int("limit", 100, "maximum exported records (1-1000)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	config := ""
	if action == socketcontrol.ActionEvidenceExport {
		if *limit <= 0 || *limit > 1000 {
			fmt.Fprintln(os.Stderr, "wv agent-evidence export: --limit must be between 1 and 1000")
			return 2
		}
		config = strconv.Itoa(*limit)
	}
	token, err := readSocketControlToken(tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv agent-evidence %s: token: %v\n", action, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := socketcontrol.Call(ctx, strings.ToLower(strings.TrimSpace(network)), strings.TrimSpace(address), token, action, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv agent-evidence %s: %v\n", action, err)
		return 1
	}
	switch action {
	case socketcontrol.ActionEvidenceStatus:
		var status evidencebinding.AgentJournalStatus
		if err := socketcontrol.DecodePayload(response, &status); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return printJSON(status)
	case socketcontrol.ActionEvidenceVerify:
		var report evidencebinding.VerificationReport
		if err := socketcontrol.DecodePayload(response, &report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return printJSON(report)
	case socketcontrol.ActionEvidenceExport:
		var exported evidencebinding.AgentJournalExport
		if err := socketcontrol.DecodePayload(response, &exported); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return printJSON(exported)
	default:
		return 2
	}
}

func defaultAgentEvidenceClientConfig() (string, string, string) {
	if network := strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_CONTROL_NETWORK")); network != "" {
		return network, strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_CONTROL")), strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_TOKEN_FILE"))
	}
	root := strings.TrimSpace(os.Getenv(app.AgentEmbeddedImmuDBPathEnv))
	if runtime.GOOS == "windows" {
		if root == "" {
			root = filepath.Join(os.TempDir(), "weaverssh-agent-evidence")
		}
		return "tcp", "127.0.0.1:19742", filepath.Join(root, "control.token")
	}
	if root == "" {
		root = filepath.Join(os.TempDir(), "weaverssh-agent-evidence")
	}
	return "unix", filepath.Join(root, "control.sock"), filepath.Join(root, "control.token")
}

func printAgentEvidenceUsage() {
	fmt.Fprint(os.Stderr, `usage:
  wv agent-evidence serve --embedded-immudb-path PATH [agent options]
  wv agent-evidence status [--control PATH --token-file FILE]
  wv agent-evidence verify [--control PATH --token-file FILE]
  wv agent-evidence export [--limit N --control PATH --token-file FILE]
`)
}
