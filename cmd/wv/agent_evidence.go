package main

import (
	"context"
	"encoding/json"
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
	case "remote-status":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceRemoteStatus, args[1:])
	case "remote-flush":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceRemoteFlush, args[1:])
	case "snapshot":
		return cmdAgentEvidenceControl(socketcontrol.ActionEvidenceSnapshot, args[1:])
	case "snapshot-verify":
		return cmdAgentEvidenceSnapshotVerify(args[1:])
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
	timeout := fs.Duration("timeout", 45*time.Second, "control call timeout")
	limit := fs.Int("limit", 100, "maximum exported records (1-1000)")
	output := fs.String("out", "", "output file for signed snapshot")
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
	if action == socketcontrol.ActionEvidenceSnapshot && strings.TrimSpace(*output) == "" {
		fmt.Fprintln(os.Stderr, "wv agent-evidence snapshot: --out is required")
		return 2
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
		if err := socketcontrol.DecodePayload(response, &status); err != nil { return commandError(err) }
		return printJSON(status)
	case socketcontrol.ActionEvidenceVerify:
		var report evidencebinding.VerificationReport
		if err := socketcontrol.DecodePayload(response, &report); err != nil { return commandError(err) }
		return printJSON(report)
	case socketcontrol.ActionEvidenceExport:
		var exported evidencebinding.AgentJournalExport
		if err := socketcontrol.DecodePayload(response, &exported); err != nil { return commandError(err) }
		return printJSON(exported)
	case socketcontrol.ActionEvidenceRemoteStatus:
		var status evidencebinding.AgentRemoteQueueStatus
		if err := socketcontrol.DecodePayload(response, &status); err != nil { return commandError(err) }
		return printJSON(status)
	case socketcontrol.ActionEvidenceRemoteFlush:
		var report evidencebinding.AgentRemoteFlushReport
		if err := socketcontrol.DecodePayload(response, &report); err != nil { return commandError(err) }
		return printJSON(report)
	case socketcontrol.ActionEvidenceSnapshot:
		var snapshot evidencebinding.AgentJournalSnapshot
		if err := socketcontrol.DecodePayload(response, &snapshot); err != nil { return commandError(err) }
		if _, err := evidencebinding.VerifyAgentJournalSnapshot(snapshot); err != nil { return commandError(err) }
		if err := writePrivateJSON(strings.TrimSpace(*output), snapshot); err != nil { return commandError(err) }
		fmt.Println(strings.TrimSpace(*output))
		return 0
	default:
		return 2
	}
}

func cmdAgentEvidenceSnapshotVerify(args []string) int {
	fs := flag.NewFlagSet("agent-evidence snapshot-verify", flag.ContinueOnError)
	path := fs.String("file", "", "signed snapshot JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return 2
	}
	data, err := os.ReadFile(strings.TrimSpace(*path))
	if err != nil { return commandError(err) }
	snapshot, err := evidencebinding.DecodeAgentJournalSnapshot(data)
	if err != nil { return commandError(err) }
	report, err := evidencebinding.VerifyAgentJournalSnapshot(snapshot)
	if err != nil { return commandError(err) }
	return printJSON(report)
}

func writePrivateJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return err }
	payload = append(payload, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { return err }
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil { return err }
	if _, err := file.Write(payload); err != nil { _ = file.Close(); return err }
	if err := file.Sync(); err != nil { _ = file.Close(); return err }
	if err := file.Close(); err != nil { return err }
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(temporary, path); err != nil { return err }
	}
	return os.Chmod(path, 0o600)
}

func commandError(err error) int {
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func defaultAgentEvidenceClientConfig() (string, string, string) {
	if network := strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_CONTROL_NETWORK")); network != "" {
		return network, strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_CONTROL")), strings.TrimSpace(os.Getenv("WEAVERSSH_AGENT_EVIDENCE_TOKEN_FILE"))
	}
	root := strings.TrimSpace(os.Getenv(app.AgentEmbeddedImmuDBPathEnv))
	if runtime.GOOS == "windows" {
		if root == "" { root = filepath.Join(os.TempDir(), "weaverssh-agent-evidence") }
		return "tcp", "127.0.0.1:19742", filepath.Join(root, "control.token")
	}
	if root == "" { root = filepath.Join(os.TempDir(), "weaverssh-agent-evidence") }
	return "unix", filepath.Join(root, "control.sock"), filepath.Join(root, "control.token")
}

func printAgentEvidenceUsage() {
	fmt.Fprint(os.Stderr, `usage:
  wv agent-evidence serve --embedded-immudb-path PATH [--remote-providers FILE] [agent options]
  wv agent-evidence status [--control PATH --token-file FILE]
  wv agent-evidence verify [--control PATH --token-file FILE]
  wv agent-evidence export [--limit N --control PATH --token-file FILE]
  wv agent-evidence remote-status [--control PATH --token-file FILE]
  wv agent-evidence remote-flush [--control PATH --token-file FILE]
  wv agent-evidence snapshot --out FILE [--control PATH --token-file FILE]
  wv agent-evidence snapshot-verify --file FILE
`)
}
