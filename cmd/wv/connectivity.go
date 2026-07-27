package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/connectivity"
	"weaverssh/sessionapi"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

func cmdConnectivity(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printConnectivityUsage()
		return 0
	}
	if args[0] != "check" {
		fmt.Fprintf(os.Stderr, "connectivity: unknown command %q\n", args[0])
		printConnectivityUsage()
		return 2
	}
	return cmdConnectivityCheck(args[1:])
}

func printConnectivityUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  wv connectivity check --ssh-host HOST [--underlay LABEL] [options]

The command resolves HOST with ssh -G, opens the resolved TCP endpoint, verifies
an SSH banner, and optionally checks the active local WeaverSSH broker. The
underlay label and all external tunnel state are informational and never
authorize WeaverSSH operations.`)
}

func cmdConnectivityCheck(args []string) int {
	fs := flag.NewFlagSet("connectivity check", flag.ContinueOnError)
	underlay := fs.String("underlay", "ssh", "informational network underlay label")
	sshHost := fs.String("ssh-host", "", "OpenSSH host or alias")
	overlayAddress := fs.String("overlay-address", "", "expected resolved overlay address")
	sshBinary := fs.String("ssh-bin", "ssh", "OpenSSH client executable")
	timeout := fs.Duration("timeout", 5*time.Second, "per-check timeout")
	jsonOutput := fs.Bool("json", false, "emit stable JSON")
	requireReady := fs.Bool("require-weaverssh", false, "fail unless the local WeaverSSH API is ready")
	fs.Usage = func() { printConnectivityUsage(); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*sshHost) == "" {
		fs.Usage()
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "connectivity: --timeout must be positive")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
	defer cancel()
	result, err := connectivity.CheckConnectivity(ctx, connectivity.Options{
		Underlay: *underlay, SSHHost: *sshHost, OverlayAddress: *overlayAddress,
		SSHBinary: *sshBinary, Timeout: *timeout,
	})
	if err != nil {
		result.Checks = append(result.Checks, connectivity.Check{Name: "connectivity", OK: false, Detail: err.Error()})
	}

	result.WeaverSSHChecked = true
	readyCtx, readyCancel := context.WithTimeout(context.Background(), *timeout)
	result.WeaverSSHReady, result.WeaverSSHDetail = checkLocalWeaverSSH(readyCtx)
	readyCancel()
	result.Checks = append(result.Checks, connectivity.Check{
		Name: "weaverssh-api", OK: result.WeaverSSHReady, Detail: result.WeaverSSHDetail,
	})

	if *jsonOutput {
		payload, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "connectivity: encode result: %v\n", marshalErr)
			return 1
		}
		fmt.Println(string(payload))
	} else {
		fmt.Printf("underlay: %s\nssh host: %s\nresolved: %s:%d\n", result.Underlay, result.SSHHost, result.ResolvedHost, result.ResolvedPort)
		fmt.Printf("overlay reachable: %t\nssh reachable: %t\nweaverssh ready: %t\n", result.OverlayReachable, result.SSHReachable, result.WeaverSSHReady)
		for _, check := range result.Checks {
			status := "ok"
			if !check.OK {
				status = "not-ok"
			}
			fmt.Printf("- %s: %s", check.Name, status)
			if check.Detail != "" {
				fmt.Printf(" (%s)", check.Detail)
			}
			fmt.Println()
		}
	}

	if err != nil || !result.OverlayReachable || !result.SSHReachable || (*requireReady && !result.WeaverSSHReady) {
		return 1
	}
	return 0
}

func checkLocalWeaverSSH(ctx context.Context) (bool, string) {
	state, err := sessionbroker.ActiveState()
	if err != nil {
		return false, err.Error()
	}
	conn, err := sessionbroker.Dial(ctx, "unix", state.Socket, sessionbroker.OpenRequest{
		Node: state.Node, Service: sessionmux.ServiceControl,
	})
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	var snapshot sessionapi.Snapshot
	if err := sessionapi.CallStream(ctx, conn, sessionapi.MethodDescribe, nil, &snapshot); err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("active node %s", state.Node)
}
