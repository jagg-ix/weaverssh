package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"weaverssh/containerexec"
	"weaverssh/containerstream"
	"weaverssh/sessionbroker"
	"weaverssh/sessionexec"
	"weaverssh/sessionmux"
)

func cmdSessionExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	inputFile := fs.String("input", "", "read bounded stdin from FILE; use - for stdin")
	timeout := fs.Duration("timeout", 30*time.Second, "broker and command timeout")
	jsonOut := fs.Bool("json", false, "emit response JSON")
	containerTarget := fs.String("container", "", "stream the action inside TARGET_URI through the provider-neutral process service")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv exec [--container TARGET_URI] [--input FILE] [--timeout DURATION] [--json] NODE ACTION [ARG ...]")
		fmt.Fprintln(os.Stderr, "ACTION is a policy-defined name, never an executable path or shell command.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 2 || *timeout <= 0 {
		fs.Usage()
		return 2
	}
	node := strings.TrimSpace(fs.Arg(0))
	action := strings.TrimSpace(fs.Arg(1))
	actionArgs := append([]string(nil), fs.Args()[2:]...)
	if node == "" || action == "" {
		fs.Usage()
		return 2
	}
	if strings.TrimSpace(*containerTarget) != "" && *jsonOut {
		fmt.Fprintln(os.Stderr, "wv exec: --json is not supported with streaming --container output")
		return 2
	}
	containerMode := strings.TrimSpace(*containerTarget) != ""
	if containerMode {
		target, parseErr := containerstream.ParseURI(*containerTarget)
		if parseErr != nil || target.Endpoint != node {
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "wv exec: invalid container target: %v\n", parseErr)
			} else {
				fmt.Fprintf(os.Stderr, "wv exec: container endpoint %q must match routed node %q\n", target.Endpoint, node)
			}
			return 2
		}
	}
	var stdin []byte
	var containerInput io.Reader
	if strings.TrimSpace(*inputFile) != "" {
		var reader io.Reader
		var closer io.Closer
		if *inputFile == "-" {
			reader = os.Stdin
		} else {
			file, err := os.Open(*inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "wv exec: input: %v\n", err)
				return 1
			}
			reader, closer = file, file
		}
		if closer != nil {
			defer closer.Close()
		}
		if containerMode {
			containerInput = reader
		} else {
			limited := io.LimitReader(reader, sessionexec.MaxInputBytes+1)
			data, err := io.ReadAll(limited)
			if err != nil {
				fmt.Fprintf(os.Stderr, "wv exec: input: %v\n", err)
				return 1
			}
			if len(data) > sessionexec.MaxInputBytes {
				fmt.Fprintf(os.Stderr, "wv exec: input exceeds %d bytes\n", sessionexec.MaxInputBytes)
				return 2
			}
			stdin = data
		}
	}
	var metadata []byte
	var err error
	if containerMode {
		metadata, err = containerexec.NewOpenMetadata(node)
	} else {
		metadata, err = sessionexec.NewOpenMetadata(node)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv exec: %v\n", err)
		return 2
	}
	state, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv exec: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	stream, err := sessionbroker.Dial(ctx, "unix", state.Socket, sessionbroker.OpenRequest{Node: node, Service: sessionmux.ServiceExec, Data: metadata})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv exec: open %s: %v\n", node, err)
		return 1
	}
	if containerMode {
		exit, callErr := containerexec.CallStream(ctx, stream, containerexec.Request{
			TargetURI: strings.TrimSpace(*containerTarget), Action: action, Args: actionArgs,
		}, containerInput, os.Stdout, os.Stderr)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "wv exec: %v\n", callErr)
			return 1
		}
		if exit.ExitCode != 0 {
			return 1
		}
		return 0
	}
	response, callErr := sessionexec.CallStream(ctx, stream, sessionexec.Request{Action: action, Args: actionArgs, Stdin: stdin, TimeoutMillis: timeout.Milliseconds()})
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
			fmt.Fprintf(os.Stderr, "wv exec: encode: %v\n", err)
			return 1
		}
	} else {
		if len(response.Stdout) > 0 {
			_, _ = os.Stdout.Write(response.Stdout)
		}
		if len(response.Stderr) > 0 {
			_, _ = os.Stderr.Write(response.Stderr)
		}
	}
	if callErr != nil {
		if !*jsonOut {
			fmt.Fprintf(os.Stderr, "wv exec: %v\n", callErr)
		}
		return 1
	}
	if response.ExitCode != 0 {
		return 1
	}
	return 0
}
