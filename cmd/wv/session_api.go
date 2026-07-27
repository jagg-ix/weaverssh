package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/sessionapi"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

func cmdSessionAPI(args []string) int {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print JSON output")
	timeout := fs.Duration("timeout", 10*time.Second, "API request timeout")
	offset := fs.Int("offset", 0, "contract list offset")
	limit := fs.Int("limit", 64, "contract list limit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv api [--json] [describe|topology|resolve NODE|route NODE [SERVICE]|capabilities|contracts|contract ID [VERSION]]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := "describe"
	rest := fs.Args()
	if len(rest) > 0 {
		command, rest = strings.ToLower(rest[0]), rest[1:]
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "api: %v\n", err)
		return 1
	}
	conn, err := sessionbroker.Dial(ctx, "unix", state.Socket, sessionbroker.OpenRequest{Node: state.Node, Service: sessionmux.ServiceControl})
	if err != nil {
		fmt.Fprintf(os.Stderr, "api: open in-band stream: %v\n", err)
		return 1
	}
	defer conn.Close()

	var result any
	switch command {
	case "describe":
		if len(rest) != 0 { fs.Usage(); return 2 }
		var value sessionapi.Snapshot
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodDescribe, nil, &value)
		result = value
	case "topology":
		if len(rest) != 0 { fs.Usage(); return 2 }
		var value struct {
			Topology []string          `json:"topology"`
			Nodes    []sessionapi.Node `json:"nodes"`
		}
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodTopology, nil, &value)
		result = value
	case "resolve":
		if len(rest) != 1 { fs.Usage(); return 2 }
		var value sessionapi.ResolveResult
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodResolve, sessionapi.ResolveParams{Node: rest[0]}, &value)
		result = value
	case "route":
		if len(rest) < 1 || len(rest) > 2 { fs.Usage(); return 2 }
		service := ""
		if len(rest) == 2 { service = rest[1] }
		var value sessionapi.RoutePlan
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodRoutePrepare, sessionapi.RoutePrepareParams{Node: rest[0], Service: service}, &value)
		result = value
	case "capabilities":
		if len(rest) != 0 { fs.Usage(); return 2 }
		var value sessionapi.Capabilities
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodCapabilities, nil, &value)
		result = value
	case "contracts":
		if len(rest) != 0 || *offset < 0 || *limit < 1 || *limit > 128 { fs.Usage(); return 2 }
		var value sessionapi.ContractListResult
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodContractsList, sessionapi.ContractListParams{Offset: *offset, Limit: *limit}, &value)
		result = value
	case "contract":
		if len(rest) < 1 || len(rest) > 2 { fs.Usage(); return 2 }
		version := ""
		if len(rest) == 2 { version = rest[1] }
		var value sessionapi.ContractDocument
		err = sessionapi.CallStream(ctx, conn, sessionapi.MethodContractGet, sessionapi.ContractGetParams{ID: rest[0], Version: version}, &value)
		if err == nil && !*jsonOut {
			switch value.Encoding {
			case "utf-8":
				fmt.Print(value.Data)
				if !strings.HasSuffix(value.Data, "\n") { fmt.Println() }
				return 0
			case "base64":
				decoded, decodeErr := base64.StdEncoding.DecodeString(value.Data)
				if decodeErr != nil { err = decodeErr } else { _, err = os.Stdout.Write(decoded) }
				if err == nil { return 0 }
			}
		}
		result = value
	default:
		fs.Usage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "api: %v\n", err)
		return 1
	}
	if *jsonOut {
		payload, _ := json.Marshal(result)
		fmt.Println(string(payload))
		return 0
	}
	payload, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(payload))
	return 0
}
