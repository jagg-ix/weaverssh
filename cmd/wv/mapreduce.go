package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"weaverssh/mapreduce"
	"weaverssh/sessionbroker"
)

func cmdMapReduce(args []string) int {
	if len(args) == 0 {
		printMapReduceUsage()
		return 2
	}
	switch args[0] {
	case "policy":
		return cmdMapReducePolicy(args[1:])
	case "plugins":
		return cmdMapReducePlugins(args[1:])
	case "describe":
		return cmdMapReduceDescribe(args[1:])
	case "run":
		return cmdMapReduceRun(args[1:], false)
	case "distributed":
		return cmdMapReduceRun(args[1:], true)
	default:
		printMapReduceUsage()
		return 2
	}
}

func printMapReduceUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  wv mapreduce policy POLICY.json
  wv mapreduce plugins PLUGINS.json
  wv mapreduce describe --node NODE [--socket PATH]
  wv mapreduce run --node NODE --plugin NAME --input RECORDS.json
  wv mapreduce distributed --map-nodes A,B --reduce-node C --plugin NAME --input RECORDS.json`)
}

func cmdMapReducePolicy(args []string) int {
	if len(args) != 1 {
		printMapReduceUsage()
		return 2
	}
	payload, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce policy: %v\n", err)
		return 1
	}
	policy, err := mapreduce.ParsePolicy(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce policy: %v\n", err)
		return 1
	}
	fmt.Printf("valid policy_sha256=%s\n", policy.SHA256())
	return 0
}

func cmdMapReducePlugins(args []string) int {
	if len(args) != 1 {
		printMapReduceUsage()
		return 2
	}
	registry, err := mapreduce.LoadPluginFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce plugins: %v\n", err)
		return 1
	}
	payload, _ := json.MarshalIndent(registry.Descriptions(), "", "  ")
	fmt.Println(string(payload))
	return 0
}

func mapReduceSocket(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return raw, nil
	}
	socket, _, err := sessionbroker.DefaultPaths()
	return socket, err
}

func cmdMapReduceDescribe(args []string) int {
	fs := flag.NewFlagSet("mapreduce describe", flag.ContinueOnError)
	node := fs.String("node", "", "target node")
	socket := fs.String("socket", "", "active session broker socket")
	timeout := fs.Duration("timeout", 15*time.Second, "call timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*node) == "" {
		fs.Usage()
		return 2
	}
	resolved, err := mapReduceSocket(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce describe: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := (mapreduce.BrokerClient{Socket: resolved}).Call(ctx, *node, mapreduce.Request{
		Protocol:  mapreduce.ProtocolVersion,
		ID:        mapreduce.NewJobID(),
		Operation: mapreduce.OperationDescribe,
		Fanout:    1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce describe: %v\n", err)
		return 1
	}
	payload, _ := json.MarshalIndent(response, "", "  ")
	fmt.Println(string(payload))
	return 0
}

type labelFlags map[string]string

func (l *labelFlags) String() string {
	if l == nil {
		return ""
	}
	parts := make([]string, 0, len(*l))
	for key, value := range *l {
		parts = append(parts, key+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (l *labelFlags) Set(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return errors.New("label must be KEY=VALUE")
	}
	if *l == nil {
		*l = map[string]string{}
	}
	(*l)[key] = value
	return nil
}

func cmdMapReduceRun(args []string, distributed bool) int {
	name := "mapreduce run"
	if distributed {
		name = "mapreduce distributed"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	node := fs.String("node", "", "target node for local run")
	mapNodes := fs.String("map-nodes", "", "comma-separated map targets")
	reduceNode := fs.String("reduce-node", "", "reduce target")
	plugin := fs.String("plugin", "", "plugin name")
	input := fs.String("input", "-", "JSON array of records or - for stdin")
	socket := fs.String("socket", "", "active broker socket")
	parallel := fs.Int("parallel", 1, "requested endpoint parallelism")
	requestTimeout := fs.Duration("request-timeout", 30*time.Second, "requested per-endpoint limit")
	callTimeout := fs.Duration("timeout", 2*time.Minute, "overall call timeout")
	var labels labelFlags
	fs.Var(&labels, "label", "rule label KEY=VALUE; repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*plugin) == "" {
		fs.Usage()
		return 2
	}
	records, err := readMapReduceRecords(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	resolved, err := mapReduceSocket(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *callTimeout)
	defer cancel()
	caller := mapreduce.BrokerClient{Socket: resolved}
	var output []mapreduce.Record
	if distributed {
		targets := splitNonempty(*mapNodes)
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "mapreduce distributed: --map-nodes is required")
			return 2
		}
		output, err = (mapreduce.Coordinator{Caller: caller}).Run(ctx, mapreduce.JobSpec{
			Plugin: *plugin, Records: records, MapTargets: targets, ReduceTarget: *reduceNode,
			Labels: labels, RequestedParallel: *parallel,
			RequestedTimeoutMillis: requestTimeout.Milliseconds(),
		})
	} else {
		if strings.TrimSpace(*node) == "" {
			fmt.Fprintln(os.Stderr, "mapreduce run: --node is required")
			return 2
		}
		response, callErr := caller.Call(ctx, *node, mapreduce.Request{
			Protocol: mapreduce.ProtocolVersion, ID: mapreduce.NewJobID(),
			Operation: mapreduce.OperationRun, Plugin: *plugin, Records: records,
			Labels: labels, RequestedParallel: *parallel,
			RequestedTimeoutMillis: requestTimeout.Milliseconds(), Fanout: 1,
		})
		err = callErr
		output = response.Records
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	payload, _ := json.MarshalIndent(mapreduce.SortedRecords(output), "", "  ")
	fmt.Println(string(payload))
	return 0
}

func readMapReduceRecords(path string) ([]mapreduce.Record, error) {
	var reader io.Reader = os.Stdin
	if strings.TrimSpace(path) != "" && path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	decoder := json.NewDecoder(io.LimitReader(reader, mapreduce.MaxMessageBytes+1))
	decoder.DisallowUnknownFields()
	var records []mapreduce.Record
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("mapreduce: trailing input data")
	}
	if len(records) == 0 || len(records) > mapreduce.MaxRecords {
		return nil, mapreduce.ErrInvalidRequest
	}
	return records, nil
}

func splitNonempty(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
