package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/mapreduce"
)

func cmdMapReduceComplete(args []string) int {
	if len(args) == 0 {
		printMapReduceUsageComplete()
		return 2
	}
	switch args[0] {
	case "policy":
		return cmdMapReducePolicyComplete(args[1:])
	case "plugins":
		return cmdMapReducePluginsComplete(args[1:])
	case "help", "-h", "--help":
		printMapReduceUsageComplete()
		return 0
	default:
		return cmdMapReduce(args)
	}
}

func cmdMapReducePolicyComplete(args []string) int {
	if len(args) == 1 && !strings.HasPrefix(args[0], "-") {
		return cmdMapReducePolicy(args)
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wv mapreduce policy <validate|digest|show|normalize> POLICY.json")
		return 2
	}
	switch args[0] {
	case "validate", "check", "digest":
		return cmdMapReducePolicy(args[1:])
	case "show":
		return cmdMapReducePolicyShow(args[1:])
	case "normalize", "format":
		return cmdMapReducePolicyNormalize(args[1:])
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stdout, "usage: wv mapreduce policy <validate|digest|show|normalize> POLICY.json")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "mapreduce policy: unknown command %q\n", args[0])
		return 2
	}
}

func cmdMapReducePolicyShow(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("mapreduce policy show", flag.ContinueOnError)
	textOut := fs.Bool("text", false, "emit a human-readable summary instead of JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv mapreduce policy show POLICY.json [--text]")
		return 2
	}
	policy, err := loadMapReducePolicy(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce policy show: %v\n", err)
		return 1
	}
	if !*textOut {
		return printJSON(policy)
	}
	fmt.Printf("version: %s\ndefault: %s\nrules: %d\npolicy-sha256: %s\n", policy.Version, policy.Default, len(policy.Rules), policy.SHA256())
	return 0
}

func cmdMapReducePolicyNormalize(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("mapreduce policy normalize", flag.ContinueOnError)
	out := fs.String("out", "", "write normalized policy JSON to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input file")
	force := fs.Bool("force", false, "replace existing --out file")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv mapreduce policy normalize POLICY.json [--out FILE|--in-place]")
		return 2
	}
	input := operands[0]
	policy, err := loadMapReducePolicy(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce policy normalize: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replace := *force
	if *inPlace {
		destination = input
		replace = true
	}
	if destination == "" {
		if err := emitJSONArtifact(os.Stdout, policy); err != nil {
			fmt.Fprintf(os.Stderr, "mapreduce policy normalize: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeJSONArtifact(destination, policy, 0o600, replace); err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce policy normalize: %v\n", err)
		return 1
	}
	fmt.Printf("mapreduce policy normalize: wrote %s\npolicy-sha256: %s\n", destination, policy.SHA256())
	return 0
}

func cmdMapReducePluginsComplete(args []string) int {
	if len(args) == 1 && !strings.HasPrefix(args[0], "-") {
		return cmdMapReducePlugins(args)
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wv mapreduce plugins <validate|list> PLUGINS.json")
		return 2
	}
	switch args[0] {
	case "list", "show", "describe":
		return cmdMapReducePlugins(args[1:])
	case "validate", "check":
		return cmdMapReducePluginsValidate(args[1:])
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stdout, "usage: wv mapreduce plugins <validate|list> PLUGINS.json")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "mapreduce plugins: unknown command %q\n", args[0])
		return 2
	}
}

func cmdMapReducePluginsValidate(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("mapreduce plugins validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv mapreduce plugins validate PLUGINS.json [--json]")
		return 2
	}
	registry, err := mapreduce.LoadPluginFile(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapreduce plugins validate: %v\n", err)
		return 1
	}
	descriptions := registry.Descriptions()
	if *jsonOut {
		return printJSON(map[string]any{"ok": true, "plugins": descriptions, "count": len(descriptions), "path": operands[0]})
	}
	fmt.Printf("valid plugin registry\nplugins: %d\n", len(descriptions))
	for _, description := range descriptions {
		fmt.Printf("- %s %s\n", description.Name, description.Version)
	}
	return 0
}

func loadMapReducePolicy(path string) (*mapreduce.Policy, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return mapreduce.ParsePolicy(payload)
}

func printMapReduceUsageComplete() {
	fmt.Fprintln(os.Stderr, `usage:
  wv mapreduce policy POLICY.json
  wv mapreduce policy validate POLICY.json
  wv mapreduce policy show POLICY.json [--text]
  wv mapreduce policy normalize POLICY.json [--out FILE|--in-place]
  wv mapreduce plugins PLUGINS.json
  wv mapreduce plugins validate PLUGINS.json
  wv mapreduce plugins list PLUGINS.json
  wv mapreduce describe --node NODE [--socket PATH]
  wv mapreduce run --node NODE --plugin NAME --input RECORDS.json
  wv mapreduce distributed --map-nodes A,B --reduce-node C --plugin NAME --input RECORDS.json`)
}
