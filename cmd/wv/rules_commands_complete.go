package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/rules"
)

func cmdRulesComplete(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "init", "initialize":
			return cmdRulesInit(args[1:])
		case "validate", "lint":
			return cmdRulesValidate(args[1:])
		case "normalize", "format":
			return cmdRulesNormalize(args[1:])
		case "pipeline-validate", "validate-pipeline":
			return cmdRulesPipelineValidate(args[1:])
		case "pipeline-normalize", "normalize-pipeline":
			return cmdRulesPipelineNormalize(args[1:])
		case "pipeline-default", "default-pipeline":
			return cmdRulesPipelineDefault(args[1:])
		case "help", "-h", "--help":
			printRulesHelp()
			fmt.Fprintln(os.Stderr, `
Configuration lifecycle:
  init [--out FILE]                         emit a valid example ruleset
  validate RULES.json [--json]              strictly validate and summarize a ruleset
  normalize RULES.json [--out FILE]          emit canonical normalized rules JSON
  pipeline-validate PIPELINE.json [--resolve] validate pipeline config and optionally load every referenced ruleset
  pipeline-normalize PIPELINE.json [--out FILE]
  pipeline-default [--node NODE] [--out FILE] emit the default local or node-aware pipeline`)
			return 0
		}
	}
	return cmdRules(args)
}

func cmdRulesInit(args []string) int {
	fs := flag.NewFlagSet("rules init", flag.ContinueOnError)
	out := fs.String("out", "", "write example ruleset to file")
	force := fs.Bool("force", false, "replace existing output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	example, err := rules.ExampleRuleSet().Normalize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules init: %v\n", err)
		return 1
	}
	return emitOrWriteRulesArtifact("rules init", *out, example, *force)
}

func cmdRulesValidate(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("rules validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv rules validate RULES.json [--json]")
		return 2
	}
	ruleSet, err := rules.LoadFile(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules validate: %v\n", err)
		return 1
	}
	summary := map[string]any{
		"ok":             true,
		"version":        ruleSet.Version,
		"default_action": ruleSet.DefaultAction,
		"rules":          len(ruleSet.Rules),
		"path":           operands[0],
	}
	if *jsonOut {
		return printJSON(summary)
	}
	fmt.Printf("valid ruleset\nversion: %s\ndefault: %s\nrules: %d\n", ruleSet.Version, ruleSet.DefaultAction, len(ruleSet.Rules))
	return 0
}

func cmdRulesNormalize(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("rules normalize", flag.ContinueOnError)
	out := fs.String("out", "", "write normalized ruleset to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input file")
	force := fs.Bool("force", false, "replace existing --out file")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv rules normalize RULES.json [--out FILE|--in-place]")
		return 2
	}
	input := operands[0]
	ruleSet, err := rules.LoadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules normalize: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replace := *force
	if *inPlace {
		destination = input
		replace = true
	}
	return emitOrWriteRulesArtifact("rules normalize", destination, ruleSet, replace)
}

func cmdRulesPipelineValidate(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("rules pipeline-validate", flag.ContinueOnError)
	resolve := fs.Bool("resolve", false, "resolve every stage path and load all referenced rulesets")
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv rules pipeline-validate PIPELINE.json [--resolve] [--json]")
		return 2
	}
	config, err := rules.LoadPipelineFile(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules pipeline-validate: %v\n", err)
		return 1
	}
	loaded := 0
	var skipped []rules.StageDecision
	if *resolve {
		sources, stageSkipped, err := config.LoadRuleSets()
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules pipeline-validate: %v\n", err)
			return 1
		}
		loaded = len(sources)
		skipped = stageSkipped
	}
	summary := map[string]any{
		"ok":              true,
		"version":         config.Version,
		"node_id":         config.NodeID,
		"stages":          len(config.Stages),
		"resolved":        *resolve,
		"loaded_rulesets": loaded,
		"skipped_stages":  skipped,
		"configuration":   config,
	}
	if *jsonOut {
		return printJSON(summary)
	}
	fmt.Printf("valid rules pipeline\nversion: %s\nstages: %d\n", config.Version, len(config.Stages))
	if config.NodeID != "" {
		fmt.Printf("node: %s\n", config.NodeID)
	}
	if *resolve {
		fmt.Printf("loaded-rulesets: %d\nskipped-stages: %d\n", loaded, len(skipped))
	}
	return 0
}

func cmdRulesPipelineNormalize(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("rules pipeline-normalize", flag.ContinueOnError)
	out := fs.String("out", "", "write normalized pipeline to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input file")
	force := fs.Bool("force", false, "replace existing --out file")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv rules pipeline-normalize PIPELINE.json [--out FILE|--in-place]")
		return 2
	}
	input := operands[0]
	config, err := rules.LoadPipelineFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules pipeline-normalize: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replace := *force
	if *inPlace {
		destination = input
		replace = true
	}
	return emitOrWriteRulesArtifact("rules pipeline-normalize", destination, config, replace)
}

func cmdRulesPipelineDefault(args []string) int {
	fs := flag.NewFlagSet("rules pipeline-default", flag.ContinueOnError)
	node := fs.String("node", "", "emit a node-aware system/node/user pipeline")
	out := fs.String("out", "", "write pipeline JSON to file")
	force := fs.Bool("force", false, "replace existing output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	config := rules.DefaultPipelineConfig()
	var err error
	if strings.TrimSpace(*node) != "" {
		config, err = rules.DefaultRemoteNodePipelineConfig(*node)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules pipeline-default: %v\n", err)
			return 1
		}
	}
	return emitOrWriteRulesArtifact("rules pipeline-default", *out, config, *force)
}

func emitOrWriteRulesArtifact(command, path string, value any, replace bool) int {
	if strings.TrimSpace(path) == "" {
		if err := emitJSONArtifact(os.Stdout, value); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", command, err)
			return 1
		}
		return 0
	}
	if err := writeJSONArtifact(path, value, 0o644, replace); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", command, err)
		return 1
	}
	fmt.Printf("%s: wrote %s\n", command, path)
	return 0
}
