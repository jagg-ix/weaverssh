package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/pubsub"
	"weaverssh/rules"
)

type rulesEvalResult struct {
	OK       bool           `json:"ok"`
	Rules    string         `json:"rules,omitempty"`
	Topic    string         `json:"topic"`
	Event    pubsub.Event   `json:"event"`
	Decision rules.Decision `json:"decision"`
}

type rulesPipelineEvalResult struct {
	OK       bool                   `json:"ok"`
	Config   string                 `json:"config,omitempty"`
	Topic    string                 `json:"topic"`
	Event    pubsub.Event           `json:"event"`
	Decision rules.PipelineDecision `json:"decision"`
}

func cmdRules(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "plan", "contract", "spec":
			return cmdRulesPlan(args[1:])
		case "pipeline", "stages", "stage":
			return cmdRulesPipeline(args[1:])
		case "consume", "consumer":
			return cmdRulesConsume(args[1:])
		case "eval", "evaluate", "test":
			return cmdRulesEval(args[1:])
		case "example":
			return cmdRulesExample(args[1:])
		case "help", "-h", "--help":
			printRulesHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "rules: unknown command %q\n", args[0])
			printRulesHelp()
			return 2
		}
	}
	printRulesHelp()
	return 2
}

func cmdRulesPlan(args []string) int {
	fs := flag.NewFlagSet("rules plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv rules plan [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	api := rules.MustNewAPI(rules.APIConfig{})
	plan := api.Contract()
	if *jsonOut {
		return printJSON(plan)
	}
	fmt.Println("weaverssh rules engine")
	fmt.Printf("  version:        %s\n", plan.Version)
	fmt.Printf("  API:            rules.API\n")
	fmt.Printf("  evaluation:     %s\n", plan.Evaluation)
	fmt.Printf("  default action: %s\n", plan.DefaultAction)
	fmt.Printf("  actions:        %s\n", strings.Join(plan.Actions, ", "))
	fmt.Printf("  operators:      %s\n", strings.Join(plan.Operators, ", "))
	fmt.Println("  facts:          topic, hook.point, event.*, field.<name>, fields.<name>, infra.*, file.*")
	fmt.Println("  pipeline:       system stage first; default paths /etc/weaverssh/rules.d/*.json and /etc/weaverssh/rules.json")
	fmt.Println("  integration:    pubsub.NewRulePlugin registers rules as hook handlers")
	return 0
}

func cmdRulesExample(args []string) int {
	fs := flag.NewFlagSet("rules example", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv rules example")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	return printJSON(rules.ExampleRuleSet())
}

func cmdRulesPipeline(args []string) int {
	fs := flag.NewFlagSet("rules pipeline", flag.ContinueOnError)
	configPath := fs.String("config", "", "pipeline JSON config file; default loads system then user rule stages")
	nodeID := fs.String("node", envOr("WEAVERSSH_NODE_ID", ""), "remote node id; enables node-local rules under /etc/weaverssh/nodes/NODE")
	systemDir := fs.String("system-dir", "", "override default system rules directory")
	systemFile := fs.String("system-file", "", "override default system rules file")
	nodeDir := fs.String("node-dir", "", "override remote node rules directory")
	nodeFile := fs.String("node-file", "", "override remote node rules file")
	userDir := fs.String("user-dir", "", "override default user rules directory")
	requireSystem := fs.Bool("require-system", false, "fail closed when the system stage has no rules")
	requireNode := fs.Bool("require-node", false, "fail closed when the remote-node stage has no rules")
	jsonOut := fs.Bool("json", false, "emit JSON")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "topic prefix when --topic is omitted")
	topic := fs.String("topic", "", "event topic; defaults to PREFIX/component/type")
	pointText := fs.String("point", string(pubsub.HookBeforePublish), "hook point used for rule facts")
	originText := fs.String("origin", string(pubsub.EventOriginInternal), "event origin: internal, external, or pubsub")
	component := fs.String("component", "runtime", "event component")
	eventType := fs.String("type", "status", "event type")
	message := fs.String("message", "", "event message")
	var fields fieldList
	fs.Var(&fields, "field", "event field as key=value; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv rules pipeline [--config FILE] [--node NODE] [--require-system] [--require-node] [--component NAME] [--type TYPE] [--field K=V] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := loadRulesPipelineConfig(*configPath, *nodeID, *systemDir, *systemFile, *nodeDir, *nodeFile, *userDir, *requireSystem, *requireNode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules pipeline: %v\n", err)
		return 2
	}
	input, event, selectedTopic, err := buildRulesInput(*prefix, *topic, *pointText, *originText, *component, *eventType, *message, fields, *nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules pipeline: %v\n", err)
		return 2
	}
	decision, err := cfg.Evaluate(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules pipeline: %v\n", err)
		return 2
	}
	result := rulesPipelineEvalResult{OK: decision.Allowed, Config: *configPath, Topic: selectedTopic, Event: event, Decision: decision}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Printf("decision: %s\n", decision.Action)
	fmt.Printf("allowed:  %t\n", decision.Allowed)
	if decision.Final.RuleID != "" {
		fmt.Printf("rule:     %s\n", decision.Final.RuleID)
	}
	if decision.Reason != "" {
		fmt.Printf("reason:   %s\n", decision.Reason)
	}
	fmt.Printf("topic:    %s\n", decision.Topic)
	fmt.Println("stages:")
	for _, stage := range decision.Stages {
		if stage.Skipped {
			fmt.Printf("  - %s skipped: %s\n", stage.Stage, stage.Reason)
			continue
		}
		fmt.Printf("  - %s %s action=%s allowed=%t", stage.Stage, stage.Path, stage.Decision.Action, stage.Decision.Allowed)
		if stage.Decision.RuleID != "" {
			fmt.Printf(" rule=%s", stage.Decision.RuleID)
		}
		fmt.Println()
	}
	return 0
}

func cmdRulesConsume(args []string) int {
	fs := flag.NewFlagSet("rules consume", flag.ContinueOnError)
	configPath := fs.String("config", "", "pipeline JSON config file; default loads system then user rule stages")
	nodeID := fs.String("node", envOr("WEAVERSSH_NODE_ID", ""), "remote node id; enables node-local rules under /etc/weaverssh/nodes/NODE")
	systemDir := fs.String("system-dir", "", "override default system rules directory")
	systemFile := fs.String("system-file", "", "override default system rules file")
	nodeDir := fs.String("node-dir", "", "override remote node rules directory")
	nodeFile := fs.String("node-file", "", "override remote node rules file")
	userDir := fs.String("user-dir", "", "override default user rules directory")
	requireSystem := fs.Bool("require-system", false, "fail closed when the system stage has no rules")
	requireNode := fs.Bool("require-node", false, "fail closed when the remote-node stage has no rules")
	eventFile := fs.String("event-file", "", "read a weaverssh pubsub event JSON file instead of constructing one from flags")
	jsonOut := fs.Bool("json", false, "emit JSON")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "topic prefix when --topic is omitted")
	topic := fs.String("topic", "", "event topic; defaults to PREFIX/component/type")
	originText := fs.String("origin", string(pubsub.EventOriginInternal), "event origin: internal, external, or pubsub")
	component := fs.String("component", "runtime", "event component")
	eventType := fs.String("type", "status", "event type")
	message := fs.String("message", "", "event message")
	var fields fieldList
	fs.Var(&fields, "field", "event field as key=value; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv rules consume [--event-file FILE|--component NAME --type TYPE] [--node NODE] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := loadRulesPipelineConfig(*configPath, *nodeID, *systemDir, *systemFile, *nodeDir, *nodeFile, *userDir, *requireSystem, *requireNode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules consume: %v\n", err)
		return 2
	}
	event, selectedTopic, err := loadConsumeEvent(*eventFile, *prefix, *topic, *originText, *component, *eventType, *message, fields, *nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules consume: %v\n", err)
		return 2
	}
	consumer, err := pubsub.NewEventConsumer(pubsub.EventConsumerConfig{NodeID: *nodeID, Pipeline: cfg})
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules consume: %v\n", err)
		return 2
	}
	result, err := consumer.PlanEvent(context.Background(), pubsub.EventConsumeRequest{Topic: selectedTopic, Event: event})
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules consume: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Printf("decision: %s\n", result.Decision.Action)
	fmt.Printf("allowed:  %t\n", result.Decision.Allowed)
	if result.Decision.Final.RuleID != "" {
		fmt.Printf("rule:     %s\n", result.Decision.Final.RuleID)
	}
	fmt.Printf("topic:    %s\n", result.Topic)
	if len(result.Intents) == 0 {
		fmt.Println("api intents: none")
		return 0
	}
	fmt.Println("api intents:")
	for _, intent := range result.Intents {
		fmt.Printf("  - api=%s operation=%s subject=%s node=%s rule=%s\n", intent.API, intent.Operation, intent.Subject, intent.NodeID, intent.RuleID)
	}
	fmt.Println("note: CLI consume plans only; trusted Go components execute intents with pubsub.APIIntentExecutor")
	return 0
}

func cmdRulesEval(args []string) int {
	fs := flag.NewFlagSet("rules eval", flag.ContinueOnError)
	rulesPath := fs.String("rules", "", "ruleset JSON file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "topic prefix when --topic is omitted")
	topic := fs.String("topic", "", "event topic; defaults to PREFIX/component/type")
	pointText := fs.String("point", string(pubsub.HookBeforePublish), "hook point used for rule facts")
	originText := fs.String("origin", string(pubsub.EventOriginInternal), "event origin: internal, external, or pubsub")
	component := fs.String("component", "runtime", "event component")
	eventType := fs.String("type", "status", "event type")
	message := fs.String("message", "", "event message")
	var fields fieldList
	fs.Var(&fields, "field", "event field as key=value; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv rules eval --rules FILE [--component NAME] [--type TYPE] [--origin internal|external|pubsub] [--field K=V] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*rulesPath) == "" {
		fs.Usage()
		return 2
	}
	ruleSet, err := rules.LoadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules eval: %v\n", err)
		return 2
	}
	input, event, selectedTopic, err := buildRulesInput(*prefix, *topic, *pointText, *originText, *component, *eventType, *message, fields, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules eval: %v\n", err)
		return 2
	}
	decision, err := ruleSet.Evaluate(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules eval: %v\n", err)
		return 2
	}
	result := rulesEvalResult{OK: decision.Allowed, Rules: *rulesPath, Topic: selectedTopic, Event: event, Decision: decision}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Printf("decision: %s\n", decision.Action)
	fmt.Printf("allowed:  %t\n", decision.Allowed)
	fmt.Printf("matched:  %t\n", decision.Matched)
	if decision.RuleID != "" {
		fmt.Printf("rule:     %s\n", decision.RuleID)
	}
	if decision.Reason != "" {
		fmt.Printf("reason:   %s\n", decision.Reason)
	}
	fmt.Printf("topic:    %s\n", decision.Topic)
	return 0
}

func loadConsumeEvent(eventFile, prefix, topic, originText, component, eventType, message string, fields fieldList, nodeID string) (pubsub.Event, string, error) {
	if strings.TrimSpace(eventFile) != "" {
		data, err := os.ReadFile(eventFile)
		if err != nil {
			return pubsub.Event{}, "", err
		}
		event, err := pubsub.DecodeEvent(data)
		if err != nil {
			return pubsub.Event{}, "", err
		}
		selectedTopic := strings.TrimSpace(topic)
		if selectedTopic == "" {
			selectedTopic, err = pubsub.EventTopic(prefix, event.Component, event.Type)
			if err != nil {
				return pubsub.Event{}, "", err
			}
		}
		return event, selectedTopic, nil
	}
	_, event, selectedTopic, err := buildRulesInput(prefix, topic, string(pubsub.HookOnEventConsumed), originText, component, eventType, message, fields, nodeID)
	return event, selectedTopic, err
}

func loadRulesPipelineConfig(configPath, nodeID, systemDir, systemFile, nodeDir, nodeFile, userDir string, requireSystem, requireNode bool) (rules.PipelineConfig, error) {
	var cfg rules.PipelineConfig
	var err error
	if strings.TrimSpace(configPath) != "" {
		cfg, err = rules.LoadPipelineFile(configPath)
		if err != nil {
			return rules.PipelineConfig{}, err
		}
		if strings.TrimSpace(nodeID) != "" {
			cleanNode, err := rules.CleanNodeID(nodeID)
			if err != nil {
				return rules.PipelineConfig{}, err
			}
			cfg.NodeID = cleanNode
		}
	} else if strings.TrimSpace(nodeID) != "" {
		cfg, err = rules.DefaultRemoteNodePipelineConfig(nodeID)
		if err != nil {
			return rules.PipelineConfig{}, err
		}
	} else {
		cfg = rules.DefaultPipelineConfig()
	}
	if strings.TrimSpace(systemDir) != "" || strings.TrimSpace(systemFile) != "" || requireSystem {
		if len(cfg.Stages) == 0 || cfg.Stages[0].Name != "system" {
			return rules.PipelineConfig{}, fmt.Errorf("pipeline must start with a system stage to apply system overrides")
		}
		paths := cfg.Stages[0].Paths
		if strings.TrimSpace(systemDir) != "" || strings.TrimSpace(systemFile) != "" {
			paths = nil
			if strings.TrimSpace(systemDir) != "" {
				paths = append(paths, strings.TrimRight(systemDir, string(os.PathSeparator))+string(os.PathSeparator)+"*.json")
			}
			if strings.TrimSpace(systemFile) != "" {
				paths = append(paths, systemFile)
			}
		}
		cfg.Stages[0].Paths = paths
		if requireSystem {
			cfg.Stages[0].Required = true
		}
	}
	if strings.TrimSpace(userDir) != "" {
		found := false
		for i := range cfg.Stages {
			if cfg.Stages[i].Name == "user" {
				cfg.Stages[i].Paths = []string{strings.TrimRight(userDir, string(os.PathSeparator)) + string(os.PathSeparator) + "*.json"}
				found = true
				break
			}
		}
		if !found {
			cfg.Stages = append(cfg.Stages, rules.StageConfig{Name: "user", Paths: []string{strings.TrimRight(userDir, string(os.PathSeparator)) + string(os.PathSeparator) + "*.json"}})
		}
	}
	if strings.TrimSpace(nodeDir) != "" || strings.TrimSpace(nodeFile) != "" || requireNode {
		if strings.TrimSpace(cfg.NodeID) == "" {
			return rules.PipelineConfig{}, fmt.Errorf("--node is required when configuring remote node rules")
		}
		found := false
		for i := range cfg.Stages {
			if cfg.Stages[i].Name == "remote-node" {
				paths := cfg.Stages[i].Paths
				if strings.TrimSpace(nodeDir) != "" || strings.TrimSpace(nodeFile) != "" {
					paths = nil
					if strings.TrimSpace(nodeDir) != "" {
						paths = append(paths, strings.TrimRight(nodeDir, string(os.PathSeparator))+string(os.PathSeparator)+"*.json")
					}
					if strings.TrimSpace(nodeFile) != "" {
						paths = append(paths, nodeFile)
					}
				}
				cfg.Stages[i].Paths = paths
				if requireNode {
					cfg.Stages[i].Required = true
				}
				found = true
				break
			}
		}
		if !found {
			paths := []string{}
			if strings.TrimSpace(nodeDir) != "" {
				paths = append(paths, strings.TrimRight(nodeDir, string(os.PathSeparator))+string(os.PathSeparator)+"*.json")
			}
			if strings.TrimSpace(nodeFile) != "" {
				paths = append(paths, nodeFile)
			}
			cfg.Stages = append(cfg.Stages, rules.StageConfig{Name: "remote-node", Required: requireNode, Paths: paths})
		}
	}
	return cfg.Normalize()
}

func buildRulesInput(prefix, topic, pointText, originText, component, eventType, message string, fields fieldList, nodeID string) (rules.Input, pubsub.Event, string, error) {
	fieldMap, err := parseFields(fields)
	if err != nil {
		return rules.Input{}, pubsub.Event{}, "", err
	}
	if strings.TrimSpace(nodeID) != "" {
		cleanNode, err := rules.CleanNodeID(nodeID)
		if err != nil {
			return rules.Input{}, pubsub.Event{}, "", err
		}
		if fieldMap == nil {
			fieldMap = map[string]string{}
		}
		fieldMap["node_id"] = cleanNode
		fieldMap["node.id"] = cleanNode
		fieldMap["remote.node_id"] = cleanNode
	}
	origin, err := pubsub.ParseEventOrigin(originText)
	if err != nil {
		return rules.Input{}, pubsub.Event{}, "", err
	}
	point, err := pubsub.ParseHookPoint(pointText)
	if err != nil {
		return rules.Input{}, pubsub.Event{}, "", err
	}
	event := pubsub.NewEventFrom(origin, eventType, component, message, fieldMap)
	selectedTopic := strings.TrimSpace(topic)
	if selectedTopic == "" {
		selectedTopic, err = pubsub.EventTopic(prefix, event.Component, event.Type)
		if err != nil {
			return rules.Input{}, pubsub.Event{}, "", err
		}
	}
	return pubsub.EventRuleInput(selectedTopic, point, event), event, selectedTopic, nil
}

func printRulesHelp() {
	fmt.Print(`wv rules - evaluate deterministic weaverssh rulesets

Usage:
  wv rules plan [--json]
  wv rules example
  wv rules eval --rules FILE [--component runtime] [--type status] [--origin internal] [--field K=V] [--json]
  wv rules pipeline [--config FILE] [--node NODE] [--require-system] [--component runtime] [--type status] [--field K=V] [--json]
  wv rules consume [--event-file FILE|--component runtime --type status] [--node NODE] [--json]

Rulesets are JSON files using version weaverssh.rules.v1. Rules are evaluated
in order; the first match returns an action. Pipelines use version
weaverssh.rules.pipeline.v1 and evaluate system rules before remote-node,
user-node, user, or profile rules.
`)
}
