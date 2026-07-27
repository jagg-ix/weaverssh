package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"weaverssh/pubsub"
)

type fieldList []string

func (f *fieldList) String() string { return strings.Join(*f, ",") }

func (f *fieldList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*f = append(*f, value)
	}
	return nil
}

type pubSubStatus struct {
	OK       bool   `json:"ok"`
	Broker   string `json:"broker"`
	ClientID string `json:"client_id"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type pubSubPublishResult struct {
	OK      bool          `json:"ok"`
	DryRun  bool          `json:"dry_run"`
	Broker  string        `json:"broker"`
	Topic   string        `json:"topic"`
	Event   *pubsub.Event `json:"event,omitempty"`
	Payload string        `json:"payload,omitempty"`
}

type pubSubMessageResult struct {
	Topic   string        `json:"topic"`
	Payload string        `json:"payload"`
	Event   *pubsub.Event `json:"event,omitempty"`
}

type pubSubMeshNode struct {
	ID              string `json:"id"`
	StatusTopic     string `json:"status_topic"`
	SubscribeFilter string `json:"subscribe_filter"`
}

type pubSubMeshPlan struct {
	Version           string             `json:"version"`
	MeshVersion       string             `json:"mesh_version"`
	Prefix            string             `json:"prefix"`
	ChainID           string             `json:"chain_id"`
	Scheme            string             `json:"scheme"`
	SchemeDescription string             `json:"scheme_description"`
	PhysicalMode      string             `json:"physical_mode"`
	DirectLinks       string             `json:"direct_links"`
	MaxHops           int                `json:"max_hops"`
	Links             []pubsub.ChainLink `json:"links"`
	Nodes             []pubSubMeshNode   `json:"nodes"`
	ForwardingRules   []pubsub.RouteRule `json:"forwarding_rules"`
}

func cmdPubSub(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "plan", "contract":
			return cmdPubSubPlan(args[1:])
		case "hooks-plan", "hook-plan", "plugins-plan":
			return cmdPubSubHooksPlan(args[1:])
		case "mesh-plan", "mesh", "bus-plan":
			return cmdPubSubMeshPlan(args[1:])
		case "broker", "serve", "server":
			return cmdPubSubBroker(args[1:])
		case "status", "check", "ping":
			return cmdPubSubStatus(args[1:])
		case "publish", "pub":
			return cmdPubSubPublish(args[1:])
		case "subscribe", "sub", "listen":
			return cmdPubSubSubscribe(args[1:])
		case "help", "-h", "--help":
			printPubSubHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "pubsub: unknown command %q\n", args[0])
			printPubSubHelp()
			return 2
		}
	}
	printPubSubHelp()
	return 2
}

func cmdPubSubPlan(args []string) int {
	fs := flag.NewFlagSet("pubsub plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "MQTT topic prefix")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub plan [--prefix PREFIX] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	examples := map[string]string{
		"status":    *prefix + "/runtime/status",
		"fault":     *prefix + "/authproof/fault",
		"relay":     *prefix + "/relay/session",
		"subscribe": *prefix + "/#",
	}
	plan := map[string]any{
		"version":          pubsub.EventVersion,
		"hook_api_version": pubsub.HookAPIVersion,
		"broker_env":       "WEAVERSSH_MQTT_BROKER",
		"prefix_env":       "WEAVERSSH_MQTT_TOPIC_PREFIX",
		"client_id_env":    "WEAVERSSH_MQTT_CLIENT_ID",
		"qos":              0,
		"topic_examples":   examples,
	}
	if *jsonOut {
		return printJSON(plan)
	}
	fmt.Println("weaverssh MQTT pub-sub plan")
	fmt.Printf("  event version: %s\n", pubsub.EventVersion)
	fmt.Printf("  hook API:      %s\n", pubsub.HookAPIVersion)
	fmt.Println("  QoS:           0 (at-most-once; status/control evidence only)")
	fmt.Println("  broker env:    WEAVERSSH_MQTT_BROKER, default mqtt://127.0.0.1:1883")
	fmt.Println("  prefix env:    WEAVERSSH_MQTT_TOPIC_PREFIX, default weaverssh")
	keys := make([]string, 0, len(examples))
	for k := range examples {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-10s %s\n", k+":", examples[k])
	}
	return 0
}

func cmdPubSubHooksPlan(args []string) int {
	fs := flag.NewFlagSet("pubsub hooks-plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub hooks-plan [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	origins := make([]string, 0, len(pubsub.KnownEventOrigins()))
	for _, origin := range pubsub.KnownEventOrigins() {
		origins = append(origins, string(origin))
	}
	points := make([]string, 0, len(pubsub.KnownHookPoints()))
	for _, point := range pubsub.KnownHookPoints() {
		points = append(points, string(point))
	}
	plan := map[string]any{
		"version":       pubsub.HookAPIVersion,
		"event_version": pubsub.EventVersion,
		"event_origins": origins,
		"hook_points":   points,
		"filter_fields": []string{"origins", "components", "types", "topic_filter"},
		"safety": []string{
			"plugins register Go handlers through pubsub.HookRegistry; wv does not load arbitrary code from MQTT",
			"before_publish hooks may return drop to fail closed before broker or bus publish",
			"pubsub-origin events are for bus/broker delivery and fault metadata, not payload inspection",
		},
	}
	if *jsonOut {
		return printJSON(plan)
	}
	fmt.Println("weaverssh plugin/hook API plan")
	fmt.Printf("  version:       %s\n", pubsub.HookAPIVersion)
	fmt.Printf("  event version: %s\n", pubsub.EventVersion)
	fmt.Printf("  origins:       %s\n", strings.Join(origins, ", "))
	fmt.Printf("  hook points:   %s\n", strings.Join(points, ", "))
	fmt.Println("  filters:       origins, components, types, topic_filter")
	fmt.Println("  API:           pubsub.API + pubsub.HookRegistry + pubsub.HookedEmitter")
	fmt.Println("  safety:        no arbitrary runtime code loading from MQTT; plugins are registered by the embedding component")
	return 0
}

func cmdPubSubMeshPlan(args []string) int {
	fs := flag.NewFlagSet("pubsub mesh-plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "MQTT topic prefix")
	chainID := fs.String("chain", envOr("WEAVERSSH_CHAIN_ID", "default"), "weaverssh chain id")
	nodesText := fs.String("nodes", "", "comma-separated node ids in SSH/X11 chain order")
	schemeText := fs.String("scheme", string(pubsub.SchemeOneOne), "pub-sub topology: one-one, one-many, or many-to-many")
	maxHops := fs.Int("max-hops", pubsub.DefaultMaxHops, "maximum mesh forwarding hops")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub mesh-plan --chain NAME --nodes alice,jump,target [--scheme one-one|one-many|many-to-many] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*nodesText) == "" {
		fs.Usage()
		return 2
	}
	nodes := parseCSVNodes(*nodesText)
	scheme, err := pubsub.ParseMeshScheme(*schemeText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub mesh-plan: %v\n", err)
		return 2
	}
	rules, err := pubsub.ChainRulesForScheme(*prefix, *chainID, nodes, scheme)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub mesh-plan: %v\n", err)
		return 2
	}
	links, err := pubsub.ChainLinks(nodes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub mesh-plan: %v\n", err)
		return 2
	}
	if !pubsub.RulesUseOnlyAdjacentLinks(rules, links) {
		fmt.Fprintln(os.Stderr, "pubsub mesh-plan: generated rules violate adjacent-only single SSH socket chain")
		return 2
	}
	plan := pubSubMeshPlan{
		Version:           pubsub.EventVersion,
		MeshVersion:       pubsub.MeshEnvelopeVersion,
		Prefix:            *prefix,
		ChainID:           *chainID,
		Scheme:            string(scheme),
		SchemeDescription: scheme.Description(),
		PhysicalMode:      pubsub.SingleSSHSocketChainMode,
		DirectLinks:       "disallowed",
		MaxHops:           *maxHops,
		Links:             links,
		ForwardingRules:   rules,
	}
	for _, node := range nodes {
		statusTopic, err := pubsub.NodeEventTopic(*prefix, *chainID, node, "runtime", "status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubsub mesh-plan: %v\n", err)
			return 2
		}
		filter := strings.Join([]string{strings.Trim(*prefix, "/"), "chains", strings.Trim(*chainID, "/"), "nodes", strings.Trim(node, "/"), "#"}, "/")
		if err := pubsub.ValidateSubscribeTopic(filter); err != nil {
			fmt.Fprintf(os.Stderr, "pubsub mesh-plan: %v\n", err)
			return 2
		}
		plan.Nodes = append(plan.Nodes, pubSubMeshNode{ID: node, StatusTopic: statusTopic, SubscribeFilter: filter})
	}
	if *jsonOut {
		return printJSON(plan)
	}
	fmt.Println("weaverssh MQTT chain data-bus plan")
	fmt.Printf("  chain:       %s\n", plan.ChainID)
	fmt.Printf("  prefix:      %s\n", plan.Prefix)
	fmt.Printf("  envelope:    %s\n", plan.MeshVersion)
	fmt.Printf("  scheme:      %s - %s\n", plan.Scheme, plan.SchemeDescription)
	fmt.Printf("  physical:    %s; direct non-adjacent links=%s\n", plan.PhysicalMode, plan.DirectLinks)
	fmt.Printf("  max hops:    %d\n", plan.MaxHops)
	fmt.Println("  physical links:")
	for _, link := range plan.Links {
		fmt.Printf("    - %s -> %s transport=%s\n", link.From, link.To, link.Transport)
	}
	fmt.Println("  nodes:")
	for _, node := range plan.Nodes {
		fmt.Printf("    - %s publish=%s subscribe=%s\n", node.ID, node.StatusTopic, node.SubscribeFilter)
	}
	fmt.Println("  forwarding rules:")
	for _, rule := range plan.ForwardingRules {
		origin := "any"
		if rule.OriginNode != "" {
			origin = rule.OriginNode
		}
		fmt.Printf("    - %s origin=%s %s -> %s filter=%s action=%s\n", rule.ID, origin, rule.FromNode, rule.ToNode, rule.TopicFilter, rule.Action)
	}
	fmt.Println("  transport: one established full-duplex SSH/X11/WebSocket socket per adjacent hop; MQTT is never a separate inter-node TCP path")
	return 0
}

func cmdPubSubBroker(args []string) int {
	fs := flag.NewFlagSet("pubsub broker", flag.ContinueOnError)
	listen := fs.String("listen", envOr("WEAVERSSH_MQTT_LISTEN", "127.0.0.1:1883"), "MQTT listen address")
	jsonOut := fs.Bool("json", false, "emit startup status as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub broker [--listen HOST:PORT] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	broker := pubsub.NewMQTTBroker(pubsub.MQTTBrokerConfig{
		Addr: *listen,
		Logger: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err := broker.Listen(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pubsub broker: listen: %v\n", err)
		return 1
	}
	addr := broker.Addr()
	if *jsonOut {
		_ = printJSON(map[string]any{"ok": true, "listen": addr, "broker": "mqtt://" + addr})
	} else {
		fmt.Println("status: listening")
		fmt.Printf("broker: mqtt://%s\n", addr)
		fmt.Println("mode:   MQTT 3.1.1 QoS0 broker for weaverssh events")
	}
	if err := broker.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pubsub broker: %v\n", err)
		return 1
	}
	return 0
}

func cmdPubSubStatus(args []string) int {
	fs := flag.NewFlagSet("pubsub status", flag.ContinueOnError)
	broker := fs.String("broker", envOr("WEAVERSSH_MQTT_BROKER", "mqtt://127.0.0.1:1883"), "MQTT broker URL")
	clientID := fs.String("client-id", envOr("WEAVERSSH_MQTT_CLIENT_ID", ""), "MQTT client id")
	username := fs.String("username", envOr("WEAVERSSH_MQTT_USERNAME", ""), "MQTT username")
	password := fs.String("password", envOr("WEAVERSSH_MQTT_PASSWORD", ""), "MQTT password")
	timeout := fs.Duration("timeout", 5*time.Second, "connect/ping timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	insecureTLS := fs.Bool("insecure-skip-verify", false, "skip MQTT TLS certificate verification for lab brokers only")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub status [--broker URL] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := pubsub.DialMQTT(ctx, pubsub.MQTTConfig{Broker: *broker, ClientID: *clientID, Username: *username, Password: *password, ConnectTimeout: *timeout, InsecureTLS: *insecureTLS})
	status := pubSubStatus{OK: err == nil, Broker: *broker, ClientID: *clientID}
	if err != nil {
		status.Status = "unreachable"
		status.Error = err.Error()
	} else {
		defer client.Close()
		if err := client.Ping(ctx); err != nil {
			status.OK = false
			status.Status = "ping_failed"
			status.Error = err.Error()
		} else {
			status.Status = "ready"
		}
	}
	if *jsonOut {
		_ = printJSON(status)
	} else if status.OK {
		fmt.Printf("status: ready\nbroker: %s\n", status.Broker)
	} else {
		fmt.Printf("status: %s\nbroker: %s\nerror:  %s\n", status.Status, status.Broker, status.Error)
	}
	if !status.OK {
		return 1
	}
	return 0
}

func cmdPubSubPublish(args []string) int {
	fs := flag.NewFlagSet("pubsub publish", flag.ContinueOnError)
	broker := fs.String("broker", envOr("WEAVERSSH_MQTT_BROKER", "mqtt://127.0.0.1:1883"), "MQTT broker URL")
	clientID := fs.String("client-id", envOr("WEAVERSSH_MQTT_CLIENT_ID", ""), "MQTT client id")
	username := fs.String("username", envOr("WEAVERSSH_MQTT_USERNAME", ""), "MQTT username")
	password := fs.String("password", envOr("WEAVERSSH_MQTT_PASSWORD", ""), "MQTT password")
	prefix := fs.String("prefix", envOr("WEAVERSSH_MQTT_TOPIC_PREFIX", pubsub.DefaultPrefix), "topic prefix when --topic is omitted")
	topic := fs.String("topic", "", "MQTT publish topic; defaults to PREFIX/component/type")
	eventType := fs.String("type", "status", "weaverssh event type")
	component := fs.String("component", "runtime", "weaverssh component name")
	message := fs.String("message", "", "human-readable event message")
	originText := fs.String("origin", string(pubsub.EventOriginInternal), "event origin: internal, external, or pubsub")
	payload := fs.String("payload", "", "raw payload; when set, --topic is required unless component/type derive one")
	timeout := fs.Duration("timeout", 5*time.Second, "connect/publish timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	dryRun := fs.Bool("dry-run", false, "print what would be published without connecting")
	insecureTLS := fs.Bool("insecure-skip-verify", false, "skip MQTT TLS certificate verification for lab brokers only")
	var fields fieldList
	fs.Var(&fields, "field", "event field as key=value; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub publish [--broker URL] [--origin internal|external|pubsub] [--component NAME] [--type TYPE] [--message TEXT] [--field K=V]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	fieldMap, err := parseFields(fields)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
		return 2
	}
	eventOrigin, err := pubsub.ParseEventOrigin(*originText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
		return 2
	}
	var event *pubsub.Event
	var body []byte
	if *payload == "" {
		e := pubsub.NewEventFrom(eventOrigin, *eventType, *component, *message, fieldMap)
		event = &e
		body, err = e.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
			return 2
		}
	} else {
		body = []byte(*payload)
	}
	selectedTopic := strings.TrimSpace(*topic)
	if selectedTopic == "" {
		selectedTopic, err = pubsub.EventTopic(*prefix, *component, *eventType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
			return 2
		}
	}
	if err := pubsub.ValidatePublishTopic(selectedTopic); err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
		return 2
	}
	result := pubSubPublishResult{OK: true, DryRun: *dryRun, Broker: *broker, Topic: selectedTopic, Event: event, Payload: string(body)}
	if *dryRun {
		return printPubSubPublishResult(result, *jsonOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := pubsub.DialMQTT(ctx, pubsub.MQTTConfig{Broker: *broker, ClientID: *clientID, Username: *username, Password: *password, ConnectTimeout: *timeout, InsecureTLS: *insecureTLS})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: connect: %v\n", err)
		return 1
	}
	defer client.Close()
	if err := client.Publish(selectedTopic, body); err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: %v\n", err)
		return 1
	}
	// QoS 0 has no publish acknowledgement. A ping round trip prevents short-lived
	// CLI publishers from closing a forwarded connection before the broker has
	// processed the publish packet.
	if err := client.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pubsub publish: confirm: %v\n", err)
		return 1
	}
	return printPubSubPublishResult(result, *jsonOut)
}

func cmdPubSubSubscribe(args []string) int {
	fs := flag.NewFlagSet("pubsub subscribe", flag.ContinueOnError)
	broker := fs.String("broker", envOr("WEAVERSSH_MQTT_BROKER", "mqtt://127.0.0.1:1883"), "MQTT broker URL")
	clientID := fs.String("client-id", envOr("WEAVERSSH_MQTT_CLIENT_ID", ""), "MQTT client id")
	username := fs.String("username", envOr("WEAVERSSH_MQTT_USERNAME", ""), "MQTT username")
	password := fs.String("password", envOr("WEAVERSSH_MQTT_PASSWORD", ""), "MQTT password")
	filter := fs.String("topic", envOr("WEAVERSSH_MQTT_SUBSCRIBE_TOPIC", pubsub.DefaultPrefix+"/#"), "MQTT topic filter")
	limit := fs.Int("limit", 1, "message limit; 0 means until timeout")
	timeout := fs.Duration("timeout", 30*time.Second, "subscribe timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	decodeEvent := fs.Bool("decode-event", true, "decode weaverssh event JSON when possible")
	insecureTLS := fs.Bool("insecure-skip-verify", false, "skip MQTT TLS certificate verification for lab brokers only")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv pubsub subscribe [--broker URL] [--topic FILTER] [--limit N] [--timeout DURATION]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := pubsub.DialMQTT(ctx, pubsub.MQTTConfig{Broker: *broker, ClientID: *clientID, Username: *username, Password: *password, ConnectTimeout: *timeout, InsecureTLS: *insecureTLS})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub subscribe: connect: %v\n", err)
		return 1
	}
	defer client.Close()
	messages, err := client.Subscribe(ctx, *filter, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsub subscribe: %v\n", err)
		return 1
	}
	results := make([]pubSubMessageResult, 0, len(messages))
	for _, msg := range messages {
		res := pubSubMessageResult{Topic: msg.Topic, Payload: string(msg.Payload)}
		if *decodeEvent {
			if event, err := pubsub.DecodeEvent(msg.Payload); err == nil {
				res.Event = &event
			}
		}
		results = append(results, res)
	}
	if *jsonOut {
		return printJSON(results)
	}
	for _, res := range results {
		fmt.Printf("topic:   %s\n", res.Topic)
		if res.Event != nil {
			fmt.Printf("event:   %s %s\n", res.Event.Component, res.Event.Type)
			if res.Event.Message != "" {
				fmt.Printf("message: %s\n", res.Event.Message)
			}
		} else {
			fmt.Printf("payload: %s\n", res.Payload)
		}
	}
	if len(results) == 0 {
		fmt.Println("status: timeout/no messages")
	}
	return 0
}

func printPubSubPublishResult(result pubSubPublishResult, jsonOut bool) int {
	if jsonOut {
		return printJSON(result)
	}
	if result.DryRun {
		fmt.Println("status: dry-run")
	} else {
		fmt.Println("status: published")
	}
	fmt.Printf("broker: %s\n", result.Broker)
	fmt.Printf("topic:  %s\n", result.Topic)
	if result.Event != nil {
		fmt.Printf("event:  %s %s\n", result.Event.Component, result.Event.Type)
	}
	return 0
}

func parseFields(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range items {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("field must be key=value: %q", item)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("field key cannot be empty")
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseCSVNodes(raw string) []string {
	var nodes []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			nodes = append(nodes, part)
		}
	}
	return nodes
}

func printPubSubHelp() {
	fmt.Print(`wv pubsub - publish and subscribe weaverssh events over MQTT

Usage:
  wv pubsub plan [--prefix PREFIX] [--json]
  wv pubsub hooks-plan [--json]
  wv pubsub mesh-plan --chain NAME --nodes alice,jump,target [--scheme one-one|one-many|many-to-many] [--json]
  wv pubsub broker [--listen 127.0.0.1:1883]
  wv pubsub status [--broker mqtt://HOST:1883] [--json]
  wv pubsub publish [--broker URL] [--origin internal|external|pubsub] [--component NAME] [--type TYPE] [--message TEXT] [--field K=V]
  wv pubsub subscribe [--broker URL] [--topic FILTER] [--limit N] [--timeout 30s]

Environment:
  WEAVERSSH_MQTT_BROKER           default broker URL, e.g. mqtt://127.0.0.1:1883
  WEAVERSSH_MQTT_TOPIC_PREFIX     default topic prefix, e.g. weaverssh
  WEAVERSSH_MQTT_CLIENT_ID        client id override
  WEAVERSSH_MQTT_USERNAME         broker username
  WEAVERSSH_MQTT_PASSWORD         broker password
  WEAVERSSH_MQTT_SUBSCRIBE_TOPIC  default subscribe filter

Security:
  Use mqtts:// for TLS brokers. Plain mqtt:// is acceptable only on loopback or
  inside a protected SSH/weaverssh channel.
`)
}
