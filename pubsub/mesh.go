package pubsub

import (
	"fmt"
	"strings"
)

const (
	MeshEnvelopeVersion      = "weaverssh.pubsub.mesh.v1"
	DefaultMaxHops           = 16
	SingleSSHSocketChainMode = "single-ssh-x11-websocket-chain"
)

type RuleAction string

type MeshScheme string

type ChainLink struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Transport string `json:"transport"`
}

const (
	RuleAllow   RuleAction = "allow"
	RuleDeny    RuleAction = "deny"
	RuleRewrite RuleAction = "rewrite"

	SchemeOneOne     MeshScheme = "one-one"
	SchemeOneMany    MeshScheme = "one-many"
	SchemeManyToMany MeshScheme = "many-to-many"
)

// MeshEnvelope carries a weaverssh event across MQTT brokers attached to each
// X11/WebSocket agent hop. It is the loop-protected payload that can be
// republished by each agent into its local broker or forwarded to the next link.
type MeshEnvelope struct {
	Version      string   `json:"version"`
	ChainID      string   `json:"chain_id"`
	NodeID       string   `json:"node_id"`
	OriginNodeID string   `json:"origin_node_id"`
	Hop          int      `json:"hop"`
	MaxHops      int      `json:"max_hops"`
	Path         []string `json:"path"`
	Topic        string   `json:"topic"`
	Event        Event    `json:"event"`
}

// RouteRule controls which messages an agent may forward toward another node.
// Empty FromNode/ToNode means any. TopicFilter uses MQTT subscribe wildcard
// syntax. RewriteTopic is used only for the rewrite action.
type RouteRule struct {
	ID           string     `json:"id"`
	Action       RuleAction `json:"action"`
	OriginNode   string     `json:"origin_node,omitempty"`
	FromNode     string     `json:"from_node,omitempty"`
	ToNode       string     `json:"to_node,omitempty"`
	TopicFilter  string     `json:"topic_filter"`
	RewriteTopic string     `json:"rewrite_topic,omitempty"`
}

type RuleDecision struct {
	Allowed bool       `json:"allowed"`
	Action  RuleAction `json:"action"`
	RuleID  string     `json:"rule_id,omitempty"`
	Topic   string     `json:"topic"`
	Reason  string     `json:"reason,omitempty"`
}

func ParseMeshScheme(value string) (MeshScheme, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return SchemeOneOne, nil
	}
	scheme := MeshScheme(value)
	switch scheme {
	case SchemeOneOne, SchemeOneMany, SchemeManyToMany:
		return scheme, nil
	default:
		return "", fmt.Errorf("unsupported mesh scheme %q; expected one-one, one-many, or many-to-many", value)
	}
}

func (s MeshScheme) Description() string {
	switch s {
	case SchemeOneOne:
		return "single logical origin flows over the single SSH/X11/WebSocket chain toward one endpoint"
	case SchemeOneMany:
		return "first listed node fans out events downstream over the same single SSH/X11/WebSocket chain"
	case SchemeManyToMany:
		return "every node may publish logically, but messages still traverse bidirectional adjacent hops on the same single SSH/X11/WebSocket chain"
	default:
		return "unknown pub-sub mesh scheme"
	}
}

func NewMeshEnvelope(prefix, chainID, nodeID string, event Event, maxHops int) (MeshEnvelope, error) {
	chainID = cleanTopicPart(chainID)
	nodeID = cleanTopicPart(nodeID)
	if chainID == "" {
		return MeshEnvelope{}, fmt.Errorf("chain id is required")
	}
	if nodeID == "" {
		return MeshEnvelope{}, fmt.Errorf("node id is required")
	}
	if maxHops <= 0 {
		maxHops = DefaultMaxHops
	}
	if err := event.Validate(); err != nil {
		return MeshEnvelope{}, err
	}
	topic, err := NodeEventTopic(prefix, chainID, nodeID, event.Component, event.Type)
	if err != nil {
		return MeshEnvelope{}, err
	}
	return MeshEnvelope{
		Version:      MeshEnvelopeVersion,
		ChainID:      chainID,
		NodeID:       nodeID,
		OriginNodeID: nodeID,
		Hop:          0,
		MaxHops:      maxHops,
		Path:         []string{nodeID},
		Topic:        topic,
		Event:        event,
	}, nil
}

func (e MeshEnvelope) Validate() error {
	if e.Version != MeshEnvelopeVersion {
		return fmt.Errorf("unsupported mesh envelope version %q", e.Version)
	}
	if strings.TrimSpace(e.ChainID) == "" {
		return fmt.Errorf("chain id is required")
	}
	if strings.TrimSpace(e.NodeID) == "" {
		return fmt.Errorf("node id is required")
	}
	if strings.TrimSpace(e.OriginNodeID) == "" {
		return fmt.Errorf("origin node id is required")
	}
	if e.MaxHops <= 0 {
		return fmt.Errorf("max hops must be positive")
	}
	if e.Hop < 0 || e.Hop > e.MaxHops {
		return fmt.Errorf("hop count %d exceeds max hops %d", e.Hop, e.MaxHops)
	}
	if len(e.Path) == 0 {
		return fmt.Errorf("path is required")
	}
	if !containsString(e.Path, e.NodeID) {
		return fmt.Errorf("path must include current node %q", e.NodeID)
	}
	if err := ValidatePublishTopic(e.Topic); err != nil {
		return err
	}
	return e.Event.Validate()
}

func (e MeshEnvelope) ForwardTo(prefix, nextNode string) (MeshEnvelope, error) {
	if err := e.Validate(); err != nil {
		return MeshEnvelope{}, err
	}
	nextNode = cleanTopicPart(nextNode)
	if nextNode == "" {
		return MeshEnvelope{}, fmt.Errorf("next node is required")
	}
	if containsString(e.Path, nextNode) {
		return MeshEnvelope{}, fmt.Errorf("refusing to forward to %q: loop detected in path %v", nextNode, e.Path)
	}
	if e.Hop+1 > e.MaxHops {
		return MeshEnvelope{}, fmt.Errorf("refusing to forward to %q: max hops %d reached", nextNode, e.MaxHops)
	}
	topic, err := NodeEventTopic(prefix, e.ChainID, nextNode, e.Event.Component, e.Event.Type)
	if err != nil {
		return MeshEnvelope{}, err
	}
	out := e
	out.NodeID = nextNode
	out.Hop++
	out.Path = append(append([]string(nil), e.Path...), nextNode)
	out.Topic = topic
	return out, nil
}

func ForwardWithRules(prefix string, envelope MeshEnvelope, nextNode string, rules []RouteRule) (MeshEnvelope, RuleDecision, error) {
	decision, err := DecideRoute(envelope, nextNode, rules)
	if err != nil {
		return MeshEnvelope{}, decision, err
	}
	if !decision.Allowed {
		return MeshEnvelope{}, decision, fmt.Errorf("route denied: %s", decision.Reason)
	}
	forwarded, err := envelope.ForwardTo(prefix, nextNode)
	if err != nil {
		return MeshEnvelope{}, decision, err
	}
	if decision.Topic != "" && decision.Topic != envelope.Topic {
		if err := ValidatePublishTopic(decision.Topic); err != nil {
			return MeshEnvelope{}, decision, err
		}
		forwarded.Topic = decision.Topic
	}
	return forwarded, decision, nil
}

func DecideRoute(envelope MeshEnvelope, nextNode string, rules []RouteRule) (RuleDecision, error) {
	if err := envelope.Validate(); err != nil {
		return RuleDecision{Allowed: false, Action: RuleDeny, Topic: envelope.Topic, Reason: err.Error()}, err
	}
	nextNode = cleanTopicPart(nextNode)
	if nextNode == "" {
		return RuleDecision{Allowed: false, Action: RuleDeny, Topic: envelope.Topic, Reason: "next node is required"}, nil
	}
	for _, rule := range rules {
		if !ruleMatches(rule, envelope, nextNode) {
			continue
		}
		action := rule.Action
		if action == "" {
			action = RuleDeny
		}
		switch action {
		case RuleAllow:
			return RuleDecision{Allowed: true, Action: action, RuleID: rule.ID, Topic: envelope.Topic}, nil
		case RuleRewrite:
			if strings.TrimSpace(rule.RewriteTopic) == "" {
				return RuleDecision{Allowed: false, Action: action, RuleID: rule.ID, Topic: envelope.Topic, Reason: "rewrite rule has no target topic"}, nil
			}
			return RuleDecision{Allowed: true, Action: action, RuleID: rule.ID, Topic: strings.TrimSpace(rule.RewriteTopic)}, nil
		case RuleDeny:
			return RuleDecision{Allowed: false, Action: action, RuleID: rule.ID, Topic: envelope.Topic, Reason: "matched deny rule"}, nil
		default:
			return RuleDecision{Allowed: false, Action: action, RuleID: rule.ID, Topic: envelope.Topic, Reason: fmt.Sprintf("unknown rule action %q", action)}, nil
		}
	}
	return RuleDecision{Allowed: false, Action: RuleDeny, Topic: envelope.Topic, Reason: "no route rule matched"}, nil
}

func NodeEventTopic(prefix, chainID, nodeID, component, eventType string) (string, error) {
	prefix = cleanTopicPart(prefix)
	if prefix == "" {
		prefix = DefaultPrefix
	}
	chainID = cleanTopicPart(chainID)
	nodeID = cleanTopicPart(nodeID)
	component = cleanTopicPart(component)
	eventType = cleanTopicPart(eventType)
	if chainID == "" || nodeID == "" || component == "" || eventType == "" {
		return "", fmt.Errorf("chain id, node id, component, and event type are required")
	}
	topic := strings.Join([]string{prefix, "chains", chainID, "nodes", nodeID, component, eventType}, "/")
	return topic, ValidatePublishTopic(topic)
}

func ChainSubscribeFilter(prefix, chainID string) (string, error) {
	prefix = cleanTopicPart(prefix)
	if prefix == "" {
		prefix = DefaultPrefix
	}
	chainID = cleanTopicPart(chainID)
	if chainID == "" {
		return "", fmt.Errorf("chain id is required")
	}
	filter := strings.Join([]string{prefix, "chains", chainID, "#"}, "/")
	return filter, ValidateSubscribeTopic(filter)
}

func DefaultChainRules(prefix, chainID string, nodes []string) ([]RouteRule, error) {
	return ChainRulesForScheme(prefix, chainID, nodes, SchemeOneOne)
}

func ChainLinks(nodes []string) ([]ChainLink, error) {
	nodes, err := cleanNodeList(nodes)
	if err != nil {
		return nil, err
	}
	links := make([]ChainLink, 0, len(nodes)-1)
	for i := 0; i < len(nodes)-1; i++ {
		links = append(links, ChainLink{
			From:      nodes[i],
			To:        nodes[i+1],
			Transport: SingleSSHSocketChainMode,
		})
	}
	return links, nil
}

func RulesUseOnlyAdjacentLinks(rules []RouteRule, links []ChainLink) bool {
	allowed := map[string]struct{}{}
	for _, link := range links {
		allowed[link.From+"->"+link.To] = struct{}{}
		allowed[link.To+"->"+link.From] = struct{}{}
	}
	for _, rule := range rules {
		if strings.TrimSpace(rule.FromNode) == "" || strings.TrimSpace(rule.ToNode) == "" {
			return false
		}
		key := cleanTopicPart(rule.FromNode) + "->" + cleanTopicPart(rule.ToNode)
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func ChainRulesForScheme(prefix, chainID string, nodes []string, scheme MeshScheme) ([]RouteRule, error) {
	scheme, err := ParseMeshScheme(string(scheme))
	if err != nil {
		return nil, err
	}
	nodes, err = cleanNodeList(nodes)
	if err != nil {
		return nil, err
	}
	filter, err := ChainSubscribeFilter(prefix, chainID)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case SchemeOneOne:
		return directionalChainRules("one-one", nodes[0], nodes, filter), nil
	case SchemeOneMany:
		return directionalChainRules("one-many", nodes[0], nodes, filter), nil
	case SchemeManyToMany:
		rules := make([]RouteRule, 0, (len(nodes)-1)*2)
		for i := 0; i < len(nodes)-1; i++ {
			rules = append(rules, allowRule("many-to-many", "", nodes[i], nodes[i+1], filter))
			rules = append(rules, allowRule("many-to-many", "", nodes[i+1], nodes[i], filter))
		}
		return rules, nil
	default:
		return nil, fmt.Errorf("unsupported mesh scheme %q", scheme)
	}
}

func directionalChainRules(prefix string, origin string, nodes []string, filter string) []RouteRule {
	rules := make([]RouteRule, 0, len(nodes)-1)
	for i := 0; i < len(nodes)-1; i++ {
		rules = append(rules, allowRule(prefix, origin, nodes[i], nodes[i+1], filter))
	}
	return rules
}

func allowRule(prefix string, origin string, from string, to string, filter string) RouteRule {
	id := fmt.Sprintf("%s-%s-to-%s", prefix, from, to)
	return RouteRule{
		ID:          id,
		Action:      RuleAllow,
		OriginNode:  origin,
		FromNode:    from,
		ToNode:      to,
		TopicFilter: filter,
	}
}

func cleanNodeList(nodes []string) ([]string, error) {
	if len(nodes) < 2 {
		return nil, fmt.Errorf("at least two nodes are required")
	}
	out := make([]string, 0, len(nodes))
	seen := map[string]struct{}{}
	for _, node := range nodes {
		node = cleanTopicPart(node)
		if node == "" {
			return nil, fmt.Errorf("node names cannot be empty")
		}
		if _, ok := seen[node]; ok {
			return nil, fmt.Errorf("duplicate node %q", node)
		}
		seen[node] = struct{}{}
		out = append(out, node)
	}
	return out, nil
}

func ruleMatches(rule RouteRule, envelope MeshEnvelope, nextNode string) bool {
	if strings.TrimSpace(rule.OriginNode) != "" && cleanTopicPart(rule.OriginNode) != envelope.OriginNodeID {
		return false
	}
	if strings.TrimSpace(rule.FromNode) != "" && cleanTopicPart(rule.FromNode) != envelope.NodeID {
		return false
	}
	if strings.TrimSpace(rule.ToNode) != "" && cleanTopicPart(rule.ToNode) != nextNode {
		return false
	}
	filter := strings.TrimSpace(rule.TopicFilter)
	if filter == "" {
		return false
	}
	return TopicMatches(filter, envelope.Topic)
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
