package sessionevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"weaverssh/pubsub"
)

const (
	ProtocolVersion      = "weaverssh.events.v1"
	OpenProtocolVersion  = "weaverssh.events-open.v1"
	PolicyVersion        = "weaverssh.events-policy.v1"
	OperationPublish     = "publish"
	OperationSubscribe   = "subscribe"
	MaxOpenMetadataBytes = 4096
	MaxMessageBytes      = 2 << 20
	MaxPayloadBytes      = 1 << 20
	MaxSubscriptionLimit = 100000
)

var (
	ErrInvalidRequest = errors.New("sessionevents: invalid request")
	ErrDenied         = errors.New("sessionevents: denied")
	ErrLimitExceeded  = errors.New("sessionevents: limit exceeded")
)

type OpenMetadata struct {
	Protocol      string `json:"protocol"`
	TargetNode    string `json:"target_node"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
}
type Request struct {
	Protocol  string `json:"protocol"`
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Topic     string `json:"topic"`
	Payload   []byte `json:"payload,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Buffer    int    `json:"buffer,omitempty"`
}
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Response struct {
	Protocol  string         `json:"protocol"`
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Topic     string         `json:"topic,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
	Delivered int            `json:"delivered,omitempty"`
	Error     *ResponseError `json:"error,omitempty"`
}

type Policy struct {
	Version string `json:"version"`
	Default string `json:"default"`
	Rules   []Rule `json:"rules"`
}
type Rule struct {
	ID         string   `json:"id"`
	Action     string   `json:"action"`
	Sources    []string `json:"sources"`
	Operations []string `json:"operations"`
	Topics     []string `json:"topics"`
}
type EngineConfig struct {
	Topology    []string
	ChainSHA256 string
	CurrentNode string
	Policy      Policy
	Bus         *pubsub.Bus
}
type Engine struct {
	topology    []string
	chainSHA256 string
	currentNode string
	policy      Policy
	bus         *pubsub.Bus
}

func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := decodeStrict(data, &p); err != nil {
		return Policy{}, err
	}
	if p.Version != PolicyVersion || strings.ToLower(strings.TrimSpace(p.Default)) != "deny" {
		return Policy{}, errors.New("sessionevents: policy must use version weaverssh.events-policy.v1 and default deny")
	}
	if len(p.Rules) == 0 {
		return Policy{}, errors.New("sessionevents: policy has no rules")
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.ID == "" || seen[r.ID] || (r.Action != "allow" && r.Action != "deny") {
			return Policy{}, fmt.Errorf("sessionevents: invalid rule %q", r.ID)
		}
		seen[r.ID] = true
		if len(r.Sources) == 0 || len(r.Operations) == 0 || len(r.Topics) == 0 {
			return Policy{}, fmt.Errorf("sessionevents: rule %s is incomplete", r.ID)
		}
		for _, source := range r.Sources {
			if source != "*" && !validName(source) {
				return Policy{}, fmt.Errorf("sessionevents: rule %s has invalid source", r.ID)
			}
		}
		for _, operation := range r.Operations {
			if operation != OperationPublish && operation != OperationSubscribe {
				return Policy{}, fmt.Errorf("sessionevents: rule %s has invalid operation", r.ID)
			}
		}
		for _, topic := range r.Topics {
			if err := pubsub.ValidateSubscribeTopic(topic); err != nil {
				return Policy{}, fmt.Errorf("sessionevents: rule %s topic: %w", r.ID, err)
			}
		}
	}
	return p, nil
}

func LoadPolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(data)
}

func NewEngine(config EngineConfig) (*Engine, error) {
	chain := strings.ToLower(strings.TrimSpace(config.ChainSHA256))
	current := strings.TrimSpace(config.CurrentNode)
	if len(chain) != 64 || indexOf(config.Topology, current) < 0 {
		return nil, errors.New("sessionevents: invalid topology")
	}
	if config.Bus == nil {
		config.Bus = pubsub.NewBus()
	}
	return &Engine{topology: append([]string(nil), config.Topology...), chainSHA256: chain, currentNode: current, policy: config.Policy, bus: config.Bus}, nil
}

func (e *Engine) Bus() *pubsub.Bus {
	if e == nil {
		return nil
	}
	return e.bus
}

func NewOpenMetadata(target string) ([]byte, error) {
	metadata := OpenMetadata{Protocol: OpenProtocolVersion, TargetNode: strings.TrimSpace(target)}
	if !validName(metadata.TargetNode) {
		return nil, errors.New("sessionevents: invalid target")
	}
	return json.Marshal(metadata)
}

func ParseOpenMetadata(raw []byte) (OpenMetadata, error) {
	if len(raw) == 0 || len(raw) > MaxOpenMetadataBytes {
		return OpenMetadata{}, errors.New("sessionevents: invalid open metadata size")
	}
	var metadata OpenMetadata
	if err := decodeStrict(raw, &metadata); err != nil {
		return OpenMetadata{}, err
	}
	metadata.Protocol = strings.TrimSpace(metadata.Protocol)
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	if metadata.Protocol != OpenProtocolVersion || !validName(metadata.TargetNode) {
		return OpenMetadata{}, errors.New("sessionevents: invalid open metadata")
	}
	return metadata, nil
}

func IsOpenMetadata(raw []byte) bool {
	metadata, err := ParseOpenMetadata(raw)
	return err == nil && metadata.Protocol == OpenProtocolVersion
}

func BindSource(raw []byte, source, binding, chain, target string) ([]byte, error) {
	metadata, err := ParseOpenMetadata(raw)
	if err != nil {
		return nil, err
	}
	chain = strings.ToLower(strings.TrimSpace(chain))
	if metadata.SourceNode == "" && metadata.SourceBinding == "" && metadata.ChainSHA256 == "" {
		metadata.SourceNode = strings.TrimSpace(source)
		metadata.SourceBinding = strings.TrimSpace(binding)
		metadata.ChainSHA256 = chain
	} else if metadata.ChainSHA256 != chain {
		return nil, errors.New("sessionevents: forwarded provenance chain mismatch")
	}
	metadata.TargetNode = strings.TrimSpace(target)
	if !validName(metadata.SourceNode) || !validName(metadata.TargetNode) || metadata.SourceBinding == "" || len(metadata.SourceBinding) > 512 || len(metadata.ChainSHA256) != 64 {
		return nil, errors.New("sessionevents: invalid broker provenance")
	}
	return json.Marshal(metadata)
}

func (e *Engine) authorize(metadata OpenMetadata, request Request) error {
	if e == nil || metadata.TargetNode != e.currentNode || metadata.ChainSHA256 != e.chainSHA256 || indexOf(e.topology, metadata.SourceNode) < 0 {
		return ErrDenied
	}
	allowed := false
	for _, rule := range e.policy.Rules {
		if !sourceMatches(rule.Sources, metadata.SourceNode) || !contains(rule.Operations, request.Operation) {
			continue
		}
		matched := false
		for _, topic := range rule.Topics {
			if request.Operation == OperationPublish {
				matched = pubsub.TopicMatches(topic, request.Topic)
			} else {
				matched = filterCovered(topic, request.Topic)
			}
			if matched {
				break
			}
		}
		if !matched {
			continue
		}
		if rule.Action == "deny" {
			return ErrDenied
		}
		allowed = true
	}
	if !allowed {
		return ErrDenied
	}
	if err := e.authorizeRuntime(context.Background(), metadata, request); err != nil {
		return err
	}
	return nil
}
