package pubsub

import (
	"context"
	"fmt"
	"strings"

	"weaverssh/rules"
)

type RulePluginConfig struct {
	ID          string        `json:"id"`
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	RuleSet     rules.RuleSet `json:"ruleset"`
	Points      []HookPoint   `json:"points,omitempty"`
	Filter      HookFilter    `json:"filter,omitempty"`
}

// NewRulePlugin adapts a deterministic ruleset into weaverssh hook handlers.
// The ruleset is evaluated only at the configured hook points. A denied/drop
// decision maps to HookDrop; allowed/rewrite/tag/audit decisions continue and
// expose rule metadata in HookDecision.Fields.
func NewRulePlugin(cfg RulePluginConfig) (Plugin, error) {
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		id = "rules"
	}
	rs, err := cfg.RuleSet.Normalize()
	if err != nil {
		return nil, err
	}
	if err := cfg.Filter.Validate(); err != nil {
		return nil, fmt.Errorf("rule plugin filter: %w", err)
	}
	points := cfg.Points
	if len(points) == 0 {
		points = []HookPoint{HookBeforePublish, HookBeforeForward, HookBeforeFileTransfer, HookOnFileTransferProgress, HookBeforeFileOperation, HookOnFileOperation, HookBeforeAPICall, HookOnAPIEvent, HookOnEventConsumed}
	}
	hooks := make([]Hook, 0, len(points))
	for _, point := range points {
		parsed, err := ParseHookPoint(string(point))
		if err != nil {
			return nil, err
		}
		p := parsed
		hooks = append(hooks, Hook{
			ID:          "rules-" + string(p),
			PluginID:    id,
			Description: "ruleset evaluation for " + string(p),
			Point:       p,
			Filter:      cfg.Filter,
			Handler: func(ctx context.Context, inv HookInvocation) (HookDecision, error) {
				decision, err := rs.Evaluate(EventRuleInput(inv.Topic, inv.Point, inv.Event))
				if err != nil {
					return HookDecision{Action: HookDrop, Reason: err.Error()}, err
				}
				return hookDecisionFromRuleDecision(decision), nil
			},
		})
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = "weaverssh rules engine"
	}
	return StaticPlugin{
		ManifestData: PluginManifest{ID: id, Name: name, Version: rules.EngineVersion, Kind: "rules", Components: []string{"pubsub", "hooks"}, Description: cfg.Description},
		HookList:     hooks,
	}, nil
}

func EventRuleInput(topic string, point HookPoint, event Event) rules.Input {
	event = event.Normalized()
	facts := map[string]string{
		"hook.point":      string(point),
		"topic":           strings.TrimSpace(topic),
		"event.id":        event.ID,
		"event.type":      event.Type,
		"event.component": event.Component,
		"event.origin":    string(event.Origin),
		"event.message":   event.Message,
		"event.version":   event.Version,
		"event.at":        event.At,
	}
	for k, v := range event.Fields {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		facts["field."+key] = v
		facts["fields."+key] = v
		if _, exists := facts[key]; !exists {
			facts[key] = v
		}
	}
	addInfrastructureAliases(facts, event)
	addEnvironmentAliases(facts, event)
	addAPIAliases(facts, event)
	return rules.NewInput(topic, facts)
}

func addInfrastructureAliases(facts map[string]string, event Event) {
	if facts == nil {
		return
	}
	if event.Component != "" {
		facts["infra.component"] = event.Component
	}
	if event.Origin != "" {
		facts["infra.origin"] = string(event.Origin)
	}
	if kind := event.Fields["kind"]; strings.TrimSpace(kind) != "" {
		facts["infra.kind"] = kind
	}
	aliases := []string{"file_id", "operation", "path", "view_path", "protocol", "subsystem", "bytes", "files", "is_dir", "status", "error"}
	for _, key := range aliases {
		value := strings.TrimSpace(event.Fields[key])
		if value == "" {
			continue
		}
		facts["infra."+key] = value
		if event.Fields["kind"] == FileOperationKind || isFileOperationEventType(event.Type) {
			facts["file."+key] = value
		}
	}
}

func addEnvironmentAliases(facts map[string]string, event Event) {
	if facts == nil {
		return
	}
	if event.Fields["kind"] != EnvironmentEventKind && event.Component != ComponentEnvironment {
		return
	}
	if event.Component != "" {
		facts["env.component"] = event.Component
	}
	if event.Origin != "" {
		facts["env.origin"] = string(event.Origin)
	}
	aliases := []string{"environment_id", "scope", "operation", "chain_id", "node_id", "host_id", "connection_id", "qos_class", "filesystem_id", "path", "data_class", "protocol", "direction", "status", "error", "bytes", "files", "latency_ms", "throughput_bps"}
	for _, key := range aliases {
		value := strings.TrimSpace(event.Fields[key])
		if value == "" {
			continue
		}
		factKey := strings.TrimPrefix(key, "environment_")
		facts["env."+factKey] = value
		switch event.Fields["scope"] {
		case string(EnvironmentScopeSystemChain):
			facts["chain."+factKey] = value
		case string(EnvironmentScopeHost):
			facts["host."+factKey] = value
		case string(EnvironmentScopeConnection):
			facts["connection."+factKey] = value
		case string(EnvironmentScopeQoS):
			facts["qos."+factKey] = value
		case string(EnvironmentScopeFilesystem):
			facts["filesystem."+factKey] = value
		case string(EnvironmentScopeFile):
			facts["file."+factKey] = value
		case string(EnvironmentScopeData):
			facts["data."+factKey] = value
		}
	}
}

func addAPIAliases(facts map[string]string, event Event) {
	for k, v := range APIEventFacts(event) {
		if strings.TrimSpace(v) == "" {
			continue
		}
		facts[k] = v
	}
}

func isFileOperationEventType(eventType string) bool {
	switch FileOperation(strings.TrimSpace(eventType)) {
	case FileCreated, FileRemoved, FileOpened, FileRead, FileWritten, FileClosed, FileListed, FileStat, FileMkdir:
		return true
	default:
		return false
	}
}

func hookDecisionFromRuleDecision(decision rules.Decision) HookDecision {
	action := HookContinue
	if !decision.Allowed || decision.Action == rules.ActionDrop || decision.Action == rules.ActionDeny {
		action = HookDrop
	}
	fields := map[string]string{
		"rules.version": rules.EngineVersion,
		"rules.action":  string(decision.Action),
		"rules.allowed": fmt.Sprintf("%t", decision.Allowed),
	}
	if decision.RuleID != "" {
		fields["rules.rule_id"] = decision.RuleID
	}
	if decision.Topic != "" {
		fields["rules.topic"] = decision.Topic
	}
	for k, v := range decision.SetFields {
		fields[k] = v
	}
	if len(decision.Tags) > 0 {
		fields["rules.tags"] = strings.Join(decision.Tags, ",")
	}
	return HookDecision{Action: action, Reason: decision.Reason, Fields: fields}
}
