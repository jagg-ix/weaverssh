package pubsub

import (
	"context"
	"testing"

	"weaverssh/rules"
)

func TestRulePluginDropsDeniedHookEvent(t *testing.T) {
	plugin, err := NewRulePlugin(RulePluginConfig{
		ID: "policy-rules",
		RuleSet: rules.RuleSet{Version: rules.EngineVersion, DefaultAction: rules.ActionAllow, Rules: []rules.Rule{{
			ID:     "drop-external-auth-fault",
			Action: rules.ActionDrop,
			When: rules.Condition{All: []rules.Condition{
				{Field: "event.origin", Op: rules.OpEquals, Value: "external"},
				{Field: "event.component", Op: rules.OpEquals, Value: "authproof"},
				{Field: "event.type", Op: rules.OpEquals, Value: "fault"},
			}},
			Reason: "external authproof fault blocked",
		}}},
		Points: []HookPoint{HookBeforePublish},
	})
	if err != nil {
		t.Fatalf("NewRulePlugin: %v", err)
	}
	registry := NewHookRegistry()
	if err := registry.RegisterPlugin(plugin); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	event := NewEventFrom(EventOriginExternal, "fault", "authproof", "bad", nil)
	dispatch, err := registry.Dispatch(context.Background(), HookBeforePublish, "weaverssh/authproof/fault", event)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !dispatch.Dropped || dispatch.Matched != 1 || dispatch.Results[0].Reason != "external authproof fault blocked" {
		t.Fatalf("dispatch mismatch: %+v", dispatch)
	}
}

func TestRulePluginAllowsAndExposesSetFields(t *testing.T) {
	plugin, err := NewRulePlugin(RulePluginConfig{
		ID: "route-rules",
		RuleSet: rules.RuleSet{Version: rules.EngineVersion, Rules: []rules.Rule{{
			ID:        "tag-bulk-transfer",
			Action:    rules.ActionTag,
			When:      rules.Condition{Field: "field.bytes", Op: rules.OpGTE, Value: "1024"},
			SetFields: map[string]string{"route_class": "bulk"},
			Tags:      []string{"bulk"},
		}}},
		Points: []HookPoint{HookOnFileTransferProgress},
	})
	if err != nil {
		t.Fatalf("NewRulePlugin: %v", err)
	}
	registry := NewHookRegistry()
	if err := registry.RegisterPlugin(plugin); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	event := NewFileTransferEvent(FileTransferProgress, FileTransfer{Source: "vfs://a", Destination: "./a", Bytes: 2048})
	topic, err := EventTopic(DefaultPrefix, event.Component, event.Type)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := registry.Dispatch(context.Background(), HookOnFileTransferProgress, topic, event)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if dispatch.Dropped || dispatch.Matched != 1 || dispatch.Results[0].Action != HookContinue {
		t.Fatalf("dispatch mismatch: %+v", dispatch)
	}
}

func TestEventRuleInputIncludesEventAndFieldFacts(t *testing.T) {
	event := NewEventFrom(EventOriginPubSub, "status", "runtime", "ready", map[string]string{"plane": "ok"})
	input := EventRuleInput("weaverssh/runtime/status", HookBeforeForward, event)
	checks := map[string]string{
		"topic":           "weaverssh/runtime/status",
		"hook.point":      string(HookBeforeForward),
		"event.origin":    string(EventOriginPubSub),
		"event.component": "runtime",
		"event.type":      "status",
		"field.plane":     "ok",
		"fields.plane":    "ok",
		"plane":           "ok",
	}
	for key, want := range checks {
		got, ok := input.Value(key)
		if !ok || got != want {
			t.Fatalf("input fact %s=(%q,%t), want %q", key, got, ok, want)
		}
	}
}

func TestEventRuleInputIncludesInfrastructureFileAliases(t *testing.T) {
	event := NewFileEvent(FileRead, FileEvent{Path: "vfs://docs/readme.md", ViewPath: "docs/readme.md", Component: ComponentVFS, Protocol: "vfs-9p", Bytes: 128})
	input := EventRuleInput("weaverssh/vfs/file_read", HookBeforeFileOperation, event)
	checks := map[string]string{
		"event.component": "vfs",
		"infra.kind":      FileOperationKind,
		"infra.operation": string(FileRead),
		"infra.path":      "vfs://docs/readme.md",
		"infra.protocol":  "vfs-9p",
		"file.operation":  string(FileRead),
		"file.path":       "vfs://docs/readme.md",
		"file.view_path":  "docs/readme.md",
		"file.bytes":      "128",
	}
	for key, want := range checks {
		got, ok := input.Value(key)
		if !ok || got != want {
			t.Fatalf("input fact %s=(%q,%t), want %q", key, got, ok, want)
		}
	}
}

func TestEventRuleInputIncludesEnvironmentAliases(t *testing.T) {
	event := NewEnvironmentEvent(EnvironmentScopeQoS, "pressure", EnvironmentEvent{NodeID: "node-a", QoSClass: "realtime", LatencyMillis: 120, ThroughputBPS: 2048})
	input := EventRuleInput("weaverssh/environment/qos_pressure", HookOnEnvironmentEvent, event)
	checks := map[string]string{
		"event.component":    "environment",
		"env.scope":          "qos",
		"env.operation":      "pressure",
		"env.node_id":        "node-a",
		"env.qos_class":      "realtime",
		"env.latency_ms":     "120",
		"env.throughput_bps": "2048",
		"qos.scope":          "qos",
		"qos.operation":      "pressure",
		"qos.qos_class":      "realtime",
	}
	for key, want := range checks {
		got, ok := input.Value(key)
		if !ok || got != want {
			t.Fatalf("input fact %s=(%q,%t), want %q", key, got, ok, want)
		}
	}
}
