package pubsub

import (
	"context"
	"errors"
	"testing"

	"weaverssh/rules"
)

func TestAPIEventContractAndFacts(t *testing.T) {
	event := NewAPIEvent(APIStarted, APIEvent{NodeID: "linode-a", API: "connections", Operation: "start", Subject: "profile-a", Fields: map[string]string{"attempt": "2"}})
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if event.Component != ComponentAPI || event.Type != string(APIStarted) {
		t.Fatalf("unexpected event: %+v", event)
	}
	input := EventRuleInput("weaverssh/api/api_started", HookBeforeAPICall, event)
	checks := map[string]string{
		"api.name":      "connections",
		"api.operation": "start",
		"api.subject":   "profile-a",
		"api.node_id":   "linode-a",
		"api.phase":     string(APIStarted),
		"api.attempt":   "2",
	}
	for key, want := range checks {
		got, ok := input.Value(key)
		if !ok || got != want {
			t.Fatalf("%s=(%q,%t), want %q", key, got, ok, want)
		}
	}
}

func TestRunAPICallCanBeDeniedByRulePlugin(t *testing.T) {
	plugin, err := NewRulePlugin(RulePluginConfig{
		ID: "api-policy",
		RuleSet: rules.RuleSet{Version: rules.EngineVersion, DefaultAction: rules.ActionAllow, Rules: []rules.Rule{{
			ID:     "deny-dangerous-on-node",
			Action: rules.ActionDeny,
			When: rules.Condition{All: []rules.Condition{
				{Field: "api.node_id", Value: "linode-a"},
				{Field: "api.name", Value: "dangerous"},
			}},
		}}},
		Points: []HookPoint{HookBeforeAPICall},
	})
	if err != nil {
		t.Fatalf("NewRulePlugin: %v", err)
	}
	api := NewAPI(APIConfig{})
	if err := api.RegisterPlugin(plugin); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	called := false
	_, err = api.RunAPICall(context.Background(), APIEvent{NodeID: "linode-a", API: "dangerous", Operation: "start"}, func(context.Context) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrEventDropped) {
		t.Fatalf("RunAPICall error=%v want ErrEventDropped", err)
	}
	if called {
		t.Fatal("denied API operation should not run")
	}
}

func TestEmitAPIEventPublishes(t *testing.T) {
	bus := NewBus()
	api := NewAPI(APIConfig{Prefix: "weaverssh", Publisher: bus})
	ch, cancel, err := bus.Subscribe("weaverssh/api/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	result, err := api.EmitAPIEvent(context.Background(), APICompleted, APIEvent{API: "connections", Operation: "scan", Status: "completed"})
	if err != nil {
		t.Fatalf("EmitAPIEvent: %v", err)
	}
	if result.Topic != "weaverssh/api/api_completed" {
		t.Fatalf("unexpected topic: %+v", result)
	}
	select {
	case msg := <-ch:
		event, err := DecodeEvent(msg.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if event.Fields["api"] != "connections" || event.Fields["operation"] != "scan" {
			t.Fatalf("unexpected event fields: %+v", event.Fields)
		}
	default:
		t.Fatal("expected api event")
	}
}
