package pubsub

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"weaverssh/rules"
)

func TestEventConsumerPlansAPICallIntentFromRemoteNodeRules(t *testing.T) {
	root := t.TempDir()
	nodeDir := filepath.Join(root, "nodes", "linode-a", "rules.d")
	writeConsumerRule(t, filepath.Join(nodeDir, "10-trigger.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{
    "id":"trigger-scan-on-status",
    "action":"tag",
    "when":{"all":[{"field":"event.component","value":"runtime"},{"field":"event.type","value":"status"}]},
    "set_fields":{"intent.api":"connections","intent.operation":"scan","intent.subject":"local"}
  }]
}`)
	cfg := rules.PipelineConfig{Version: rules.PipelineVersion, NodeID: "linode-a", Stages: []rules.StageConfig{
		{Name: "remote-node", Paths: []string{filepath.Join(root, "nodes", "{node}", "rules.d", "*.json")}},
	}}
	consumer, err := NewEventConsumer(EventConsumerConfig{NodeID: "linode-a", Pipeline: cfg})
	if err != nil {
		t.Fatalf("NewEventConsumer: %v", err)
	}
	plan, err := consumer.PlanEvent(context.Background(), EventConsumeRequest{Topic: "weaverssh/runtime/status", Event: NewEvent("status", "runtime", "ready", nil)})
	if err != nil {
		t.Fatalf("PlanEvent: %v", err)
	}
	if !plan.Decision.Allowed || len(plan.Intents) != 1 {
		t.Fatalf("expected one allowed intent: %+v", plan)
	}
	intent := plan.Intents[0]
	if intent.API != "connections" || intent.Operation != "scan" || intent.NodeID != "linode-a" || intent.RuleID != "trigger-scan-on-status" {
		t.Fatalf("unexpected intent: %+v", intent)
	}
}

func TestEventConsumerDoesNotPlanIntentWhenPipelineDenies(t *testing.T) {
	root := t.TempDir()
	nodeDir := filepath.Join(root, "nodes", "linode-a", "rules.d")
	writeConsumerRule(t, filepath.Join(nodeDir, "10-deny.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"deny-status","action":"deny","when":{"field":"event.type","value":"status"},"set_fields":{"intent.api":"connections"}}]
}`)
	cfg := rules.PipelineConfig{Version: rules.PipelineVersion, NodeID: "linode-a", Stages: []rules.StageConfig{
		{Name: "remote-node", Paths: []string{filepath.Join(root, "nodes", "{node}", "rules.d", "*.json")}},
	}}
	consumer, err := NewEventConsumer(EventConsumerConfig{NodeID: "linode-a", Pipeline: cfg})
	if err != nil {
		t.Fatalf("NewEventConsumer: %v", err)
	}
	plan, err := consumer.PlanEvent(context.Background(), EventConsumeRequest{Topic: "weaverssh/runtime/status", Event: NewEvent("status", "runtime", "ready", nil)})
	if err != nil {
		t.Fatalf("PlanEvent: %v", err)
	}
	if plan.Decision.Allowed || len(plan.Intents) != 0 {
		t.Fatalf("denied decision should not produce intents: %+v", plan)
	}
}

func TestAPIIntentExecutorExecutesTrustedHandler(t *testing.T) {
	root := t.TempDir()
	nodeDir := filepath.Join(root, "nodes", "linode-a", "rules.d")
	writeConsumerRule(t, filepath.Join(nodeDir, "10-trigger.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"trigger","action":"tag","set_fields":{"intent.api":"connections","intent.operation":"scan"}}]
}`)
	cfg := rules.PipelineConfig{Version: rules.PipelineVersion, NodeID: "linode-a", Stages: []rules.StageConfig{
		{Name: "remote-node", Paths: []string{filepath.Join(root, "nodes", "{node}", "rules.d", "*.json")}},
	}}
	var called APICallIntent
	consumer, err := NewEventConsumer(EventConsumerConfig{
		NodeID:   "linode-a",
		Pipeline: cfg,
	})
	if err != nil {
		t.Fatalf("NewEventConsumer: %v", err)
	}
	plan, err := consumer.PlanEvent(context.Background(), EventConsumeRequest{Topic: "weaverssh/runtime/status", Event: NewEvent("status", "runtime", "ready", nil)})
	if err != nil {
		t.Fatalf("PlanEvent: %v", err)
	}
	executor, err := NewAPIIntentExecutor(APIIntentExecutorConfig{
		API: NewAPI(APIConfig{}),
		Handler: func(ctx context.Context, intent APICallIntent) error {
			called = intent
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewAPIIntentExecutor: %v", err)
	}
	results, err := executor.ExecutePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if called.API != "connections" || len(results) != 1 || !results[0].Executed {
		t.Fatalf("handler/intent mismatch called=%+v results=%+v", called, results)
	}
}

func writeConsumerRule(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEventConsumerRequiresContext(t *testing.T) {
	consumer, err := NewEventConsumer(EventConsumerConfig{})
	if err != nil {
		t.Fatalf("NewEventConsumer: %v", err)
	}
	_, err = consumer.PlanEvent(nil, EventConsumeRequest{Event: NewEvent("status", "runtime", "ready", nil)})
	if err == nil {
		t.Fatalf("PlanEvent with nil context should fail")
	}
}

func TestAPICallIntentsAcceptLegacyTriggerFields(t *testing.T) {
	root := t.TempDir()
	nodeDir := filepath.Join(root, "nodes", "linode-a", "rules.d")
	writeConsumerRule(t, filepath.Join(nodeDir, "10-trigger.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"legacy-trigger","action":"tag","set_fields":{"trigger.api":"connections","trigger.operation":"scan"}}]
}`)
	cfg := rules.PipelineConfig{Version: rules.PipelineVersion, NodeID: "linode-a", Stages: []rules.StageConfig{
		{Name: "remote-node", Paths: []string{filepath.Join(root, "nodes", "{node}", "rules.d", "*.json")}},
	}}
	consumer, err := NewEventConsumer(EventConsumerConfig{NodeID: "linode-a", Pipeline: cfg})
	if err != nil {
		t.Fatalf("NewEventConsumer: %v", err)
	}
	plan, err := consumer.PlanEvent(context.Background(), EventConsumeRequest{Topic: "weaverssh/runtime/status", Event: NewEvent("status", "runtime", "ready", nil)})
	if err != nil {
		t.Fatalf("PlanEvent: %v", err)
	}
	if len(plan.Intents) != 1 || plan.Intents[0].API != "connections" {
		t.Fatalf("legacy trigger fields should map to intents: %+v", plan.Intents)
	}
}
