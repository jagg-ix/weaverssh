package rules

import (
	"strings"
	"testing"
)

func TestRuleSetAllowsFirstMatchingRule(t *testing.T) {
	rs := RuleSet{Version: EngineVersion, DefaultAction: ActionDeny, Rules: []Rule{
		{ID: "deny-external", Action: ActionDrop, When: Condition{Field: "event.origin", Op: OpEquals, Value: "external"}},
		{ID: "allow-runtime", Action: ActionAllow, When: Condition{All: []Condition{
			{Field: "event.origin", Op: OpEquals, Value: "internal"},
			{Field: "event.component", Op: OpEquals, Value: "runtime"},
		}}},
	}}
	decision, err := rs.Evaluate(NewInput("weaverssh/runtime/status", map[string]string{"event.origin": "internal", "event.component": "runtime"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed || decision.RuleID != "allow-runtime" || decision.Action != ActionAllow {
		t.Fatalf("decision mismatch: %+v", decision)
	}
}

func TestRuleSetDefaultsToDenyWhenNoRuleMatches(t *testing.T) {
	decision, err := (RuleSet{Version: EngineVersion, Rules: []Rule{{ID: "allow-status", Action: ActionAllow, When: Condition{Field: "event.type", Value: "status"}}}}).Evaluate(NewInput("weaverssh/runtime/fault", map[string]string{"event.type": "fault"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || decision.Action != ActionDeny || decision.Matched {
		t.Fatalf("default deny decision wrong: %+v", decision)
	}
}

func TestRuleConditionsSupportTopicAndNumericComparisons(t *testing.T) {
	rs := RuleSet{Version: EngineVersion, Rules: []Rule{{
		ID:     "tag-large-vfs-transfer",
		Action: ActionTag,
		When: Condition{All: []Condition{
			{Op: OpTopicMatches, Value: "weaverssh/vfs/#"},
			{Field: "field.bytes", Op: OpGTE, Value: "1024"},
		}},
		SetFields: map[string]string{"route_class": "bulk"},
		Tags:      []string{"bulk"},
	}}}
	decision, err := rs.Evaluate(NewInput("weaverssh/vfs/file_transfer_progress", map[string]string{"field.bytes": "4096"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed || decision.Fields["route_class"] != "bulk" || len(decision.Tags) != 1 || decision.Tags[0] != "bulk" {
		t.Fatalf("tag decision wrong: %+v", decision)
	}
}

func TestRuleRewriteRequiresTopicAndCanRewrite(t *testing.T) {
	rs := RuleSet{Version: EngineVersion, Rules: []Rule{{ID: "rewrite", Action: ActionRewrite, RewriteTopic: "weaverssh/audit/status", When: Condition{Field: "event.type", Value: "status"}}}}
	decision, err := rs.Evaluate(NewInput("weaverssh/runtime/status", map[string]string{"event.type": "status"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed || decision.Topic != "weaverssh/audit/status" {
		t.Fatalf("rewrite decision wrong: %+v", decision)
	}
	_, err = (RuleSet{Version: EngineVersion, Rules: []Rule{{ID: "bad", Action: ActionRewrite}}}).Normalize()
	if err == nil || !strings.Contains(err.Error(), "rewrite_topic") {
		t.Fatalf("expected rewrite_topic validation error, got %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(strings.NewReader(`{"version":"weaverssh.rules.v1","unknown":true}`))
	if err == nil {
		t.Fatal("unknown JSON fields should fail")
	}
}
