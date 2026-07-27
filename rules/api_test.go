package rules

import (
	"errors"
	"strings"
	"testing"
)

func TestAPIEvaluatesDefaultAndNamedRuleSets(t *testing.T) {
	api, err := NewAPI(APIConfig{RuleSets: map[string]RuleSet{
		DefaultRuleSetName: {
			Version: EngineVersion,
			Rules: []Rule{{
				ID:     "allow-runtime-status",
				Action: ActionAllow,
				When:   Condition{Field: "event.type", Value: "status"},
			}},
		},
		"strict": {
			Version: EngineVersion,
			Rules: []Rule{{
				ID:     "drop-external",
				Action: ActionDrop,
				When:   Condition{Field: "event.origin", Value: "external"},
			}},
		},
	}})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	decision, err := api.Evaluate(NewInput("weaverssh/runtime/status", map[string]string{"event.type": "status"}))
	if err != nil {
		t.Fatalf("Evaluate default: %v", err)
	}
	if !decision.Allowed || decision.RuleID != "allow-runtime-status" {
		t.Fatalf("default decision wrong: %+v", decision)
	}
	decision, err = api.EvaluateNamed("strict", NewInput("weaverssh/authproof/fault", map[string]string{"event.origin": "external"}))
	if err != nil {
		t.Fatalf("EvaluateNamed strict: %v", err)
	}
	if decision.Allowed || decision.Action != ActionDrop || decision.RuleID != "drop-external" {
		t.Fatalf("strict decision wrong: %+v", decision)
	}
}

func TestAPIRegisterPutLoadAndMissingRulesets(t *testing.T) {
	api := MustNewAPI(APIConfig{})
	if _, err := api.Evaluate(NewInput("", nil)); !errors.Is(err, ErrRuleSetNotFound) {
		t.Fatalf("empty API error=%v want ErrRuleSetNotFound", err)
	}
	rs := RuleSet{Version: EngineVersion, Rules: []Rule{{ID: "allow", Action: ActionAllow}}}
	if err := api.Register("local", rs); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := api.Register("local", rs); !errors.Is(err, ErrRuleSetAlreadyExists) {
		t.Fatalf("duplicate Register error=%v want ErrRuleSetAlreadyExists", err)
	}
	if err := api.SetDefaultName("local"); err != nil {
		t.Fatalf("SetDefaultName: %v", err)
	}
	decision, err := api.Evaluate(NewInput("weaverssh/runtime/status", nil))
	if err != nil || !decision.Allowed {
		t.Fatalf("Evaluate local decision=%+v err=%v", decision, err)
	}
	jsonRuleSet := `{"version":"weaverssh.rules.v1","rules":[{"id":"deny-fault","action":"deny","when":{"field":"event.type","value":"fault"}}]}`
	if err := api.Load("loaded", strings.NewReader(jsonRuleSet)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	decision, err = api.EvaluateNamed("loaded", NewInput("weaverssh/runtime/fault", map[string]string{"event.type": "fault"}))
	if err != nil {
		t.Fatalf("Evaluate loaded: %v", err)
	}
	if decision.Allowed || decision.RuleID != "deny-fault" {
		t.Fatalf("loaded decision wrong: %+v", decision)
	}
	if !api.Remove("loaded") {
		t.Fatal("Remove loaded should report true")
	}
	if _, ok := api.RuleSet("loaded"); ok {
		t.Fatal("removed ruleset should not be returned")
	}
}

func TestAPIContractAndNames(t *testing.T) {
	api := MustNewAPI(APIConfig{RuleSets: map[string]RuleSet{
		"b": {Version: EngineVersion, Rules: []Rule{{ID: "b", Action: ActionAllow}}},
		"a": {Version: EngineVersion, Rules: []Rule{{ID: "a", Action: ActionAllow}}},
	}})
	names := api.Names()
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("Names not sorted: %v", names)
	}
	contract := api.Contract()
	if contract.Version != EngineVersion || contract.DefaultAction != ActionDeny || len(contract.Actions) == 0 || len(contract.Operators) == 0 {
		t.Fatalf("contract incomplete: %+v", contract)
	}
}

func TestAPIRuleSetReturnsDefensiveCopy(t *testing.T) {
	api := MustNewAPI(APIConfig{RuleSets: map[string]RuleSet{
		"default": {Version: EngineVersion, Rules: []Rule{{ID: "tag", Action: ActionTag, SetFields: map[string]string{"class": "a"}, Tags: []string{"one"}}}},
	}})
	rs, ok := api.RuleSet("default")
	if !ok {
		t.Fatal("default ruleset missing")
	}
	rs.Rules[0].SetFields["class"] = "mutated"
	rs.Rules[0].Tags[0] = "mutated"
	again, ok := api.RuleSet("default")
	if !ok {
		t.Fatal("default ruleset missing on second read")
	}
	if again.Rules[0].SetFields["class"] != "a" || again.Rules[0].Tags[0] != "one" {
		t.Fatalf("ruleset copy mutated stored state: %+v", again.Rules[0])
	}
}
