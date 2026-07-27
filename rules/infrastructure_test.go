package rules

import "testing"

func TestInfrastructureInputAddsFileFacts(t *testing.T) {
	input := NewInfrastructureInput("weaverssh/infrastructure/file_read", InfrastructureEvent{
		Operation: "file_read",
		Path:      "/srv/data/report.txt",
		ViewPath:  "reports/report.txt",
		Protocol:  "vfs-9p",
		Bytes:     2048,
		Fields:    map[string]string{"profile": "default"},
	})
	checks := map[string]string{
		"infra.kind":      InfrastructureKindFile,
		"infra.operation": "file_read",
		"infra.path":      "/srv/data/report.txt",
		"file.operation":  "file_read",
		"file.path":       "/srv/data/report.txt",
		"file.view_path":  "reports/report.txt",
		"file.bytes":      "2048",
		"file.protocol":   "vfs-9p",
		"event.component": InfrastructureComponent,
		"event.origin":    InfrastructureOriginInternal,
		"field.profile":   "default",
		"profile":         "default",
	}
	for key, want := range checks {
		got, ok := input.Value(key)
		if !ok || got != want {
			t.Fatalf("%s=(%q,%t), want %q", key, got, ok, want)
		}
	}
}

func TestAPIEvaluatesInfrastructureEvents(t *testing.T) {
	api := MustNewAPI(APIConfig{RuleSets: map[string]RuleSet{
		"default": {Version: EngineVersion, Rules: []Rule{
			{ID: "deny-secret-remove", Action: ActionDeny, When: Condition{All: []Condition{
				{Field: "file.operation", Value: "file_removed"},
				{Field: "file.path", Op: OpPrefix, Value: "/srv/secret/"},
			}}},
			{ID: "allow-vfs-read", Action: ActionAllow, When: Condition{All: []Condition{
				{Field: "file.operation", Value: "file_read"},
				{Field: "file.protocol", Value: "vfs-9p"},
			}}},
		}},
	}})
	decision, err := api.EvaluateInfrastructure("weaverssh/infrastructure/file_read", InfrastructureEvent{Operation: "file_read", Path: "/srv/public/a.txt", Protocol: "vfs-9p"})
	if err != nil {
		t.Fatalf("EvaluateInfrastructure read: %v", err)
	}
	if !decision.Allowed || decision.RuleID != "allow-vfs-read" {
		t.Fatalf("read decision wrong: %+v", decision)
	}
	decision, err = api.EvaluateInfrastructure("weaverssh/infrastructure/file_removed", InfrastructureEvent{Operation: "file_removed", Path: "/srv/secret/key.txt"})
	if err != nil {
		t.Fatalf("EvaluateInfrastructure remove: %v", err)
	}
	if decision.Allowed || decision.RuleID != "deny-secret-remove" {
		t.Fatalf("remove decision wrong: %+v", decision)
	}
}
