package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRulesTopLevelCommandRegistered(t *testing.T) {
	if !containsString(topLevelCommands, "rules") {
		t.Fatalf("topLevelCommands missing rules: %v", topLevelCommands)
	}
	if !containsString(topLevelCommands, "policy") {
		t.Fatalf("topLevelCommands missing policy alias: %v", topLevelCommands)
	}
}

func TestRulesPlanExampleAndEval(t *testing.T) {
	if rc := cmdRules([]string{"plan"}); rc != 0 {
		t.Fatalf("rules plan rc=%d", rc)
	}
	if rc := cmdRules([]string{"example"}); rc != 0 {
		t.Fatalf("rules example rc=%d", rc)
	}
	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	data := []byte(`{
  "version": "weaverssh.rules.v1",
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-runtime-status",
      "action": "allow",
      "when": {
        "all": [
          {"field": "event.component", "value": "runtime"},
          {"field": "event.type", "value": "status"},
          {"field": "field.plane", "value": "ok"}
        ]
      }
    }
  ]
}
`)
	if err := os.WriteFile(rulesFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := cmdRules([]string{"eval", "--rules", rulesFile, "--component", "runtime", "--type", "status", "--field", "plane=ok"}); rc != 0 {
		t.Fatalf("rules eval allowed rc=%d", rc)
	}
	if rc := cmdRules([]string{"eval", "--rules", rulesFile, "--component", "runtime", "--type", "fault"}); rc != 0 {
		t.Fatalf("rules eval denied still reports decision rc=%d", rc)
	}
	if rc := cmdRules([]string{"eval"}); rc != 2 {
		t.Fatalf("rules eval missing file rc=%d want 2", rc)
	}
}

func TestRulesPipelineSystemStageRunsFirst(t *testing.T) {
	root := t.TempDir()
	systemDir := filepath.Join(root, "system")
	userDir := filepath.Join(root, "user")
	mustWriteRulesCLI(t, filepath.Join(systemDir, "00-deny.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"system-deny-fault","action":"deny","when":{"field":"event.type","value":"fault"}}]
}`)
	mustWriteRulesCLI(t, filepath.Join(userDir, "99-allow.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"deny",
  "rules":[{"id":"user-allow-fault","action":"allow","when":{"field":"event.type","value":"fault"}}]
}`)
	rc := cmdRules([]string{
		"pipeline",
		"--system-dir", systemDir,
		"--user-dir", userDir,
		"--require-system",
		"--component", "runtime",
		"--type", "fault",
	})
	if rc != 0 {
		t.Fatalf("rules pipeline rc=%d", rc)
	}
}

func TestRulesPipelineRequireSystemMissingFails(t *testing.T) {
	rc := cmdRules([]string{"pipeline", "--system-dir", filepath.Join(t.TempDir(), "missing"), "--require-system"})
	if rc != 2 {
		t.Fatalf("missing required system stage rc=%d want 2", rc)
	}
}

func TestRulesPipelineRemoteNodeStage(t *testing.T) {
	root := t.TempDir()
	systemDir := filepath.Join(root, "system")
	nodeDir := filepath.Join(root, "node")
	mustWriteRulesCLI(t, filepath.Join(systemDir, "00-system.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"system-tag","action":"tag","set_fields":{"system_checked":"true"}}]
}`)
	mustWriteRulesCLI(t, filepath.Join(nodeDir, "10-node.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"node-deny-api","action":"deny","when":{"all":[{"field":"api.name","value":"dangerous"},{"field":"node.id","value":"linode-a"}]}}]
}`)
	rc := cmdRules([]string{
		"pipeline",
		"--node", "linode-a",
		"--system-dir", systemDir,
		"--node-dir", nodeDir,
		"--require-system",
		"--require-node",
		"--component", "api",
		"--type", "api_started",
		"--field", "api=dangerous",
	})
	if rc != 0 {
		t.Fatalf("rules pipeline remote node rc=%d", rc)
	}
}

func mustWriteRulesCLI(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRulesConsumeRemoteNodeTriggerPlan(t *testing.T) {
	root := t.TempDir()
	nodeDir := filepath.Join(root, "node")
	mustWriteRulesCLI(t, filepath.Join(nodeDir, "10-trigger.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"node-trigger-scan","action":"tag","when":{"all":[{"field":"event.component","value":"runtime"},{"field":"event.type","value":"status"}]},"set_fields":{"intent.api":"connections","intent.operation":"scan","intent.subject":"local"}}]
}`)
	rc := cmdRules([]string{
		"consume",
		"--node", "linode-a",
		"--node-dir", nodeDir,
		"--require-node",
		"--component", "runtime",
		"--type", "status",
	})
	if rc != 0 {
		t.Fatalf("rules consume remote node trigger rc=%d", rc)
	}
}
