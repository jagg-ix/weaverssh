package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPipelineSystemDenyStopsUserOverride(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "system")
	user := filepath.Join(dir, "user")
	mustWriteRule(t, filepath.Join(system, "00-deny.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"deny-fault","action":"deny","when":{"field":"event.type","value":"fault"},"reason":"system fault deny"}]
}`)
	mustWriteRule(t, filepath.Join(user, "99-allow.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"deny",
  "rules":[{"id":"allow-fault","action":"allow","when":{"field":"event.type","value":"fault"}}]
}`)
	cfg := PipelineConfig{Version: PipelineVersion, Stages: []StageConfig{
		{Name: "system", Required: true, Paths: []string{filepath.Join(system, "*.json")}},
		{Name: "user", Paths: []string{filepath.Join(user, "*.json")}},
	}}
	decision, err := cfg.Evaluate(NewInput("weaverssh/runtime/fault", map[string]string{"event.type": "fault"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || decision.Action != ActionDeny || decision.Final.RuleID != "deny-fault" || len(decision.Stages) != 1 {
		t.Fatalf("system deny should be terminal before user override: %+v", decision)
	}
}

func TestPipelineSystemAllowContinuesToProfileDeny(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "system")
	profile := filepath.Join(dir, "profile")
	mustWriteRule(t, filepath.Join(system, "00-baseline.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"tag-system","action":"tag","set_fields":{"system_policy":"checked"}}]
}`)
	mustWriteRule(t, filepath.Join(profile, "10-path.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"deny-secret-read","action":"deny","when":{"all":[{"field":"file.operation","value":"file_read"},{"field":"file.path","op":"prefix","value":"/secret/"}]}}]
}`)
	cfg := PipelineConfig{Version: PipelineVersion, Stages: []StageConfig{
		{Name: "system", Required: true, Paths: []string{system}},
		{Name: "profile", Paths: []string{profile}},
	}}
	decision, err := cfg.Evaluate(NewInput("weaverssh/vfs/file_read", map[string]string{"file.operation": "file_read", "file.path": "/secret/key"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || decision.Final.RuleID != "deny-secret-read" || decision.Fields["system_policy"] != "checked" || len(decision.Stages) != 2 {
		t.Fatalf("profile deny after system tag wrong: %+v", decision)
	}
}

func TestPipelineRequiredStageMissingFailsClosed(t *testing.T) {
	cfg := PipelineConfig{Version: PipelineVersion, Stages: []StageConfig{{Name: "system", Required: true, Paths: []string{filepath.Join(t.TempDir(), "missing", "*.json")}}}}
	_, err := cfg.Evaluate(NewInput("weaverssh/runtime/status", nil))
	if err == nil {
		t.Fatal("required missing system stage should fail")
	}
}

func TestDefaultPipelineSystemStageIsFirst(t *testing.T) {
	cfg := DefaultPipelineConfig()
	if len(cfg.Stages) == 0 || cfg.Stages[0].Name != "system" {
		t.Fatalf("default pipeline should start with system stage: %+v", cfg)
	}
	if len(cfg.Stages[0].Paths) == 0 || cfg.Stages[0].Paths[0] != filepath.Join(DefaultSystemRulesDir, "*.json") {
		t.Fatalf("default system paths wrong: %+v", cfg.Stages[0].Paths)
	}
}

func TestRemoteNodePipelineEvaluatesNodeRulesBeforeUser(t *testing.T) {
	root := t.TempDir()
	nodeID := "linode-a"
	system := filepath.Join(root, "system")
	node := filepath.Join(root, "nodes", nodeID, "rules.d")
	user := filepath.Join(root, "user")
	mustWriteRule(t, filepath.Join(system, "00-system.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"system-tag","action":"tag","set_fields":{"system_checked":"true"}}]
}`)
	mustWriteRule(t, filepath.Join(node, "10-node.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"node-deny-api","action":"deny","when":{"all":[{"field":"node.id","value":"linode-a"},{"field":"api.name","value":"dangerous"}]}}]
}`)
	mustWriteRule(t, filepath.Join(user, "99-user.json"), `{
  "version":"weaverssh.rules.v1",
  "default_action":"allow",
  "rules":[{"id":"user-allow-api","action":"allow","when":{"field":"api.name","value":"dangerous"}}]
}`)
	cfg := PipelineConfig{Version: PipelineVersion, NodeID: nodeID, Stages: []StageConfig{
		{Name: "system", Paths: []string{system}},
		{Name: "remote-node", Paths: []string{filepath.Join(root, "nodes", "{node}", "rules.d", "*.json")}},
		{Name: "user-node", Paths: []string{user}},
	}}
	decision, err := cfg.Evaluate(NewInput("weaverssh/api/api_started", map[string]string{"api.name": "dangerous"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || decision.Final.RuleID != "node-deny-api" || decision.Fields["system_checked"] != "true" || len(decision.Stages) != 2 {
		t.Fatalf("remote node policy should deny before user stage: %+v", decision)
	}
}

func TestDefaultRemoteNodePipelineUsesNodePaths(t *testing.T) {
	cfg, err := DefaultRemoteNodePipelineConfig("linode-a")
	if err != nil {
		t.Fatalf("DefaultRemoteNodePipelineConfig: %v", err)
	}
	if cfg.NodeID != "linode-a" || len(cfg.Stages) < 3 || cfg.Stages[1].Name != "remote-node" {
		t.Fatalf("unexpected remote pipeline: %+v", cfg)
	}
	if _, err := DefaultRemoteNodePipelineConfig("../bad"); err == nil {
		t.Fatal("unsafe node id should fail")
	}
}

func mustWriteRule(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
