package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"weaverssh/authproof"
	"weaverssh/mapreduce"
	"weaverssh/rules"
	"weaverssh/socksproof"
)

func TestRulesLifecycleCommands(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	pipelinePath := filepath.Join(dir, "pipeline.json")
	if code := cmdRulesComplete([]string{"init", "--out", rulesPath}); code != 0 {
		t.Fatalf("rules init code=%d", code)
	}
	if code := cmdRulesComplete([]string{"validate", rulesPath}); code != 0 {
		t.Fatalf("rules validate code=%d", code)
	}
	if code := cmdRulesComplete([]string{"normalize", rulesPath, "--in-place"}); code != 0 {
		t.Fatalf("rules normalize code=%d", code)
	}
	loaded, err := rules.LoadFile(rulesPath)
	if err != nil || len(loaded.Rules) == 0 {
		t.Fatalf("normalized rules=%+v err=%v", loaded, err)
	}
	if code := cmdRulesComplete([]string{"pipeline-default", "--node", "node-a", "--out", pipelinePath}); code != 0 {
		t.Fatalf("pipeline default code=%d", code)
	}
	if code := cmdRulesComplete([]string{"pipeline-validate", pipelinePath}); code != 0 {
		t.Fatalf("pipeline validate code=%d", code)
	}
	pipeline, err := rules.LoadPipelineFile(pipelinePath)
	if err != nil || pipeline.NodeID != "node-a" {
		t.Fatalf("pipeline=%+v err=%v", pipeline, err)
	}
}

func TestSocksPolicyLifecycleCommands(t *testing.T) {
	dir := t.TempDir()
	firstPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, ed25519.SeedSize))
	secondPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	firstKey := filepath.Join(dir, "first.pub")
	secondKey := filepath.Join(dir, "second.pub")
	policyPath := filepath.Join(dir, "socks-policy.json")
	if err := os.WriteFile(firstKey, []byte(authproof.EncodePublicKey(firstPrivate.Public().(ed25519.PublicKey))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondKey, []byte(authproof.EncodePublicKey(secondPrivate.Public().(ed25519.PublicKey))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdSocksPolicyComplete([]string{
		"init", "--server-id", "proxy-a", "--principal", "build",
		"--public-key-file", firstKey, "--destination", "*.internal:443",
		"--out", policyPath,
	}); code != 0 {
		t.Fatalf("socks policy init code=%d", code)
	}
	if code := cmdSocksPolicyComplete([]string{
		"principal", "add", policyPath, "--id", "deploy",
		"--public-key-file", secondKey, "--destination", "api.internal:443",
		"--in-place",
	}); code != 0 {
		t.Fatalf("socks principal add code=%d", code)
	}
	policy, err := socksproof.LoadPolicyFile(policyPath)
	if err != nil || len(policy.Principals) != 2 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if code := cmdSocksPolicyComplete([]string{"principal", "show", policyPath, "deploy", "--json"}); code != 0 {
		t.Fatalf("socks principal show code=%d", code)
	}
	if code := cmdSocksPolicyComplete([]string{"principal", "remove", policyPath, "build", "--in-place"}); code != 0 {
		t.Fatalf("socks principal remove code=%d", code)
	}
	policy, err = socksproof.LoadPolicyFile(policyPath)
	if err != nil || len(policy.Principals) != 1 || policy.Principals[0].ID != "deploy" {
		t.Fatalf("remaining policy=%+v err=%v", policy, err)
	}
	if code := cmdSocksPolicyComplete([]string{"validate", policyPath}); code != 0 {
		t.Fatalf("socks policy validate code=%d", code)
	}
}

func TestMapReduceValidationAliases(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "mapreduce-policy.json")
	pluginPath := filepath.Join(dir, "plugins.json")
	policy := mapreduce.Policy{
		Version: mapreduce.PolicyVersion,
		Default: mapreduce.EffectDeny,
		Rules: []mapreduce.Rule{{
			Name:        "allow-test",
			Effect:      mapreduce.EffectAllow,
			SourceNodes: []string{"origin"},
			TargetNodes: []string{"node-a"},
			Plugins:     []string{"test-plugin"},
			Operations:  []mapreduce.Operation{mapreduce.OperationRun},
		}},
	}
	if err := writeJSONArtifact(policyPath, policy, 0o600, false); err != nil {
		t.Fatal(err)
	}
	if code := cmdMapReduceComplete([]string{"policy", "validate", policyPath}); code != 0 {
		t.Fatalf("policy validate code=%d", code)
	}
	if code := cmdMapReduceComplete([]string{"policy", "normalize", policyPath, "--in-place"}); code != 0 {
		t.Fatalf("policy normalize code=%d", code)
	}
	payload, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mapreduce.ParsePolicy(payload)
	if err != nil || parsed.SHA256() == "" {
		t.Fatalf("parsed policy=%+v err=%v", parsed, err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plugins := mapreduce.PluginFileConfig{
		Version: mapreduce.PluginConfigVersion,
		Plugins: []mapreduce.CommandPluginConfig{{
			Name:       "test-plugin",
			Version:    "1",
			MapCommand: []string{executable},
		}},
	}
	if err := writeJSONArtifact(pluginPath, plugins, 0o600, false); err != nil {
		t.Fatal(err)
	}
	if code := cmdMapReduceComplete([]string{"plugins", "validate", pluginPath, "--json"}); code != 0 {
		t.Fatalf("plugin validate code=%d", code)
	}
	if code := cmdMapReduceComplete([]string{"plugins", "list", pluginPath}); code != 0 {
		t.Fatalf("plugin list code=%d", code)
	}
}

func TestStrictJSONArtifactRejectsTrailingData(t *testing.T) {
	var target map[string]any
	if err := decodeStrictJSON([]byte(`{"ok":true} {"extra":true}`), &target); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	var encoded map[string]any
	data, err := json.Marshal(map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(data, &encoded); err != nil || encoded["ok"] != true {
		t.Fatalf("strict decode=%v err=%v", encoded, err)
	}
}
