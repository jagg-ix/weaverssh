package sessionexec

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

const testChain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testPolicy(t *testing.T) Policy {
	t.Helper()
	raw := []byte(`{"version":"weaverssh.exec-policy.v1","default":"deny","actions":[{"name":"echo","executable":"/bin/echo","sources":["origin"],"max_args":4,"max_stdout_bytes":1024}]}`)
	policy, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestBindSourceAndExecute(t *testing.T) {
	raw, err := NewOpenMetadata("target")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(raw, "origin", "binding-1", testChain, "target")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ParseOpenMetadata(bound)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{Topology: []string{"origin", "target"}, ChainSHA256: testChain, CurrentNode: "target", Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := engine.Execute(context.Background(), metadata, Request{Action: "echo", Args: []string{"hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Stdout) != "hello\n" || response.ExitCode != 0 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Topology: []string{"origin", "target"}, ChainSHA256: testChain, CurrentNode: "target", Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := NewOpenMetadata("target")
	bound, _ := BindSource(raw, "origin", "binding-1", testChain, "target")
	server, client := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = engine.Serve(ctx, server, bound) }()
	response, err := CallStream(ctx, client, Request{Action: "echo", Args: []string{"stream"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(response.Stdout)) != "stream" {
		t.Fatalf("stdout=%q", response.Stdout)
	}
}

func TestPolicyRejectsCredentialEnvironment(t *testing.T) {
	var value map[string]any
	_ = json.Unmarshal([]byte(`{"version":"weaverssh.exec-policy.v1","default":"deny","actions":[{"name":"bad","executable":"/bin/echo","sources":["origin"],"env":{"SSH_AUTH_SOCK":"/tmp/agent"}}]}`), &value)
	raw, _ := json.Marshal(value)
	if _, err := ParsePolicy(raw); err == nil {
		t.Fatal("credential-like environment was accepted")
	}
}

func TestForwardedChainMismatch(t *testing.T) {
	raw, _ := NewOpenMetadata("target")
	bound, _ := BindSource(raw, "origin", "binding-1", testChain, "target")
	if _, err := BindSource(bound, "other", "binding-2", strings.Repeat("b", 64), "target"); err == nil {
		t.Fatal("chain mismatch was accepted")
	}
}
