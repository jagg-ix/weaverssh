package app

import (
	"reflect"
	"strings"
	"testing"

	"weaverssh/authproof"
)

func TestInjectOpenSSHSetEnv(t *testing.T) {
	input := []string{"ssh", "-J", "jump-a", "-X", "user@endpoint"}
	got, injected, err := injectOpenSSHSetEnv(input, "workstation-42")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh", "-o", "SetEnv=WVORIGIN=workstation-42", "-J", "jump-a", "-X", "user@endpoint"}
	if !injected || !reflect.DeepEqual(got, want) {
		t.Fatalf("injected=%t got=%q want=%q", injected, got, want)
	}
}

func TestInjectRecursiveOpenSSHEnvironment(t *testing.T) {
	input := []string{"ssh", "-J", "jump-a", "-X", "user@compute-node"}
	got, injected, err := injectOpenSSHEnvironment(input, map[string]string{
		EnvWVOrigin: "jump-a",
		EnvWVHop:    "encoded-chain",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ssh", "-A", "-o", "SetEnv=WVHOP=encoded-chain WVORIGIN=jump-a",
		"-J", "jump-a", "-X", "user@compute-node",
	}
	if !injected || !reflect.DeepEqual(got, want) {
		t.Fatalf("injected=%t got=%q want=%q", injected, got, want)
	}
}

func TestInjectRecursiveOpenSSHPreservesExistingAgentForwarding(t *testing.T) {
	input := []string{"ssh", "-A", "host"}
	got, injected, err := injectOpenSSHEnvironment(input, map[string]string{EnvWVOrigin: "jump-a", EnvWVHop: "chain"}, true)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, argument := range got {
		if argument == "-A" {
			count++
		}
	}
	if !injected || count != 1 {
		t.Fatalf("injected=%t -A count=%d got=%q", injected, count, got)
	}
}

func TestInjectRecursiveOpenSSHRejectsDisabledAgent(t *testing.T) {
	for _, input := range [][]string{
		{"ssh", "-a", "host"},
		{"ssh", "-o", "ForwardAgent=no", "host"},
	} {
		if _, _, err := injectOpenSSHEnvironment(input, map[string]string{EnvWVOrigin: "jump-a", EnvWVHop: "chain"}, true); err == nil {
			t.Fatalf("input=%q unexpectedly accepted", input)
		}
	}
}

func TestInjectOpenSSHSetEnvRejectsConflict(t *testing.T) {
	_, _, err := injectOpenSSHSetEnv([]string{"ssh", "-o", "SetEnv=WVORIGIN=other", "host"}, "workstation-42")
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("error=%v", err)
	}
}

func TestInjectOpenSSHSetEnvLeavesOtherChildCommands(t *testing.T) {
	input := []string{"bash", "-lc", "ssh -X user@endpoint"}
	got, injected, err := injectOpenSSHSetEnv(input, "workstation-42")
	if err != nil {
		t.Fatal(err)
	}
	if injected || !reflect.DeepEqual(got, input) {
		t.Fatalf("injected=%t got=%q", injected, got)
	}
}

func TestValidateWVOriginUsesImmediatePreviousNode(t *testing.T) {
	ctx := authproof.NodeContext{
		IssuerPeerID:  "test",
		ChainID:       "chain",
		ChainSHA256:   strings.Repeat("a", 64),
		Nodes:         []string{"workstation-42", "jump-a", "compute-node"},
		CurrentNode:   "compute-node",
		OriginNode:    "workstation-42",
		EndpointNode:  "compute-node",
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "wvorigin-test-nonce",
		IssuedAtUnix:  1,
		ExpiresAtUnix: 4102444800,
	}
	if got, err := ValidateWVOrigin("jump-a", ctx); err != nil || got != "jump-a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := ValidateWVOrigin("workstation-42", ctx); err == nil {
		t.Fatal("root node unexpectedly matched immediate previous node")
	}
	if _, err := ValidateWVOrigin("", ctx); err == nil || !strings.Contains(err.Error(), "AcceptEnv WVORIGIN WVHOP") {
		t.Fatalf("missing variable error=%v", err)
	}
}

func TestSignedWVOriginUsesCurrentNodeForNextHop(t *testing.T) {
	ctx := authproof.NodeContext{
		IssuerPeerID:  "test",
		ChainID:       "chain",
		ChainSHA256:   strings.Repeat("a", 64),
		Nodes:         []string{"workstation-42", "jump-a", "compute-node"},
		CurrentNode:   "jump-a",
		OriginNode:    "workstation-42",
		EndpointNode:  "compute-node",
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "signed-origin-test",
		IssuedAtUnix:  1,
		ExpiresAtUnix: 4102444800,
	}
	if got, err := SignedWVOrigin(ctx); err != nil || got != "jump-a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
