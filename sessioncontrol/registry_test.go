package sessioncontrol

import (
	"errors"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestRegistryResolvesAuthenticatedTopology(t *testing.T) {
	registry := NewRegistry()
	workstationContext := testConcreteNodeContext("workstation-42", "chain-a", strings.Repeat("a", 64), "workstation-nonce")
	endpointContext := testConcreteNodeContext("compute-node", "chain-a", strings.Repeat("a", 64), "endpoint-nonce")

	if _, err := registry.RegisterVerified(workstationContext, []sessionmux.ServiceID{sessionmux.ServiceFS}); err != nil {
		t.Fatalf("register workstation: %v", err)
	}
	if _, err := registry.RegisterVerified(endpointContext, []sessionmux.ServiceID{sessionmux.ServiceFS, sessionmux.ServiceTCP}); err != nil {
		t.Fatalf("register endpoint: %v", err)
	}

	cases := map[string]string{
		"workstation-42": "workstation-42",
		"endpoint":       "compute-node",
		"self":           "workstation-42",
		"next":           "compute-node",
	}
	for ref, want := range cases {
		node, err := registry.Resolve(ref, "workstation-42")
		if err != nil {
			t.Fatalf("resolve %s: %v", ref, err)
		}
		if node.ID != want {
			t.Fatalf("resolve %s=%s want %s", ref, node.ID, want)
		}
	}
	previous, err := registry.Resolve("previous", "compute-node")
	if err != nil || previous.ID != "workstation-42" {
		t.Fatalf("previous from endpoint=%+v err=%v", previous, err)
	}

	for _, removedKeyword := range []string{"origin", "workstation", "@origin"} {
		if _, err := registry.Resolve(removedKeyword, "compute-node"); !errors.Is(err, ErrUnknownNode) {
			t.Fatalf("%s error=%v want ErrUnknownNode", removedKeyword, err)
		}
	}
	if _, err := registry.Authorize("compute-node", "workstation-42", sessionmux.ServiceTCP); err != nil {
		t.Fatalf("authorize endpoint tcp: %v", err)
	}
	if _, err := registry.Authorize("workstation-42", "workstation-42", sessionmux.ServiceTCP); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("workstation tcp error=%v want ErrServiceUnavailable", err)
	}
}

func TestRegistryRejectsDifferentChain(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.RegisterVerified(
		testNodeContext("origin", "chain-a", strings.Repeat("a", 64), "nonce-a"),
		[]sessionmux.ServiceID{sessionmux.ServiceFS},
	); err != nil {
		t.Fatal(err)
	}
	_, err := registry.RegisterVerified(
		testNodeContext("endpoint", "chain-b", strings.Repeat("b", 64), "nonce-b"),
		[]sessionmux.ServiceID{sessionmux.ServiceFS},
	)
	if !errors.Is(err, ErrChainMismatch) {
		t.Fatalf("chain mismatch error=%v", err)
	}
}

func TestRegistryRejectsServiceWithoutSignedCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "missing-capability-nonce")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext}
	_, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceFS})
	if !errors.Is(err, authproof.ErrMissingCapability) {
		t.Fatalf("registration error=%v want ErrMissingCapability", err)
	}
}

func testNodeContext(current, chainID, chainSHA, nonce string) authproof.NodeContext {
	now := time.Now()
	return authproof.NodeContext{
		IssuerPeerID:  "test-issuer",
		ChainID:       chainID,
		ChainSHA256:   chainSHA,
		Nodes:         []string{"origin", "endpoint"},
		CurrentNode:   current,
		OriginNode:    "origin",
		EndpointNode:  "endpoint",
		Capabilities: []string{
			authproof.CapabilityNodeContext,
			authproof.CapabilityVFSMesh,
			authproof.CapabilitySocksProxy,
		},
		Nonce:         nonce,
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
}

func testConcreteNodeContext(current, chainID, chainSHA, nonce string) authproof.NodeContext {
	ctx := testNodeContext("origin", chainID, chainSHA, nonce)
	ctx.Nodes = []string{"workstation-42", "compute-node"}
	ctx.CurrentNode = current
	ctx.OriginNode = "workstation-42"
	ctx.EndpointNode = "compute-node"
	return ctx
}
