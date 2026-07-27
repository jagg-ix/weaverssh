package sessioncontrol

import (
	"errors"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestRegistryAllowsServiceExecWithSignedMapReduceCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "exec-nonce")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext, authproof.CapabilityMapReduce}
	node, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceExec})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Supports(sessionmux.ServiceExec) {
		t.Fatal("ServiceExec was not registered")
	}
}

func TestRegistryRejectsServiceExecWithoutSignedMapReduceCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "exec-no-cap-nonce")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext}
	_, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceExec})
	if !errors.Is(err, authproof.ErrMissingCapability) {
		t.Fatalf("error=%v want ErrMissingCapability", err)
	}
}
