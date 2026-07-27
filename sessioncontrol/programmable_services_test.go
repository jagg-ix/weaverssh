package sessioncontrol

import (
	"errors"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestRegistryAllowsEventsWithSignedProgrammableCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "events-nonce")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext, authproof.CapabilityMapReduce}
	node, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceEvents})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Supports(sessionmux.ServiceEvents) {
		t.Fatal("ServiceEvents was not registered")
	}
}
func TestRegistryRejectsEventsWithoutSignedProgrammableCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "events-no-cap")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext}
	_, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceEvents})
	if !errors.Is(err, authproof.ErrMissingCapability) {
		t.Fatalf("error=%v want ErrMissingCapability", err)
	}
}
