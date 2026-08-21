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

func TestRegistryAllowsExecWithDedicatedContainerCapability(t *testing.T) {
	registry := NewRegistry()
	ctx := testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "container-exec-cap")
	ctx.Capabilities = []string{authproof.CapabilityNodeContext, authproof.CapabilityContainerExec}
	node, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceExec})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Supports(sessionmux.ServiceExec) {
		t.Fatal("ServiceExec was not registered")
	}
	if _, err := registry.RegisterVerified(ctx, []sessionmux.ServiceID{sessionmux.ServiceEvents}); !errors.Is(err, authproof.ErrMissingCapability) {
		t.Fatalf("container exec capability unexpectedly authorized events: %v", err)
	}
}
