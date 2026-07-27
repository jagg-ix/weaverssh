package sessioncontrol

import (
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestLocalTargetRequiresConcreteWVOriginNode(t *testing.T) {
	now := time.Now()
	ctx := authproof.NodeContext{
		IssuerPeerID:  "test",
		ChainID:       "chain",
		ChainSHA256:   strings.Repeat("a", 64),
		Nodes:         []string{"workstation-42", "compute-node"},
		CurrentNode:   "workstation-42",
		OriginNode:    "workstation-42",
		EndpointNode:  "compute-node",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "local-wvorigin-test",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	if !referenceResolvesToLocal("workstation-42", ctx) {
		t.Fatal("concrete WVORIGIN node did not resolve to local workstation")
	}
	for _, removedKeyword := range []string{"origin", "workstation", "node:origin"} {
		if referenceResolvesToLocal(removedKeyword, ctx) {
			t.Fatalf("removed keyword %q unexpectedly resolved", removedKeyword)
		}
	}
}
