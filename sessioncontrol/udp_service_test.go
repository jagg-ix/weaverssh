package sessioncontrol

import (
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestUDPServiceRequiresSignedSocksCapability(t *testing.T) {
	base := authproof.NodeContext{
		IssuerPeerID: "issuer",
		Audience: authproof.AudienceNodeContext,
		ChainID: "chain",
		Nodes: []string{"node-a"},
		CurrentNode: "node-a",
		OriginNode: "node-a",
		EndpointNode: "node-a",
		Nonce: "udp-service-nonce",
		IssuedAtUnix: time.Now().Add(-time.Second).Unix(),
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	}
	base.ChainSHA256 = authproof.ChainBindingSHA256(base.Nodes...)
	base.Capabilities = []string{authproof.CapabilityNodeContext}
	if _, err := NewRegistry().RegisterVerified(base, []sessionmux.ServiceID{sessionmux.ServiceUDP}); err == nil || !strings.Contains(err.Error(), "lacks signed capability") {
		t.Fatalf("error=%v", err)
	}
	base.Capabilities = append(base.Capabilities, authproof.CapabilitySocksProxy)
	node, err := NewRegistry().RegisterVerified(base, []sessionmux.ServiceID{sessionmux.ServiceUDP})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Supports(sessionmux.ServiceUDP) {
		t.Fatal("authorized UDP service was not registered")
	}
}
