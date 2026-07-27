package sessioncontrol

import (
	"context"
	"net"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestServeAnyRegistrationDispatchesLegacyProtocol(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	clientMux, err := sessionmux.New(left, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer clientMux.Close()
	serverMux, err := sessionmux.New(right, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer serverMux.Close()

	now := time.Now()
	nodes := []string{"origin", "endpoint"}
	contextValue := authproof.NodeContext{
		IssuerPeerID: "authority", Audience: authproof.AudienceNodeContext,
		ChainID: "chain", ChainSHA256: authproof.ChainBindingSHA256(nodes...), Nodes: nodes,
		CurrentNode: "endpoint", OriginNode: "origin", EndpointNode: "endpoint",
		Capabilities: []string{authproof.CapabilityNodeContext}, Nonce: "legacy-dispatch",
		IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	serverResult := make(chan AcceptedRegistration, 1)
	serverError := make(chan error, 1)
	go func() {
		accepted, serveErr := ServeAnyRegistration(context.Background(), serverMux, NewRegistry(), AnyRegistrationConfig{
			ExpectedSessionBinding: "binding",
			LegacyVerifier: func(signed authproof.SignedNodeContext) (authproof.NodeContext, error) {
				return signed.Context, nil
			},
		})
		serverResult <- accepted
		serverError <- serveErr
	}()

	response, err := RegisterNode(context.Background(), clientMux, authproof.SignedNodeContext{Context: contextValue, Signature: "test"}, nil, "binding")
	if err != nil {
		t.Fatal(err)
	}
	if response.Node != "endpoint" {
		t.Fatalf("response node=%q", response.Node)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	accepted := <-serverResult
	if accepted.Mode != RegistrationModeLegacy || accepted.Node.ID != "endpoint" {
		t.Fatalf("accepted=%+v", accepted)
	}
}
