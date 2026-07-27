package sessioncontrol

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestAuthorizePendingLocalDefersAcknowledgement(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		stream, openErr := OpenTarget(ctx, left, "node-a", sessionmux.ServiceFS, []byte("metadata"))
		if stream != nil {
			_ = stream.Close()
		}
		clientDone <- openErr
	}()

	stream, err := right.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := InspectAcceptedTarget(stream)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	local := authproof.NodeContext{
		IssuerPeerID:  "issuer",
		ChainID:       "chain-a",
		ChainSHA256:   strings.Repeat("0", 64),
		Nodes:         []string{"node-a"},
		CurrentNode:   "node-a",
		OriginNode:    "node-a",
		EndpointNode:  "node-a",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "nonce-a",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	accepted, err := AuthorizePendingLocal(pending, local, []sessionmux.ServiceID{sessionmux.ServiceFS})
	if err != nil {
		t.Fatal(err)
	}
	if string(accepted.Data) != "metadata" {
		t.Fatalf("accepted data=%q", accepted.Data)
	}

	select {
	case err := <-clientDone:
		t.Fatalf("client completed before acknowledgement: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := AcknowledgePendingTarget(ctx, pending); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
