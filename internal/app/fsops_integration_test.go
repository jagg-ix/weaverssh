package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionfsops"
	"weaverssh/sessionmux"
)

func TestAtomicFSOpsShareAuthorizedServiceFSRouting(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nodes := []string{"workstation-42", "compute-node"}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID: "fsops-integration",
		Audience: authproof.AudienceNodeContext,
		ChainID: "fsops-integration-chain",
		ChainSHA256: authproof.ChainBindingSHA256(nodes...),
		Nodes: nodes,
		CurrentNode: nodes[1],
		OriginNode: nodes[0],
		EndpointNode: nodes[1],
		Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce: "fsops-integration-nonce",
		IssuedAtUnix: now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	finalPath := filepath.Join(root, "final.bin")
	if err := os.WriteFile(finalPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalServices(LocalServiceConfig{SignedContext: signed, PublicKey: publicKey, Root: root})
	if err != nil {
		t.Fatal(err)
	}

	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- (&sessiondispatch.Dispatcher{Mux: right, Target: local.HandleStream}).Serve(ctx)
	}()

	socket := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- (&sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			return sessioncontrol.OpenTarget(openCtx, left, request.Node, request.Service, request.Data)
		}}).Serve(ctx, listener)
	}()

	operations := sessionfsops.Client{Socket: socket, Node: nodes[1]}
	prepared, err := operations.PrepareReplace(ctx, "final.bin", 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != "old" || prepared.AppliedMode != 0o600 {
		t.Fatalf("before=%q prepared=%+v", before, prepared)
	}

	p9Transport, err := sessionbroker.Dial(ctx, "unix", socket, sessionbroker.OpenRequest{Node: nodes[1], Service: sessionmux.ServiceFS})
	if err != nil {
		t.Fatal(err)
	}
	client, err := p9client.Attach(p9Transport)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := client.OpenWriter(prepared.TempPath, prepared.AppliedMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("new-complete")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := operations.CommitReplace(ctx, prepared.TempPath, "final.bin"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "new-complete" {
		t.Fatalf("after=%q", after)
	}

	cancel()
	_ = listener.Close()
	_ = left.Close()
	_ = right.Close()
	for name, done := range map[string]<-chan error{"dispatcher": dispatchDone, "broker": brokerDone} {
		select {
		case err := <-done:
			if err != nil && ctx.Err() == nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not stop", name)
		}
	}
}
