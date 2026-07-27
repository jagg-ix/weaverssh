package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
)

func TestAttachLifecycleServesAuthorizedPreviousNodeFSWithoutPort(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	const workstationNode = "workstation-42"
	const computeNode = "compute-node"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	chain := []string{workstationNode, computeNode}
	chainHash := authproof.ChainBindingSHA256(chain...)
	signContext := func(node, nonce string, capabilities []string) authproof.SignedNodeContext {
		signed, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID:  "test-issuer",
			Audience:      authproof.AudienceNodeContext,
			ChainID:       "test-chain",
			ChainSHA256:   chainHash,
			Nodes:         chain,
			CurrentNode:   node,
			OriginNode:    workstationNode,
			EndpointNode:  computeNode,
			Capabilities:  capabilities,
			Nonce:         nonce,
			IssuedAtUnix:  now.Add(-time.Second).Unix(),
			ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	workstationContext := signContext(workstationNode, "workstation-nonce", []string{
		authproof.CapabilityNodeContext,
		authproof.CapabilityVFSMesh,
	})
	computeContext := signContext(computeNode, "compute-nonce", []string{
		authproof.CapabilityNodeContext,
	})

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello through attach lifecycle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host, err := NewDynamicHost(DynamicHostConfig{
		Root:          root,
		ReadOnly:      true,
		SignedContext: workstationContext,
		PublicKey:     publicKey,
		MaxTTL:        10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network:    "tcp",
		X11Target:     "unused:0",
		AuthTimeout:   2 * time.Second,
		Proof: authproof.RuntimeConfig{
			Mode:          authproof.ProofModeOff,
			SecurityLevel: authproof.SecurityLevelCompat,
		},
	}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- runtime.ServeDynamicSessionConn(ctx, serverConn, host.Serve) }()

	t.Setenv("DISPLAY", "localhost:10.0")
	used := false
	attached, err := AttachDynamicSession(ctx, AttachConfig{
		AuthCookie:    cookie,
		SignedContext: computeContext,
		DialTimeout:   time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			if used {
				t.Fatal("attach dialed more than once")
			}
			used = true
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	if attached.Node != computeNode || strings.TrimSpace(attached.Session.Binding) == "" {
		t.Fatalf("attached=%+v", attached)
	}

	socketPath := filepath.Join(t.TempDir(), "session.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := &sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
		return sessioncontrol.OpenTarget(openCtx, attached.Session.Mux, request.Node, request.Service, request.Data)
	}}
	brokerErr := make(chan error, 1)
	go func() { brokerErr <- broker.Serve(ctx, listener) }()

	brokerConn, err := sessionbroker.Dial(ctx, "unix", socketPath, sessionbroker.OpenRequest{
		Node:    workstationNode,
		Service: sessionmux.ServiceFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := p9client.Attach(brokerConn)
	if err != nil {
		t.Fatal(err)
	}
	data, err := client.ReadFile("hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello through attach lifecycle\n" {
		t.Fatalf("hello.txt=%q", data)
	}
	_ = client.Close()

	// This direct host does not serve the attached node's filesystem. It must
	// reject that target instead of exposing the workstation root under another ID.
	if conn, err := sessionbroker.Dial(ctx, "unix", socketPath, sessionbroker.OpenRequest{
		Node:    computeNode,
		Service: sessionmux.ServiceFS,
	}); err == nil {
		_ = conn.Close()
		t.Fatal("non-local compute filesystem was accepted by workstation host")
	}

	cancel()
	if err := <-brokerErr; err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}
