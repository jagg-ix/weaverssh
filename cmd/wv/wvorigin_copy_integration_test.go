package main

import (
	"bytes"
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
	"weaverssh/internal/app"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
)

// TestWVCPFromEndpointToWVOriginWorkstation covers the user-facing direction:
//
//   # WVORIGIN was passed into the SSH session by session-host
//   wv cp someOnNodeFS/path/file.txt "$WVORIGIN:/mypath/"
//
// The source is an ordinary endpoint-local path. The destination is the concrete
// signed workstation node ID, not an "origin" keyword.
func TestWVCPFromEndpointToWVOriginWorkstation(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	const workstationNode = "workstation-42"
	const endpointNode = "compute-node"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	chain := []string{workstationNode, endpointNode}
	chainHash := authproof.ChainBindingSHA256(chain...)
	sign := func(node, nonce string, capabilities []string) authproof.SignedNodeContext {
		t.Helper()
		signed, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID:  "wvorigin-copy-test",
			Audience:      authproof.AudienceNodeContext,
			ChainID:       "wvorigin-copy-chain",
			ChainSHA256:   chainHash,
			Nodes:         chain,
			CurrentNode:   node,
			OriginNode:    workstationNode,
			EndpointNode:  endpointNode,
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
	workstationContext := sign(workstationNode, "wvorigin-copy-workstation", []string{
		authproof.CapabilityNodeContext,
		authproof.CapabilityVFSMesh,
	})
	endpointContext := sign(endpointNode, "wvorigin-copy-endpoint", []string{
		authproof.CapabilityNodeContext,
	})

	workstationRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workstationRoot, "mypath"), 0o755); err != nil {
		t.Fatal(err)
	}
	host, err := app.NewDynamicHost(app.DynamicHostConfig{
		Root:          workstationRoot,
		ReadOnly:      false,
		SignedContext: workstationContext,
		PublicKey:     publicKey,
		MaxTTL:        10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := app.NewAgentRuntime(app.AgentConfig{
		InterfaceMode: string(app.AgentInterfaceLibrary),
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
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	hostErr := make(chan error, 1)
	go func() { hostErr <- runtime.ServeDynamicSessionConn(ctx, serverConn, host.Serve) }()

	t.Setenv("DISPLAY", "localhost:10.0")
	t.Setenv(app.EnvWVOrigin, workstationNode)
	if _, err := app.ValidateWVOrigin(os.Getenv(app.EnvWVOrigin), endpointContext.Context); err != nil {
		t.Fatal(err)
	}
	attached, err := app.AttachDynamicSession(ctx, app.AttachConfig{
		AuthCookie:    cookie,
		SignedContext: endpointContext,
		DialTimeout:   time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()

	socket := filepath.Join(t.TempDir(), "endpoint-session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openedNode := make(chan string, 1)
	broker := &sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
		if request.Service != sessionmux.ServiceFS {
			t.Errorf("broker service=%s, want fs", request.Service)
		}
		select {
		case openedNode <- request.Node:
		default:
		}
		return sessioncontrol.OpenTarget(openCtx, attached.Session.Mux, request.Node, request.Service, request.Data)
	}}
	brokerErr := make(chan error, 1)
	go func() { brokerErr <- broker.Serve(ctx, listener) }()

	statePath := filepath.Join(t.TempDir(), "endpoint-session.json")
	if err := sessionbroker.WriteState(statePath, sessionbroker.State{
		PID:       os.Getpid(),
		Socket:    socket,
		Binding:   attached.Session.Binding,
		Node:      endpointNode,
		StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(sessionbroker.EnvSocket, "")

	endpointRoot := t.TempDir()
	sourceRelative := filepath.Join("someOnNodeFS", "path", "file.txt")
	sourceAbsolute := filepath.Join(endpointRoot, sourceRelative)
	if err := os.MkdirAll(filepath.Dir(sourceAbsolute), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("endpoint-to-wvorigin-flow-controlled-copy\n"), 24000)
	if err := os.WriteFile(sourceAbsolute, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(endpointRoot); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWorkingDirectory)

	var stderr bytes.Buffer
	destination := os.Getenv(app.EnvWVOrigin) + ":/mypath/"
	if code := cmdSessionCP([]string{filepath.ToSlash(sourceRelative), destination}, bytes.NewReader(nil), io.Discard, &stderr); code != 0 {
		t.Fatalf("wv cp code=%d stderr=%s", code, stderr.String())
	}

	select {
	case node := <-openedNode:
		if node != workstationNode {
			t.Fatalf("broker target=%q want %q", node, workstationNode)
		}
	case <-time.After(time.Second):
		t.Fatal("wv cp did not open the WVORIGIN filesystem target")
	}
	copied, err := os.ReadFile(filepath.Join(workstationRoot, "mypath", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, payload) {
		t.Fatalf("copied bytes=%d want=%d", len(copied), len(payload))
	}

	_ = attached.Close()
	cancel()
	_ = listener.Close()
	select {
	case err := <-brokerErr:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("endpoint broker did not stop")
	}
	select {
	case err := <-hostErr:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("workstation host did not stop")
	}
}
