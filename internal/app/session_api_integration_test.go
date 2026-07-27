package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/p9client"
	"weaverssh/sessionapi"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
)

func TestInBandAPIAndLargeP9TransferShareDynamicSession(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []string{"workstation-42", "compute-node"}
	chainHash := authproof.ChainBindingSHA256(nodes...)
	now := time.Now()
	sign := func(node, nonce string, capabilities []string) authproof.SignedNodeContext {
		t.Helper()
		value, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID: "api-integration",
			Audience: authproof.AudienceNodeContext,
			ChainID: "api-integration-chain",
			ChainSHA256: chainHash,
			Nodes: nodes,
			CurrentNode: node,
			OriginNode: nodes[0],
			EndpointNode: nodes[1],
			Capabilities: capabilities,
			Nonce: nonce,
			IssuedAtUnix: now.Add(-time.Second).Unix(),
			ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	workstationContext := sign(nodes[0], "api-workstation", []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh})
	computeContext := sign(nodes[1], "api-compute", []string{authproof.CapabilityNodeContext})

	root := t.TempDir()
	payload := bytes.Repeat([]byte("api-and-p9-flow-control\n"), 24000)
	if err := os.WriteFile(filepath.Join(root, "large.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	hostReady := make(chan *sessionruntime.Session, 1)
	host, err := NewDynamicHost(DynamicHostConfig{
		Root: root,
		ReadOnly: true,
		SignedContext: workstationContext,
		PublicKey: publicKey,
		OnReady: func(
			session *sessionruntime.Session,
			_ *sessioncontrol.Registry,
			_, _ sessioncontrol.Node,
			_ *sessionroute.Router,
		) (func(), error) {
			hostReady <- session
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network: "tcp",
		X11Target: "unused:0",
		AuthTimeout: 2 * time.Second,
		Proof: authproof.RuntimeConfig{Mode: authproof.ProofModeOff, SecurityLevel: authproof.SecurityLevelCompat},
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
	attached, err := AttachDynamicSession(ctx, AttachConfig{
		AuthCookie: cookie,
		SignedContext: computeContext,
		DialTimeout: time.Second,
		PreviousNode: nodes[0],
		Dial: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	hostSession := <-hostReady

	fileStream, err := sessioncontrol.OpenTarget(ctx, attached.Session.Mux, nodes[0], sessionmux.ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := p9client.Attach(fileStream)
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	errorsCh := make(chan error, 17)
	group.Add(1)
	go func() {
		defer group.Done()
		data, err := client.ReadFile("large.bin")
		if err == nil && !bytes.Equal(data, payload) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			errorsCh <- err
		}
	}()
	for index := 0; index < 15; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			var snapshot sessionapi.Snapshot
			if err := sessionapi.Call(ctx, attached.Session.Mux, sessionapi.MethodDescribe, nil, &snapshot); err != nil {
				errorsCh <- err
				return
			}
			if snapshot.CurrentNode != nodes[0] || snapshot.Binding != attached.Session.Binding || len(snapshot.Topology) != 2 {
				errorsCh <- io.ErrUnexpectedEOF
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		var plan sessionapi.RoutePlan
		if err := sessionapi.Call(ctx, hostSession.Mux, sessionapi.MethodRoutePrepare, sessionapi.RoutePrepareParams{Node: nodes[0], Service: "fs"}, &plan); err != nil {
			errorsCh <- err
			return
		}
		if plan.Direction != "previous" || plan.NextHop != nodes[0] || !plan.Available || !plan.UsesCurrent || plan.NextBinding == "" {
			errorsCh <- io.ErrUnexpectedEOF
		}
	}()
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	_ = client.Close()
	_ = attached.Close()
	cancel()
	select {
	case err := <-hostErr:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop")
	}
}
