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
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/p9client"
	"weaverssh/sessionapi"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
)

func TestThreeNodeFilesystemRoutingAcrossTwoDynamicSessions(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	nodes := []string{"workstation-42", "jump-a", "compute-node"}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sign := func(node, nonce string, capabilities []string) authproof.SignedNodeContext {
		t.Helper()
		signed, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID: "three-node-route-test",
			Audience: authproof.AudienceNodeContext,
			ChainID: "three-node-route-chain",
			ChainSHA256: authproof.ChainBindingSHA256(nodes...),
			Nodes: nodes,
			CurrentNode: node,
			OriginNode: nodes[0],
			EndpointNode: nodes[2],
			Capabilities: capabilities,
			Nonce: nonce,
			IssuedAtUnix: now.Unix(),
			ExpiresAtUnix: now.Add(10 * time.Minute).Unix(),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	workstationContext := sign(nodes[0], "route-workstation", []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh})
	jumpContext := sign(nodes[1], "route-jump", []string{authproof.CapabilityNodeContext})
	computeContext := sign(nodes[2], "route-compute", []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh})

	workstationRoot := t.TempDir()
	computeRoot := t.TempDir()
	workstationPayload := bytes.Repeat([]byte("from-workstation-through-jump\n"), 24000)
	computePayload := bytes.Repeat([]byte("from-compute-through-jump\n"), 24000)
	if err := os.WriteFile(filepath.Join(workstationRoot, "workstation.bin"), workstationPayload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(computeRoot, "compute.bin"), computePayload, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	routePath := filepath.Join(t.TempDir(), "routes.json")
	routeStore := sessionroute.Store{Path: routePath}
	t.Setenv("DISPLAY", "localhost:10.0")

	// Session 1: workstation-42 <-> jump-a.
	workstationReady := make(chan *sessionruntime.Session, 1)
	workstationHost, err := NewDynamicHost(DynamicHostConfig{
		Root: workstationRoot,
		ReadOnly: true,
		SignedContext: workstationContext,
		PublicKey: publicKey,
		RouteStorePath: routePath,
		OnReady: func(
			session *sessionruntime.Session,
			_ *sessioncontrol.Registry,
			_, _ sessioncontrol.Node,
			_ *sessionroute.Router,
		) (func(), error) {
			workstationReady <- session
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	workstationRuntime := testAgentRuntime(t, cookie)
	defer workstationRuntime.Close()
	workstationServerConn, jumpParentConn := net.Pipe()
	workstationErr := make(chan error, 1)
	go func() { workstationErr <- workstationRuntime.ServeDynamicSessionConn(ctx, workstationServerConn, workstationHost.Serve) }()
	jumpParent, err := AttachDynamicSession(ctx, AttachConfig{
		AuthCookie: cookie,
		SignedContext: jumpContext,
		PreviousNode: nodes[0],
		RouteStorePath: routePath,
		DialTimeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return jumpParentConn, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer jumpParent.Close()
	workstationSession := <-workstationReady

	parentSocket := filepath.Join(t.TempDir(), "jump-parent.sock")
	parentListener, err := net.Listen("unix", parentSocket)
	if err != nil {
		t.Fatal(err)
	}
	parentBroker := &sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
		if request.Service == sessionmux.ServiceControl {
			return sessionapi.Open(openCtx, jumpParent.Session.Mux)
		}
		return jumpParent.Router.OpenLocal(openCtx, request.Node, request.Service, request.Data)
	}}
	parentBrokerErr := make(chan error, 1)
	go func() { parentBrokerErr <- parentBroker.Serve(ctx, parentListener) }()
	parentEntry, err := sessionroute.NewEntry(jumpContext.Context, jumpParent.Session.Binding, parentSocket, nodes[0], os.Getpid(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := routeStore.Register(ctx, parentEntry); err != nil {
		t.Fatal(err)
	}

	// Session 2: jump-a <-> compute-node. The jump host owns a second broker.
	childSocket := filepath.Join(t.TempDir(), "jump-child.sock")
	childListener, err := net.Listen("unix", childSocket)
	if err != nil {
		t.Fatal(err)
	}
	childBrokerRouter := &sessionbroker.Router{}
	childBrokerErr := make(chan error, 1)
	go func() {
		childBrokerErr <- (&sessionbroker.Server{Open: childBrokerRouter.Open}).Serve(ctx, childListener)
	}()
	jumpChildReady := make(chan *sessionruntime.Session, 1)
	jumpHost, err := NewDynamicHost(DynamicHostConfig{
		SignedContext: jumpContext,
		PublicKey: publicKey,
		ControlOnly: true,
		RouteStorePath: routePath,
		OnReady: func(
			session *sessionruntime.Session,
			_ *sessioncontrol.Registry,
			local, remote sessioncontrol.Node,
			router *sessionroute.Router,
		) (func(), error) {
			clear := childBrokerRouter.Set(session.Binding, func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
				if request.Service == sessionmux.ServiceControl {
					return sessionapi.Open(openCtx, session.Mux)
				}
				return router.OpenLocal(openCtx, request.Node, request.Service, request.Data)
			})
			entry, err := sessionroute.NewEntry(jumpContext.Context, session.Binding, childSocket, remote.ID, os.Getpid(), now.Add(time.Second))
			if err != nil {
				clear()
				return nil, err
			}
			if err := routeStore.Register(ctx, entry); err != nil {
				clear()
				return nil, err
			}
			if local.ID != nodes[1] || remote.ID != nodes[2] {
				clear()
				return nil, io.ErrUnexpectedEOF
			}
			jumpChildReady <- session
			return func() {
				_ = routeStore.Remove(context.Background(), session.Binding)
				clear()
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	jumpRuntime := testAgentRuntime(t, cookie)
	defer jumpRuntime.Close()
	jumpServerConn, computeConn := net.Pipe()
	jumpHostErr := make(chan error, 1)
	go func() { jumpHostErr <- jumpRuntime.ServeDynamicSessionConn(ctx, jumpServerConn, jumpHost.Serve) }()
	computeServices, err := NewLocalServices(LocalServiceConfig{
		SignedContext: computeContext,
		PublicKey: publicKey,
		Root: computeRoot,
		ReadOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := AttachDynamicSession(ctx, AttachConfig{
		AuthCookie: cookie,
		SignedContext: computeContext,
		PreviousNode: nodes[1],
		LocalServices: computeServices,
		RouteStorePath: routePath,
		DialTimeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return computeConn, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer compute.Close()
	<-jumpChildReady

	// Final node to root: compute opens current child session; jump routes to parent.
	toWorkstation, err := compute.Router.OpenLocal(ctx, nodes[0], sessionmux.ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	workstationClient, err := p9client.Attach(toWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	gotWorkstation, err := workstationClient.ReadFile("workstation.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotWorkstation, workstationPayload) {
		t.Fatalf("workstation bytes=%d want=%d", len(gotWorkstation), len(workstationPayload))
	}
	_ = workstationClient.Close()

	// Root to final: workstation sends target into parent session; jump routes child.
	toCompute, err := sessioncontrol.OpenTarget(ctx, workstationSession.Mux, nodes[2], sessionmux.ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	computeClient, err := p9client.Attach(toCompute)
	if err != nil {
		t.Fatal(err)
	}
	gotCompute, err := computeClient.ReadFile("compute.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCompute, computePayload) {
		t.Fatalf("compute bytes=%d want=%d", len(gotCompute), len(computePayload))
	}
	_ = computeClient.Close()

	// Live API planning at jump must report the opposite adjacent binding.
	var routePlan sessionapi.RoutePlan
	if err := sessionapi.Call(ctx, compute.Session.Mux, sessionapi.MethodRoutePrepare, sessionapi.RoutePrepareParams{Node: nodes[0], Service: "fs"}, &routePlan); err != nil {
		t.Fatal(err)
	}
	if !routePlan.Available || routePlan.Direction != "previous" || routePlan.NextHop != nodes[0] || routePlan.NextBinding != jumpParent.Session.Binding {
		t.Fatalf("route plan=%+v", routePlan)
	}

	cancel()
	_ = compute.Close()
	_ = jumpParent.Close()
	_ = parentListener.Close()
	_ = childListener.Close()
	for name, channel := range map[string]<-chan error{
		"workstation-host": workstationErr,
		"jump-host": jumpHostErr,
		"parent-broker": parentBrokerErr,
		"child-broker": childBrokerErr,
	} {
		select {
		case err := <-channel:
			if err != nil && ctx.Err() == nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not stop", name)
		}
	}
}

func testAgentRuntime(t *testing.T, cookie string) *AgentRuntime {
	t.Helper()
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
	return runtime
}
