package sessionapi_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"weaverssh/sessionapi"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionmux"
)

func TestAPIAndServiceStreamsShareOneDispatcher(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil { t.Fatal(err) }
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil { t.Fatal(err) }
	defer right.Close()

	server := testServer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- (&sessiondispatch.Dispatcher{
			Mux: right,
			Control: server.ServeStream,
			Target: func(_ context.Context, stream *sessionmux.Stream) error {
				defer stream.Close()
				payload, err := io.ReadAll(stream)
				if err != nil { return err }
				_, err = stream.Write(append([]byte("echo:"), payload...))
				return err
			},
		}).Serve(ctx)
	}()

	const count = 20
	var group sync.WaitGroup
	errorsCh := make(chan error, count*2)
	for index := 0; index < count; index++ {
		index := index
		group.Add(2)
		go func() {
			defer group.Done()
			var plan sessionapi.RoutePlan
			err := sessionapi.Call(ctx, left, sessionapi.MethodRoutePrepare, sessionapi.RoutePrepareParams{Node: "workstation-42", Service: "fs"}, &plan)
			if err == nil && (plan.Direction != "previous" || plan.NextHop != "workstation-42") {
				err = fmt.Errorf("route plan=%+v", plan)
			}
			if err != nil { errorsCh <- err }
		}()
		go func() {
			defer group.Done()
			stream, err := left.Open(ctx, sessionmux.ServiceFS, []byte("test"))
			if err != nil { errorsCh <- err; return }
			message := []byte(fmt.Sprintf("payload-%d", index))
			if _, err := stream.Write(message); err != nil { errorsCh <- err; return }
			_ = stream.Close()
			response, err := io.ReadAll(stream)
			if err != nil { errorsCh <- err; return }
			if string(response) != "echo:"+string(message) { errorsCh <- fmt.Errorf("response=%q", response) }
		}()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh { t.Error(err) }
	cancel()
	_ = left.Close()
	_ = right.Close()
	select {
	case err := <-dispatchDone:
		if err != nil { t.Fatal(err) }
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop")
	}
}

func TestAllReadOnlyAPIMethods(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil { t.Fatal(err) }
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil { t.Fatal(err) }
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (&sessiondispatch.Dispatcher{Mux: right, Control: testServer().ServeStream}).Serve(ctx)
	}()

	var capabilities sessionapi.Capabilities
	if err := sessionapi.Call(ctx, left, sessionapi.MethodCapabilities, nil, &capabilities); err != nil { t.Fatal(err) }
	if capabilities.Protocol != sessionapi.ProtocolVersion || len(capabilities.Methods) != 5 { t.Fatalf("capabilities=%+v", capabilities) }

	var snapshot sessionapi.Snapshot
	if err := sessionapi.Call(ctx, left, sessionapi.MethodDescribe, nil, &snapshot); err != nil { t.Fatal(err) }
	if snapshot.CurrentNode != "jump-a" || snapshot.PreviousNode != "workstation-42" || snapshot.NextNode != "compute-node" || snapshot.HopDepth != 1 { t.Fatalf("snapshot=%+v", snapshot) }

	var topology struct {
		Topology []string          `json:"topology"`
		Nodes    []sessionapi.Node `json:"nodes"`
	}
	if err := sessionapi.Call(ctx, left, sessionapi.MethodTopology, nil, &topology); err != nil { t.Fatal(err) }
	if len(topology.Topology) != 3 || len(topology.Nodes) != 3 { t.Fatalf("topology=%+v", topology) }

	for input, want := range map[string]string{"self": "jump-a", "previous": "workstation-42", "next": "compute-node", "endpoint": "compute-node"} {
		var resolved sessionapi.ResolveResult
		if err := sessionapi.Call(ctx, left, sessionapi.MethodResolve, sessionapi.ResolveParams{Node: input}, &resolved); err != nil { t.Fatal(err) }
		if resolved.Node != want { t.Fatalf("resolve %q=%+v", input, resolved) }
	}

	for target, direction := range map[string]string{"workstation-42": "previous", "jump-a": "local", "compute-node": "next"} {
		var plan sessionapi.RoutePlan
		if err := sessionapi.Call(ctx, left, sessionapi.MethodRoutePrepare, sessionapi.RoutePrepareParams{Node: target, Service: "fs"}, &plan); err != nil { t.Fatal(err) }
		if plan.Direction != direction { t.Fatalf("route %q=%+v", target, plan) }
	}

	if err := sessionapi.Call(ctx, left, "unsupported.method", nil, &struct{}{}); err == nil || !strings.Contains(err.Error(), "unknown_method") {
		t.Fatalf("unknown method error=%v", err)
	}
	cancel()
	_ = left.Close()
	_ = right.Close()
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop")
	}
}

func testServer() *sessionapi.Server {
	return &sessionapi.Server{Snapshot: func(context.Context) (sessionapi.Snapshot, error) {
		return sessionapi.Snapshot{
			Binding: "binding-a", CurrentNode: "jump-a", CurrentIndex: 1,
			Topology: []string{"workstation-42", "jump-a", "compute-node"},
			Nodes: []sessionapi.Node{
				{ID: "workstation-42", Index: 0, Registered: true, Services: []string{"fs"}},
				{ID: "jump-a", Index: 1, Registered: true, Services: []string{"fs", "tcp"}},
				{ID: "compute-node", Index: 2, Registered: true},
			},
			LocalServices: []string{"fs", "tcp"}, Features: []string{"api.read.v1", "route.plan.v1"},
			PreviousNode: "workstation-42", NextNode: "compute-node", HopDepth: 1,
			HopChainSHA256: sessionapi.HopChainDigest("signed-hop-chain"),
		}, nil
	}}
}
