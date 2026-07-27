package sessionroute

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
)

func TestRouterPrepareUsesCurrentOrOppositeBinding(t *testing.T) {
	ctx := routeContext([]string{"workstation-42", "jump-a", "compute-node"}, "jump-a")
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	child, err := NewEntry(ctx, "child-binding", filepath.Join(t.TempDir(), "child.sock"), "compute-node", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	router := &Router{
		Store: store,
		Context: ctx,
		CurrentBinding: "parent-binding",
		CurrentMux: &sessionmux.Mux{},
		PeerNode: "workstation-42",
	}
	parentPlan, err := router.Prepare("workstation-42")
	if err != nil {
		t.Fatal(err)
	}
	if !parentPlan.Available || !parentPlan.UsesCurrent || parentPlan.NextBinding != "parent-binding" {
		t.Fatalf("parent plan=%+v", parentPlan)
	}
	childPlan, err := router.Prepare("compute-node")
	if err != nil {
		t.Fatal(err)
	}
	if !childPlan.Available || childPlan.UsesCurrent || childPlan.NextBinding != "child-binding" {
		t.Fatalf("child plan=%+v", childPlan)
	}
}

func TestOpenForwardRejectsSourcePeerSide(t *testing.T) {
	ctx := routeContext([]string{"workstation-42", "jump-a", "compute-node"}, "jump-a")
	router := &Router{
		Store: Store{Path: filepath.Join(t.TempDir(), "routes.json")},
		Context: ctx,
		CurrentBinding: "child-binding",
		PeerNode: "compute-node",
	}
	_, _, err := router.OpenForward(context.Background(), sessioncontrol.PendingTarget{
		NodeRef: "compute-node",
		Service: sessionmux.ServiceFS,
	})
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("error=%v want ErrNoRoute", err)
	}
}

func TestOpenForwardRequiresOppositeAdjacentEntry(t *testing.T) {
	ctx := routeContext([]string{"a", "b", "c"}, "b")
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	router := &Router{Store: store, Context: ctx, CurrentBinding: "child", PeerNode: "c"}
	_, _, err := router.OpenForward(context.Background(), sessioncontrol.PendingTarget{NodeRef: "a", Service: sessionmux.ServiceFS})
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("error=%v want ErrNoRoute", err)
	}
}

func TestLiveBrokerTargetDenialDoesNotPruneRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	nodeContext := routeContext([]string{"a", "b", "c"}, "b")
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	socket := filepath.Join(t.TempDir(), "live.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- (&sessionbroker.Server{Open: func(context.Context, sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			return nil, errors.New("final service denied")
		}}).Serve(ctx, listener)
	}()
	entry, err := NewEntry(nodeContext, "child-binding", socket, "c", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, entry); err != nil {
		t.Fatal(err)
	}
	router := &Router{Store: store, Context: nodeContext, CurrentBinding: "parent-binding", PeerNode: "a"}
	if _, err := router.OpenLocal(ctx, "c", sessionmux.ServiceFS, nil); err == nil {
		t.Fatal("target denial unexpectedly succeeded")
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Binding != "child-binding" {
		t.Fatalf("live route was pruned: %+v", snapshot.Entries)
	}
	cancel()
	_ = listener.Close()
	select {
	case err := <-brokerDone:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
}

func TestStaleNewestBrokerFallsBackToOlderLiveRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	nodeContext := routeContext([]string{"a", "b", "c"}, "b")
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	liveSocket := filepath.Join(t.TempDir(), "live.sock")
	listener, err := net.Listen("unix", liveSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- (&sessionbroker.Server{Open: func(context.Context, sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			left, right := net.Pipe()
			go func() {
				defer right.Close()
				_, _ = io.Copy(io.Discard, right)
			}()
			return left, nil
		}}).Serve(ctx, listener)
	}()
	liveEntry, err := NewEntry(nodeContext, "live-binding", liveSocket, "c", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	staleEntry, err := NewEntry(nodeContext, "stale-binding", filepath.Join(t.TempDir(), "missing.sock"), "c", 2, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, liveEntry); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, staleEntry); err != nil {
		t.Fatal(err)
	}
	router := &Router{Store: store, Context: nodeContext, CurrentBinding: "parent-binding", PeerNode: "a"}
	conn, err := router.OpenLocal(ctx, "c", sessionmux.ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Binding != "live-binding" {
		t.Fatalf("entries after fallback=%+v", snapshot.Entries)
	}
	cancel()
	_ = listener.Close()
	select {
	case err := <-brokerDone:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
}
