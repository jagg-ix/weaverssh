package sessionroute

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestStoreResolvesOppositeAdjacentSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	store := Store{Path: path}
	ctx := routeContext([]string{"workstation-42", "jump-a", "compute-node"}, "jump-a")
	now := time.Now()
	parent, err := NewEntry(ctx, "binding-parent", filepath.Join(t.TempDir(), "parent.sock"), "workstation-42", 100, now)
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewEntry(ctx, "binding-child", filepath.Join(t.TempDir(), "child.sock"), "compute-node", 101, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), child); err != nil {
		t.Fatal(err)
	}

	entry, target, index, err := store.ResolveAdjacent("binding-parent", ctx, "compute-node")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Binding != "binding-child" || target != "compute-node" || index != 2 {
		t.Fatalf("entry=%+v target=%q index=%d", entry, target, index)
	}
	entry, target, index, err = store.ResolveAdjacent("binding-child", ctx, "workstation-42")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Binding != "binding-parent" || target != "workstation-42" || index != 0 {
		t.Fatalf("entry=%+v target=%q index=%d", entry, target, index)
	}
}

func TestStoreExcludesIncomingBindingAndMismatchedChain(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	ctx := routeContext([]string{"a", "b", "c"}, "b")
	entry, err := NewEntry(ctx, "current", filepath.Join(t.TempDir(), "current.sock"), "c", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ResolveAdjacent("current", ctx, "c"); err == nil {
		t.Fatal("incoming binding unexpectedly selected itself")
	}

	other := entry
	other.Binding = "wrong-chain"
	other.Socket = filepath.Join(t.TempDir(), "wrong.sock")
	other.ChainSHA256 = strings.Repeat("f", 64)
	if err := store.Register(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ResolveAdjacent("current", ctx, "c"); err == nil {
		t.Fatal("mismatched chain unexpectedly selected")
	}
}

func TestStoreSelectsNewestMatchingEntry(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	ctx := routeContext([]string{"a", "b", "c"}, "b")
	now := time.Now()
	for _, item := range []struct {
		binding string
		started time.Time
	}{
		{binding: "old", started: now},
		{binding: "new", started: now.Add(time.Second)},
	} {
		entry, err := NewEntry(ctx, item.binding, filepath.Join(t.TempDir(), item.binding+".sock"), "c", 1, item.started)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Register(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	entry, _, _, err := store.ResolveAdjacent("incoming-parent", ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Binding != "new" {
		t.Fatalf("binding=%q want new", entry.Binding)
	}
}

func TestRegistryIsUserPrivateAndRemovable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	store := Store{Path: path}
	ctx := routeContext([]string{"a", "b"}, "a")
	entry, err := NewEntry(ctx, "binding", filepath.Join(t.TempDir(), "route.sock"), "b", os.Getpid(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := store.Remove(context.Background(), "binding"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 0 {
		t.Fatalf("entries=%+v", snapshot.Entries)
	}
}

func TestResolveNodeUsesSignedRelativeNames(t *testing.T) {
	ctx := routeContext([]string{"a", "b", "c"}, "b")
	cases := map[string]string{"self": "b", "previous": "a", "next": "c", "endpoint": "c", "a": "a"}
	for input, want := range cases {
		got, _, err := ResolveNode(ctx, input)
		if err != nil || got != want {
			t.Fatalf("ResolveNode(%q)=%q err=%v want=%q", input, got, err, want)
		}
	}
	if _, _, err := ResolveNode(ctx, "user@host"); err == nil {
		t.Fatal("SSH identity syntax unexpectedly resolved as a route node")
	}
}

func routeContext(nodes []string, current string) authproof.NodeContext {
	now := time.Now()
	return authproof.NodeContext{
		IssuerPeerID: "route-test",
		ChainID: "route-chain",
		ChainSHA256: authproof.ChainBindingSHA256(nodes...),
		Nodes: append([]string(nil), nodes...),
		CurrentNode: current,
		OriginNode: nodes[0],
		EndpointNode: nodes[len(nodes)-1],
		Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce: "route-context-" + current,
		IssuedAtUnix: now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
	}
}
