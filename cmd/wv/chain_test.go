package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

func TestSplitChainNodesSupportsJumpSyntax(t *testing.T) {
	got := splitChainNodes("node/local->node/linode-a=>profile/linode-b,edge + target")
	want := []string{"node/local", "node/linode-a", "profile/linode-b", "edge", "target"}
	if !slices.Equal(got, want) {
		t.Fatalf("splitChainNodes=%v want %v", got, want)
	}
}

func TestConnectionsNodeFlagOneLinerAndUseByNumber(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnections([]string{"--name", "linodes", "--number", "1", "--nodes", "node/local->node/linode-a->profile/linode-b", "--tag", "prod", "-l", "env=prod", "--set-label", "role=jump"}); rc != 0 {
		t.Fatalf("connections --nodes rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore: %v", err)
	}
	if store.ActiveChain != "linodes" || len(store.Chains) != 1 {
		t.Fatalf("store chain state wrong: %+v", store)
	}
	chain := store.Chains[0]
	if chain.Number != 1 || chain.Label != "linodes" {
		t.Fatalf("chain identity wrong: %+v", chain)
	}
	if !slices.Equal(chain.Nodes, []string{"local", "linode-a", "linode-b"}) {
		t.Fatalf("chain nodes wrong: %+v", chain.Nodes)
	}
	if len(chain.Tags) != 1 || chain.Tags[0] != "prod" {
		t.Fatalf("chain tags wrong: %+v", chain.Tags)
	}
	if chain.Labels["env"] != "prod" || chain.Labels["role"] != "jump" {
		t.Fatalf("chain labels wrong: %+v", chain.Labels)
	}
	resolved, _, ok := resolveChain(store, "#1")
	if !ok || resolved.Label != "linodes" {
		t.Fatalf("resolve #1 failed: %+v ok=%v", resolved, ok)
	}
}

func TestConnectionsNodeFlagDefaultsLabelAndNumber(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnections([]string{"--node", "node1,node2,node3"}); rc != 0 {
		t.Fatalf("connections --node rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore: %v", err)
	}
	if len(store.Chains) != 1 {
		t.Fatalf("chains=%d want 1: %+v", len(store.Chains), store.Chains)
	}
	chain := store.Chains[0]
	if chain.Number != 1 || chain.Label != "chain-1" || store.ActiveChain != "chain-1" {
		t.Fatalf("default chain wrong: %+v active=%q", chain, store.ActiveChain)
	}
	if !slices.Equal(chain.Nodes, []string{"node1", "node2", "node3"}) {
		t.Fatalf("default chain nodes wrong: %+v", chain.Nodes)
	}
}

func TestConnectionsNodeFlagAppendIncrementally(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnections([]string{"--label", "incident", "--number", "7", "--node", "local"}); rc != 0 {
		t.Fatalf("initial --node rc=%d", rc)
	}
	if rc := cmdConnections([]string{"--label", "incident", "--append", "--node", "linode-a,linode-b"}); rc != 0 {
		t.Fatalf("append --node rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatalf("loadConnStore: %v", err)
	}
	chain, _, ok := findChain(store, "incident")
	if !ok {
		t.Fatal("incident chain missing")
	}
	if chain.Number != 7 {
		t.Fatalf("append should keep chain number 7: %+v", chain)
	}
	if !slices.Equal(chain.Nodes, []string{"local", "linode-a", "linode-b"}) {
		t.Fatalf("nodes after append=%v", chain.Nodes)
	}
}

func TestConnectionsNodeFlagRejectsDuplicateNumberAndDuplicateNode(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnections([]string{"--label", "a", "--number", "1", "--nodes", "local,linode-a"}); rc != 0 {
		t.Fatalf("chain a rc=%d", rc)
	}
	if rc := cmdConnections([]string{"--label", "b", "--number", "1", "--nodes", "local,linode-b"}); rc != 1 {
		t.Fatalf("duplicate number rc=%d want 1", rc)
	}
	if rc := cmdConnections([]string{"--label", "dup", "--number", "2", "--nodes", "local,local"}); rc != 2 {
		t.Fatalf("duplicate node rc=%d want 2", rc)
	}
}

func TestNormalizeResourceRefs(t *testing.T) {
	if got := normalizeNodeRef("node/linode-a"); got != "linode-a" {
		t.Fatalf("normalizeNodeRef node/=%q", got)
	}
	if got := normalizeNodeRef("profile/linode-b"); got != "linode-b" {
		t.Fatalf("normalizeNodeRef profile/=%q", got)
	}
	if got := normalizeChainRef("chain/linodes"); got != "linodes" {
		t.Fatalf("normalizeChainRef chain/=%q", got)
	}
}

func TestConnectionsNodeFlagJSON(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	rc, out := captureStdout(t, func() int {
		return cmdConnections([]string{"--label", "linodes", "--number", "1", "--nodes", "local,linode-a,linode-b", "--json"})
	})
	if rc != 0 {
		t.Fatalf("connections --nodes --json rc=%d output=%s", rc, out)
	}
	var chain ConnChain
	if err := json.Unmarshal([]byte(out), &chain); err != nil {
		t.Fatalf("decode chain json: %v\n%s", err, out)
	}
	if chain.Label != "linodes" || chain.Number != 1 || len(chain.Nodes) != 3 {
		t.Fatalf("decoded chain wrong: %+v", chain)
	}
}

func TestConnectionsChainSubcommandLifecycle(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if rc := cmdConnectionsDispatch([]string{"chain", "set", "linodes", "--number", "1", "--nodes", "local,linode-a,linode-b"}); rc != 0 {
		t.Fatalf("chain set rc=%d", rc)
	}
	if rc := cmdConnectionsDispatch([]string{"chain", "use", "#1"}); rc != 0 {
		t.Fatalf("chain use rc=%d", rc)
	}
	if rc := cmdConnectionsDispatch([]string{"chain", "rename", "#1", "production"}); rc != 0 {
		t.Fatalf("chain rename rc=%d", rc)
	}
	store, err := loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.ActiveChain != "production" || len(store.Chains) != 1 || store.Chains[0].Number != 1 {
		t.Fatalf("renamed store=%+v", store)
	}
	rc, output := captureStdout(t, func() int {
		return cmdConnectionsDispatch([]string{"chain", "current", "--json"})
	})
	if rc != 0 {
		t.Fatalf("chain current rc=%d output=%s", rc, output)
	}
	var current ConnChain
	if err := json.Unmarshal([]byte(output), &current); err != nil || current.Label != "production" {
		t.Fatalf("current=%+v err=%v output=%s", current, err, output)
	}
	if rc := cmdConnectionsDispatch([]string{"chain", "remove", "production"}); rc != 0 {
		t.Fatalf("chain remove rc=%d", rc)
	}
	store, err = loadConnStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Chains) != 0 || store.ActiveChain != "" {
		t.Fatalf("removed store=%+v", store)
	}
}
