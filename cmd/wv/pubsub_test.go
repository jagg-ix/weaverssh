package main

import (
	"slices"
	"testing"
)

func TestPubSubDryRunPublishUsesGeneratedTopic(t *testing.T) {
	rc := cmdPubSub([]string{
		"publish",
		"--dry-run",
		"--component", "runtime",
		"--type", "status",
		"--message", "ready",
		"--field", "plane=ok",
	})
	if rc != 0 {
		t.Fatalf("pubsub publish dry-run rc=%d", rc)
	}
}

func TestPubSubRejectsBadField(t *testing.T) {
	if rc := cmdPubSub([]string{"publish", "--dry-run", "--field", "bad"}); rc != 2 {
		t.Fatalf("bad field rc=%d want 2", rc)
	}
}

func TestPubSubIsTopLevelCommand(t *testing.T) {
	if !slices.Contains(topLevelCommands, "pubsub") {
		t.Fatalf("topLevelCommands should include pubsub: %v", topLevelCommands)
	}
	if !slices.Contains(topLevelCommands, "events") {
		t.Fatalf("topLevelCommands should include events alias: %v", topLevelCommands)
	}
}

func TestPubSubMeshPlanRequiresChainNodesAndAcceptsValidChain(t *testing.T) {
	if rc := cmdPubSub([]string{"mesh-plan"}); rc != 2 {
		t.Fatalf("mesh-plan without nodes rc=%d want 2", rc)
	}
	if rc := cmdPubSub([]string{"mesh-plan", "--chain", "linodes", "--nodes", "alice,linode-a,linode-b"}); rc != 0 {
		t.Fatalf("mesh-plan valid chain rc=%d", rc)
	}
	if rc := cmdPubSub([]string{"mesh-plan", "--chain", "linodes", "--nodes", "alice,linode-a,linode-b", "--scheme", "many-to-many"}); rc != 0 {
		t.Fatalf("mesh-plan many-to-many rc=%d", rc)
	}
	if rc := cmdPubSub([]string{"mesh-plan", "--chain", "linodes", "--nodes", "alice,linode-a", "--scheme", "bad"}); rc != 2 {
		t.Fatalf("mesh-plan bad scheme rc=%d want 2", rc)
	}
	if rc := cmdPubSub([]string{"mesh-plan", "--chain", "linodes", "--nodes", "alice"}); rc != 2 {
		t.Fatalf("mesh-plan single node rc=%d want 2", rc)
	}
}

func TestPubSubMeshPlanRejectsDuplicateNodes(t *testing.T) {
	if rc := cmdPubSub([]string{"mesh-plan", "--chain", "linodes", "--nodes", "origin,node1,origin"}); rc != 2 {
		t.Fatalf("mesh-plan duplicate nodes rc=%d want 2", rc)
	}
}

func TestPubSubPublishOriginFlag(t *testing.T) {
	if rc := cmdPubSub([]string{"publish", "--dry-run", "--origin", "external", "--component", "adapter", "--type", "status"}); rc != 0 {
		t.Fatalf("external origin dry-run rc=%d", rc)
	}
	if rc := cmdPubSub([]string{"publish", "--dry-run", "--origin", "bad", "--component", "adapter", "--type", "status"}); rc != 2 {
		t.Fatalf("bad origin rc=%d want 2", rc)
	}
}
