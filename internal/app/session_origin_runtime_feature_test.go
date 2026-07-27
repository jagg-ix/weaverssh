package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/originruntime"
)

func TestSessionAPISnapshotReportsOriginRuntime(t *testing.T) {
	t.Setenv(originruntime.EnvKind, string(originruntime.KindDocker))
	t.Setenv(originruntime.EnvID, "docker-0123456789abcdef")
	chain := strings.Repeat("c", 64)
	ctx := authproof.NodeContext{
		ChainSHA256: chain,
		Nodes: []string{"node-a"},
		CurrentNode: "node-a",
		OriginNode: "node-a",
		EndpointNode: "node-a",
		Capabilities: []string{authproof.CapabilityNodeContext},
	}
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: ctx})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(snapshot.Features, " ")
	for _, feature := range []string{"origin.runtime.v1", "origin.runtime.docker.v1", "origin.runtime.path-map.v1"} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}

func TestSessionAPISnapshotIgnoresUnpairedRuntimeMetadata(t *testing.T) {
	t.Setenv(originruntime.EnvKind, string(originruntime.KindWSL))
	t.Setenv(originruntime.EnvID, "")
	chain := strings.Repeat("d", 64)
	ctx := authproof.NodeContext{
		ChainSHA256: chain,
		Nodes: []string{"node-a"},
		CurrentNode: "node-a",
		OriginNode: "node-a",
		EndpointNode: "node-a",
		Capabilities: []string{authproof.CapabilityNodeContext},
	}
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: ctx})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(snapshot.Features, " "), "origin.runtime") {
		t.Fatalf("features=%v", snapshot.Features)
	}
}
