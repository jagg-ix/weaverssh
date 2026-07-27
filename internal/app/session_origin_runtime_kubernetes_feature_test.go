package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/originruntime"
)

func TestSessionAPISnapshotReportsKubernetesOriginRuntime(t *testing.T) {
	t.Setenv(originruntime.EnvKind, string(originruntime.KindKubernetes))
	t.Setenv(originruntime.EnvID, "kubernetes-0123456789abcdef")
	chain := strings.Repeat("e", 64)
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
	for _, feature := range []string{"origin.runtime.v1", "origin.runtime.kubernetes.v1", "origin.runtime.path-map.v1"} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
