package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/mapreduce"
)

func TestSessionAPISnapshotReportsMapReduce(t *testing.T) {
	registry := mapreduce.NewRegistry()
	if err := registry.RegisterPlugin(mapreduce.Plugin{
		Descriptor: mapreduce.Descriptor{Name: "identity", Version: "1"},
		Map: func(_ context.Context, input mapreduce.MapInput) ([]mapreduce.Record, error) {
			return []mapreduce.Record{input.Record}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	policy, err := mapreduce.NewPolicy(mapreduce.Policy{
		Version: mapreduce.PolicyVersion,
		Default: mapreduce.EffectDeny,
		Rules: []mapreduce.Rule{{
			Name:        "describe-and-map",
			Effect:      mapreduce.EffectAllow,
			SourceNodes: []string{"node-a"},
			TargetNodes: []string{"node-a"},
			Plugins:     []string{"identity", "system.describe"},
			Operations:  []mapreduce.Operation{mapreduce.OperationDescribe, mapreduce.OperationMap},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := mapreduce.NewEngine(mapreduce.EngineConfig{
		Topology: mapreduce.Topology{
			ChainSHA256: strings.Repeat("a", 64),
			Nodes:       []string{"node-a"},
			CurrentNode: "node-a",
		},
		Registry: registry,
		Policy:   policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	local := &LocalServices{Context: authproof.NodeContext{
		ChainSHA256: strings.Repeat("a", 64),
		Nodes:       []string{"node-a"},
		CurrentNode: "node-a",
		OriginNode:  "node-a",
		EndpointNode: "node-a",
	}}
	if err := installMapReduce(local, engine); err != nil {
		t.Fatal(err)
	}
	defer uninstallMapReduce(local)

	server := NewSessionAPIServer(SessionAPIConfig{
		Binding: "binding-a",
		Context: local.Context,
		Local:   local,
	})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(snapshot.Features, " ")
	for _, feature := range []string{
		"compute.mapreduce.v1",
		"compute.mapreduce.rules.v1",
		"compute.mapreduce.plugins.v1",
	} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
