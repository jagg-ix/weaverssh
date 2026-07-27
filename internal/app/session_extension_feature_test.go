package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/extension"
)

type featureEBPFRuntime struct{}

func (featureEBPFRuntime) Name() string { return "test-vm" }
func (featureEBPFRuntime) Run(context.Context, extension.EBPFRuntimeRequest) (uint32, error) {
	return extension.EBPFDecisionAllow, nil
}

func TestSessionAPISnapshotReportsExtensionHooks(t *testing.T) {
	registry := extension.NewRegistry(nil)
	if err := registry.Register(extension.Definition{
		Descriptor: extension.Descriptor{Name: "audit", Version: "1"},
		Hooks: []extension.Hook{{
			Point: extension.PointSessionReady,
			Handler: func(context.Context, extension.Event) error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := extensionSnapshot(t, registry)
	if !strings.Contains(strings.Join(snapshot, " "), "extensions.hooks.v1") {
		t.Fatalf("features=%v", snapshot)
	}
}

func TestSessionAPISnapshotReportsEBPFRuntime(t *testing.T) {
	hook, err := extension.NewEBPFHook(featureEBPFRuntime{}, extension.EBPFHookConfig{
		Point: extension.PointTargetAuthorized, Program: "policy/program",
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := extension.NewRegistry(nil)
	if err := registry.RegisterEBPF(extension.Definition{
		Descriptor: extension.Descriptor{Name: "ebpf-policy", Version: "1"},
		Hooks:      []extension.Hook{hook},
	}); err != nil {
		t.Fatal(err)
	}
	features := extensionSnapshot(t, registry)
	joined := strings.Join(features, " ")
	for _, feature := range []string{"extensions.hooks.v1", "extensions.ebpf.v1"} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", features, feature)
		}
	}
}

func extensionSnapshot(t *testing.T, registry *extension.Registry) []string {
	t.Helper()
	nodeContext := authproof.NodeContext{
		Nodes:        []string{"workstation-42"},
		CurrentNode:  "workstation-42",
		OriginNode:   "workstation-42",
		EndpointNode: "workstation-42",
	}
	server := NewSessionAPIServer(SessionAPIConfig{
		Binding:    "binding-a",
		Context:    nodeContext,
		Extensions: registry,
	})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Features
}
