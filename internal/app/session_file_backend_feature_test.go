package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/filebackend"
	"weaverssh/sessionmux"
)

func TestSessionAPISnapshotReportsFileBackendCore(t *testing.T) {
	root := t.TempDir()
	registry := filebackend.NewRegistry(nil)
	if err := registry.Register(filebackend.Hook{
		Operation: filebackend.OperationRead,
		Handler: func(context.Context, filebackend.Event) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := filebackend.NewOSService(root, false, filebackend.NewMemoryStore(), registry)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	local := &LocalServices{
		Context: authproof.NodeContext{
			Nodes: []string{"node-a"}, CurrentNode: "node-a",
			OriginNode: "node-a", EndpointNode: "node-a",
		},
		services: []sessionmux.ServiceID{sessionmux.ServiceFS},
		fileBackend: controller,
	}
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: local.Context, Local: local})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(snapshot.Features, " ")
	for _, feature := range []string{"fs.backend-api.v1", "fs.qid-core.v1", "fs.hooks.v1", "fs.core.memory.v1"} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
