package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/sessionevents"
	"weaverssh/sessionexec"
	"weaverssh/sessionmux"
)

func TestSessionAPISnapshotReportsExecAndEvents(t *testing.T) {
	chain := strings.Repeat("c", 64)
	local := &LocalServices{Context: authproof.NodeContext{ChainSHA256: chain, Nodes: []string{"node-a"}, CurrentNode: "node-a", OriginNode: "node-a", EndpointNode: "node-a", Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityMapReduce}}}
	execPolicy, err := sessionexec.ParsePolicy([]byte(`{"version":"weaverssh.exec-policy.v1","default":"deny","actions":[{"name":"echo","executable":"/bin/echo","sources":["node-a"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	execEngine, err := sessionexec.NewEngine(sessionexec.EngineConfig{Topology: local.Context.Nodes, ChainSHA256: chain, CurrentNode: "node-a", Policy: execPolicy})
	if err != nil {
		t.Fatal(err)
	}
	eventsPolicy, err := sessionevents.ParsePolicy([]byte(`{"version":"weaverssh.events-policy.v1","default":"deny","rules":[{"id":"self","action":"allow","sources":["node-a"],"operations":["publish","subscribe"],"topics":["weaverssh/#"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	eventsEngine, err := sessionevents.NewEngine(sessionevents.EngineConfig{Topology: local.Context.Nodes, ChainSHA256: chain, CurrentNode: "node-a", Policy: eventsPolicy})
	if err != nil {
		t.Fatal(err)
	}
	ensureLocalService(local, sessionmux.ServiceExec)
	ensureLocalService(local, sessionmux.ServiceEvents)
	localExecEngines.Store(local, execEngine)
	localEventEngines.Store(local, eventsEngine)
	defer uninstallExtendedServices(local)
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: local.Context, Local: local})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(snapshot.Features, " ")
	for _, feature := range []string{"exec.command.v1", "exec.policy.v1", "events.routed.v1", "events.policy.v1"} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
