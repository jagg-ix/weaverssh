package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
	"weaverssh/sessiontcp"
	"weaverssh/sessiontcpproof"
	"weaverssh/socksproof"
)

func TestSessionAPISnapshotReportsMQTTGRPCFeatures(t *testing.T) {
	local := &LocalServices{
		Context: authproof.NodeContext{
			Nodes:        []string{"workstation-42"},
			CurrentNode:  "workstation-42",
			OriginNode:   "workstation-42",
			EndpointNode: "workstation-42",
		},
		services: []sessionmux.ServiceID{sessionmux.ServiceTCP},
		tcp:      &sessiontcp.Server{},
		tcpProof: &sessiontcpproof.Server{Verifier: &socksproof.Verifier{}},
	}
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: local.Context, Local: local})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(snapshot.Features, " ")
	for _, feature := range []string{
		"grpc.mqtt-framing.v1",
		"grpc.mqtt-stream-dialer.v1",
		"grpc.mqtt-loopback-proxy.v1",
		"grpc.mqtt-framing.proof.v1",
	} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
