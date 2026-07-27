package app

import (
	"context"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
	"weaverssh/sessiontcpproof"
)

func TestSessionAPISnapshotReportsTCPProofRequirement(t *testing.T) {
	local := &LocalServices{
		Context: authproof.NodeContext{
			Nodes:        []string{"workstation-42"},
			CurrentNode:  "workstation-42",
			OriginNode:   "workstation-42",
			EndpointNode: "workstation-42",
		},
		services:        []sessionmux.ServiceID{sessionmux.ServiceTCP},
		tcpProof:        &sessiontcpproof.Server{},
		tcpRequireProof: true,
	}
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
		"tcp.client-proof.v1",
		"tcp.client-proof.required.v1",
		"socks5.auth.private-0x80.v1",
	} {
		if !strings.Contains(joined, feature) {
			t.Fatalf("features=%v missing %s", snapshot.Features, feature)
		}
	}
}
