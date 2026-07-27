package sessionproxy

import (
	"context"
	"testing"

	"weaverssh/socksproof"
)

func TestProofProviderRefreshesPerClient(t *testing.T) {
	calls := 0
	server := &Server{ProofProvider: func(context.Context) (*socksproof.ServerConfig, error) {
		calls++
		return &socksproof.ServerConfig{SessionBinding: string(rune('a' + calls - 1))}, nil
	}}
	first, err := server.proofConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.proofConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || first.SessionBinding == second.SessionBinding {
		t.Fatalf("calls=%d first=%q second=%q", calls, first.SessionBinding, second.SessionBinding)
	}
}

func TestStaticProofCompatibilityFallback(t *testing.T) {
	static := &socksproof.ServerConfig{SessionBinding: "static"}
	server := &Server{Proof: static}
	resolved, err := server.proofConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != static {
		t.Fatal("static proof configuration was not preserved")
	}
}
