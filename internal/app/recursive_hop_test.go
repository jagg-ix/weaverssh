package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/hopproof"
	"weaverssh/sessionbroker"
)

type appHopSigner struct {
	private map[string]ed25519.PrivateKey
}

func (s appHopSigner) Sign(_ context.Context, principal string, message []byte) ([]byte, error) {
	key := s.private[principal]
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("missing private key")
	}
	return ed25519.Sign(key, message), nil
}

type appHopVerifier struct {
	public map[string]ed25519.PublicKey
}

func (v appHopVerifier) Verify(_ context.Context, principal string, message, signature []byte) error {
	key := v.public[principal]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return hopproof.ErrSignature
	}
	return nil
}

func TestPrepareRecursiveHopUsesPreviousNodeAndParentBinding(t *testing.T) {
	nodes := []string{"workstation-42", "jump-a", "compute-node"}
	private := make(map[string]ed25519.PrivateKey)
	public := make(map[string]ed25519.PublicKey)
	for _, node := range nodes {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private[node] = priv
		public[node] = pub
	}
	signer := appHopSigner{private: private}
	verifier := appHopVerifier{public: public}
	now := time.Unix(2_000_000_000, 0)

	root, err := PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
		NodeContext: recursiveHopContext(nodes, "workstation-42"),
		TTL:         5 * time.Minute,
		Now:         now,
		Signer:      signer,
		Verifier:    verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if root.Origin != "workstation-42" || root.NextNode != "jump-a" || root.HopDepth != 1 {
		t.Fatalf("root environment=%+v", root)
	}

	statePath := filepath.Join(t.TempDir(), "session.json")
	if err := sessionbroker.WriteState(statePath, sessionbroker.State{
		PID:       1234,
		Socket:    filepath.Join(t.TempDir(), "session.sock"),
		Binding:   "parent-binding-workstation-jump",
		Node:      "jump-a",
		StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessionbroker.WriteHopState(statePath, sessionbroker.HopState{
		PreviousNode: "workstation-42",
		HopChain:     root.HopChain,
		Depth:        1,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(sessionbroker.EnvSocket, "")
	// Simulate a second local shell that did not inherit the SSH environment.
	t.Setenv(EnvWVOrigin, "")
	t.Setenv(EnvWVHop, "")

	second, err := PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
		NodeContext: recursiveHopContext(nodes, "jump-a"),
		TTL:         5 * time.Minute,
		Now:         now.Add(time.Second),
		Signer:      signer,
		Verifier:    verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Origin != "jump-a" || second.NextNode != "compute-node" || second.HopDepth != 2 {
		t.Fatalf("second environment=%+v", second)
	}
	chain, err := hopproof.Decode(second.HopChain)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Hops[1].Hop.ParentSessionBinding != "parent-binding-workstation-jump" {
		t.Fatalf("parent binding=%q", chain.Hops[1].Hop.ParentSessionBinding)
	}
	if chain.Hops[1].Hop.ParentHopSHA256 == "" {
		t.Fatal("second hop did not link the first signed record")
	}
	if err := hopproof.Verify(context.Background(), recursiveHopContext(nodes, "compute-node"), chain, verifier, hopproof.VerifyOptions{Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareRecursiveHopRejectsWrongParentOrigin(t *testing.T) {
	nodes := []string{"a", "b", "c"}
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	signer := appHopSigner{private: map[string]ed25519.PrivateKey{"a": privA, "b": privB}}
	verifier := appHopVerifier{public: map[string]ed25519.PublicKey{"a": pubA, "b": pubB}}
	now := time.Unix(2_000_000_000, 0)
	first, err := PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
		NodeContext: recursiveHopContext(nodes, "a"),
		Now:         now,
		Signer:      signer,
		Verifier:    verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "session.json")
	if err := sessionbroker.WriteState(statePath, sessionbroker.State{
		PID: 1, Socket: filepath.Join(t.TempDir(), "s.sock"), Binding: "binding", Node: "b", StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sessionbroker.EnvState, statePath)
	t.Setenv(EnvWVOrigin, "attacker")
	_, err = PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
		NodeContext:   recursiveHopContext(nodes, "b"),
		IncomingChain: first.HopChain,
		Now:           now.Add(time.Second),
		Signer:        signer,
		Verifier:      verifier,
	})
	if err == nil || !strings.Contains(err.Error(), "verified previous hop") {
		t.Fatalf("error=%v", err)
	}
}

func TestRecursiveRuntimePathsAreIsolated(t *testing.T) {
	socket, state := RecursiveRuntimePaths("/run/user/1000/weaverssh/session.sock", "/run/user/1000/weaverssh/session.json", "jump-a")
	if socket == "/run/user/1000/weaverssh/session.sock" || state == "/run/user/1000/weaverssh/session.json" {
		t.Fatalf("socket=%q state=%q", socket, state)
	}
	if !strings.Contains(socket, "session-host-") || !strings.Contains(state, "session-host-") {
		t.Fatalf("socket=%q state=%q", socket, state)
	}
}

func recursiveHopContext(nodes []string, current string) authproof.NodeContext {
	now := time.Now()
	return authproof.NodeContext{
		IssuerPeerID:  "recursive-hop-test",
		ChainID:       "recursive-chain",
		ChainSHA256:   strings.Repeat("b", 64),
		Nodes:         append([]string(nil), nodes...),
		CurrentNode:   current,
		OriginNode:    nodes[0],
		EndpointNode:  nodes[len(nodes)-1],
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "recursive-context-" + current,
		IssuedAtUnix:  now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
	}
}
