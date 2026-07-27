package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/vfs"
)

func TestHydrateVFSNodeRefEnvFromActiveChain(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	t.Setenv(vfs.EnvOriginNode, "")
	t.Setenv(vfs.EnvEndpointNode, "")
	t.Setenv(vfs.EnvChainNodes, "")
	store := ConnStore{
		ActiveChain: "prod",
		Chains: []ConnChain{{
			Number: 1,
			Label:  "prod",
			Nodes:  []string{"node/workstation", "node/linode-a", "profile/linode-b"},
		}},
	}
	if err := saveConnStore(store); err != nil {
		t.Fatalf("saveConnStore: %v", err)
	}
	if err := hydrateVFSNodeRefEnv(); err != nil {
		t.Fatalf("hydrateVFSNodeRefEnv: %v", err)
	}
	if got := os.Getenv(vfs.EnvOriginNode); got != "workstation" {
		t.Fatalf("origin env=%q", got)
	}
	if got := os.Getenv(vfs.EnvEndpointNode); got != "linode-b" {
		t.Fatalf("endpoint env=%q", got)
	}
	if got := os.Getenv(vfs.EnvChainNodes); got != "workstation,linode-a,linode-b" {
		t.Fatalf("chain env=%q", got)
	}
}

func TestHydrateVFSNodeRefEnvPrefersSignedContext(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	nodes := []string{"origin", "node1", "node2"}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "origin-peer",
		ChainID:       "signed-chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "node1",
		Nonce:         "signed-context-nonce",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatalf("SignNodeContext: %v", err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	dir := t.TempDir()
	ctxPath := filepath.Join(dir, "node-context.json")
	pubPath := filepath.Join(dir, "node-context.pub")
	if err := os.WriteFile(ctxPath, data, 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(authproof.EncodePublicKey(publicKey)), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	t.Setenv(envNodeContextFile, ctxPath)
	t.Setenv(envNodeContextPublicKeyFile, pubPath)
	t.Setenv(vfs.EnvOriginNode, "untrusted-origin")
	t.Setenv(vfs.EnvEndpointNode, "untrusted-endpoint")
	t.Setenv(vfs.EnvCurrentNode, "untrusted-current")
	if err := hydrateVFSNodeRefEnv(); err != nil {
		t.Fatalf("hydrate signed context: %v", err)
	}
	if got := os.Getenv(vfs.EnvOriginNode); got != "origin" {
		t.Fatalf("origin env=%q", got)
	}
	if got := os.Getenv(vfs.EnvEndpointNode); got != "node2" {
		t.Fatalf("endpoint env=%q", got)
	}
	if got := os.Getenv(vfs.EnvCurrentNode); got != "node1" {
		t.Fatalf("current env=%q", got)
	}
	if got := os.Getenv(envChainID); got != "signed-chain" {
		t.Fatalf("chain id env=%q", got)
	}
}
