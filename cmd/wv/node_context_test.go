package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/vfs"
)

func TestCmdNodeContextSignAndVerifyEnv(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, "node.ed25519")
	pubPath := filepath.Join(dir, "node.ed25519.pub")
	ctxPath := filepath.Join(dir, "node-context.json")
	if err := os.WriteFile(privPath, []byte(authproof.EncodePrivateKey(privateKey)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(authproof.EncodePublicKey(publicKey)), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	rc, out := captureStdout(t, func() int {
		return cmdNodeContext([]string{"sign", "--nodes", "origin,node1,node2", "--node", "node1", "--issuer", "test-origin", "--private-key-file", privPath, "--out", ctxPath})
	})
	if rc != 0 {
		t.Fatalf("node-context sign rc=%d out=%s", rc, out)
	}
	if _, err := os.Stat(ctxPath); err != nil {
		t.Fatalf("context not written: %v", err)
	}
	rc, out = captureStdout(t, func() int {
		return cmdNodeContext([]string{"env", "--file", ctxPath, "--public-key-file", pubPath, "--node", "node1"})
	})
	if rc != 0 {
		t.Fatalf("node-context env rc=%d out=%s", rc, out)
	}
	for _, want := range []string{
		"export WEAVERSSH_CHAIN_ID='adhoc'",
		"export WEAVERSSH_CHAIN_NODES='origin,node1,node2'",
		"export WEAVERSSH_ORIGIN_NODE='origin'",
		"export WEAVERSSH_ENDPOINT_NODE='node2'",
		"export WEAVERSSH_NODE_ID='node1'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("env output missing %q\n%s", want, out)
		}
	}
}

func TestCmdNodeContextStatusIdentifiesOriginFromSignedContextOnNode2(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	nodes := []string{"laptop", "bastion", "node1", "node2"}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "laptop-peer",
		ChainID:       "prod-chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "node2",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "node2-origin-status-nonce",
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
	ctxPath := filepath.Join(dir, "node2.context.json")
	pubPath := filepath.Join(dir, "origin.pub")
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

	rc, out := captureStdout(t, func() int {
		return cmdNodeContext([]string{"status"})
	})
	if rc != 0 {
		t.Fatalf("node-context status rc=%d out=%s", rc, out)
	}
	for _, want := range []string{
		"source:   signed-node-context",
		"trusted:  yes",
		"chain:    prod-chain",
		"nodes:    laptop -> bastion -> node1 -> node2",
		"origin:   laptop",
		"current:  node2",
		"endpoint: node2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q\n%s", want, out)
		}
	}
}

func TestCmdNodeContextStatusIdentifiesOriginFromActiveChainOnNode2(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	t.Setenv(vfs.EnvOriginNode, "")
	t.Setenv(vfs.EnvEndpointNode, "")
	t.Setenv(vfs.EnvChainNodes, "")
	t.Setenv(vfs.EnvCurrentNode, "")
	t.Setenv(vfs.EnvCurrentNodeShort, "node2")
	store := ConnStore{
		ActiveChain: "prod",
		Chains: []ConnChain{{
			Number: 1,
			Label:  "prod",
			Nodes:  []string{"laptop", "bastion", "node1", "node2"},
		}},
	}
	if err := saveConnStore(store); err != nil {
		t.Fatalf("saveConnStore: %v", err)
	}
	rc, out := captureStdout(t, func() int {
		return cmdNodeContext([]string{"status"})
	})
	if rc != 0 {
		t.Fatalf("node-context status rc=%d out=%s", rc, out)
	}
	for _, want := range []string{
		"source:   active-chain",
		"trusted:  no",
		"chain:    prod",
		"nodes:    laptop -> bastion -> node1 -> node2",
		"origin:   laptop",
		"current:  node2",
		"endpoint: node2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q\n%s", want, out)
		}
	}
}
