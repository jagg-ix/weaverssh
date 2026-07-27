package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestAuthproofIssueVerifyAndHashes(t *testing.T) {
	dir := t.TempDir()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(dir, "issuer.key")
	publicPath := filepath.Join(dir, "issuer.pub")
	proofPath := filepath.Join(dir, "proof.json")
	if err := os.WriteFile(privatePath, []byte(authproof.EncodePrivateKey(private)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(authproof.EncodePublicKey(public)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	issue := []string{
		"--issuer", "origin",
		"--subject", "node-a",
		"--audience", authproof.AudienceAgent,
		"--x11-cookie", "00112233445566778899aabbccddeeff",
		"--nodes", "origin,node-a",
		"--capability", authproof.CapabilityWebSocketUpgrade,
		"--capability", authproof.CapabilityX11Relay,
		"--private-key-file", privatePath,
		"--ttl", "1m",
		"--out", proofPath,
	}
	if code := cmdAuthproof([]string{"issue"}); code == 0 {
		t.Fatal("issue without required flags unexpectedly succeeded")
	}
	if code := cmdAuthproof(append([]string{"issue"}, issue...)); code != 0 {
		t.Fatalf("authproof issue code=%d", code)
	}
	info, err := os.Stat(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("proof mode=%o want user-private", info.Mode().Perm())
	}
	verify := []string{
		"verify", "--file", proofPath,
		"--public-key-file", publicPath,
		"--audience", authproof.AudienceAgent,
		"--subject", "node-a",
		"--x11-cookie", "00112233445566778899aabbccddeeff",
		"--nodes", "origin,node-a",
		"--require-capability", authproof.CapabilityX11Relay,
	}
	if code := cmdAuthproof(verify); code != 0 {
		t.Fatalf("authproof verify code=%d", code)
	}
	if code := cmdAuthproof(append(verify, "--subject", "wrong")); code != 1 {
		t.Fatalf("wrong subject verify code=%d want 1", code)
	}

	_, cookieOutput := captureStdout(t, func() int {
		return cmdAuthproof([]string{"hash-cookie", "cookie-value"})
	})
	if cookieOutput != authproof.HashX11Cookie("cookie-value")+"\n" {
		t.Fatalf("cookie hash output=%q", cookieOutput)
	}
	_, chainOutput := captureStdout(t, func() int {
		return cmdAuthproof([]string{"hash-chain", "--nodes", "origin,node-a"})
	})
	if chainOutput != authproof.ChainBindingSHA256("origin", "node-a")+"\n" {
		t.Fatalf("chain hash output=%q", chainOutput)
	}
}

func TestReconnectIdentityIssueVerifyAndPrivateKeyMatch(t *testing.T) {
	dir := t.TempDir()
	authorityPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	authorityPublic := authorityPrivate.Public().(ed25519.PublicKey)
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	wrongPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	now := time.Now().Add(-time.Second)
	context := authproof.NodeContext{
		IssuerPeerID:  "authority",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "demo-chain",
		ChainSHA256:   authproof.ChainBindingSHA256("origin", "node-a"),
		Nodes:         []string{"origin", "node-a"},
		CurrentNode:   "node-a",
		OriginNode:    "origin",
		EndpointNode:  "node-a",
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "reconnect-context-nonce",
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(10 * time.Minute).Unix(),
	}
	signedContext, err := authproof.SignNodeContext(context, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(dir, "node-context.json")
	authorityPrivatePath := filepath.Join(dir, "authority.key")
	authorityPublicPath := filepath.Join(dir, "authority.pub")
	nodePrivatePath := filepath.Join(dir, "node.key")
	wrongPrivatePath := filepath.Join(dir, "wrong.key")
	identityPath := filepath.Join(dir, "node-reconnect.json")
	if err := writeJSONArtifact(contextPath, signedContext, 0o600, false); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		authorityPrivatePath: authproof.EncodePrivateKey(authorityPrivate),
		authorityPublicPath:  authproof.EncodePublicKey(authorityPublic),
		nodePrivatePath:      authproof.EncodePrivateKey(nodePrivate),
		wrongPrivatePath:     authproof.EncodePrivateKey(wrongPrivate),
	} {
		if err := os.WriteFile(path, []byte(data+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code := cmdReconnectIdentity([]string{
		"issue",
		"--node-context", contextPath,
		"--authority-private-key-file", authorityPrivatePath,
		"--node-private-key-file", nodePrivatePath,
		"--node", "node-a",
		"--out", identityPath,
	}); code != 0 {
		t.Fatalf("reconnect issue code=%d", code)
	}
	if code := cmdReconnectIdentity([]string{
		"verify",
		"--file", identityPath,
		"--authority-public-key-file", authorityPublicPath,
		"--node", "node-a",
		"--chain-id", "demo-chain",
		"--node-private-key-file", nodePrivatePath,
	}); code != 0 {
		t.Fatalf("reconnect verify code=%d", code)
	}
	if code := cmdReconnectIdentity([]string{
		"verify",
		"--file", identityPath,
		"--authority-public-key-file", authorityPublicPath,
		"--node-private-key-file", wrongPrivatePath,
	}); code != 1 {
		t.Fatalf("wrong node key verify code=%d want 1", code)
	}
	if code := cmdReconnectIdentity([]string{"digest", identityPath}); code != 0 {
		t.Fatalf("reconnect digest code=%d", code)
	}
}
