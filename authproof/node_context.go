package authproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	NodeContextVersion  = "weaverssh.node-context.v1"
	AudienceNodeContext = "wv-node-context"
)

// NodeContext is a signed, short-lived description of the local node's position
// in a weaverssh chain. It is intentionally small: callers use it to resolve
// relative names such as origin/self/endpoint without trusting unauthenticated
// environment variables supplied by a remote shell.
type NodeContext struct {
	Version       string   `json:"version"`
	Algorithm     string   `json:"algorithm"`
	IssuerPeerID  string   `json:"issuer_peer_id"`
	Audience      string   `json:"audience"`
	ChainID       string   `json:"chain_id"`
	ChainSHA256   string   `json:"chain_sha256"`
	Nodes         []string `json:"nodes"`
	CurrentNode   string   `json:"current_node"`
	OriginNode    string   `json:"origin_node"`
	EndpointNode  string   `json:"endpoint_node"`
	Capabilities  []string `json:"capabilities"`
	Nonce         string   `json:"nonce"`
	IssuedAtUnix  int64    `json:"issued_at_unix"`
	ExpiresAtUnix int64    `json:"expires_at_unix"`
}

// SignedNodeContext is the JSON object passed through files/env/IPC and verified
// before node-relative decisions are made.
type SignedNodeContext struct {
	Context   NodeContext `json:"context"`
	Signature string      `json:"signature"`
}

// NodeContextVerifyOptions constrains context verification to the expected
// chain and, when known, the expected local node.
type NodeContextVerifyOptions struct {
	Now         time.Time
	Audience    string
	ChainID     string
	ChainSHA256 string
	CurrentNode string
	MaxTTL      time.Duration
	ReplayCache *NonceCache
}

func (c NodeContext) Normalized() NodeContext {
	out := c
	if out.Version == "" {
		out.Version = NodeContextVersion
	}
	if out.Algorithm == "" {
		out.Algorithm = Algorithm
	}
	if out.Audience == "" {
		out.Audience = AudienceNodeContext
	}
	out.IssuerPeerID = strings.TrimSpace(out.IssuerPeerID)
	out.Audience = strings.TrimSpace(out.Audience)
	out.ChainID = strings.TrimSpace(out.ChainID)
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.Nodes = normalizeNodeContextNodes(out.Nodes)
	out.CurrentNode = strings.TrimSpace(out.CurrentNode)
	out.OriginNode = strings.TrimSpace(out.OriginNode)
	out.EndpointNode = strings.TrimSpace(out.EndpointNode)
	if out.OriginNode == "" && len(out.Nodes) > 0 {
		out.OriginNode = out.Nodes[0]
	}
	if out.EndpointNode == "" && len(out.Nodes) > 0 {
		out.EndpointNode = out.Nodes[len(out.Nodes)-1]
	}
	out.Capabilities = normalizeCapabilities(out.Capabilities)
	if len(out.Capabilities) == 0 {
		out.Capabilities = []string{CapabilityNodeContext}
	}
	out.Nonce = strings.TrimSpace(out.Nonce)
	return out
}

func (c NodeContext) Validate() error {
	c = c.Normalized()
	if c.Version != NodeContextVersion {
		return fmt.Errorf("%w: unsupported node context version %q", ErrInvalidGrant, c.Version)
	}
	if c.Algorithm != Algorithm {
		return fmt.Errorf("%w: unsupported node context algorithm %q", ErrInvalidGrant, c.Algorithm)
	}
	for name, value := range map[string]string{
		"issuer_peer_id": c.IssuerPeerID,
		"audience":       c.Audience,
		"chain_id":       c.ChainID,
		"chain_sha256":   c.ChainSHA256,
		"current_node":   c.CurrentNode,
		"origin_node":    c.OriginNode,
		"endpoint_node":  c.EndpointNode,
		"nonce":          c.Nonce,
	} {
		if value == "" {
			return fmt.Errorf("%w: missing %s", ErrInvalidGrant, name)
		}
	}
	if !isLowerHexSHA256(c.ChainSHA256) {
		return fmt.Errorf("%w: node context chain_sha256 must be 64 lowercase hex chars", ErrInvalidGrant)
	}
	if len(c.Nodes) == 0 {
		return fmt.Errorf("%w: node context requires at least one node", ErrInvalidGrant)
	}
	for _, node := range []string{c.CurrentNode, c.OriginNode, c.EndpointNode} {
		if !nodeInContext(c.Nodes, node) {
			return fmt.Errorf("%w: node %q is not in node context chain", ErrInvalidGrant, node)
		}
	}
	if c.OriginNode != c.Nodes[0] {
		return fmt.Errorf("%w: origin_node must equal first chain node", ErrInvalidGrant)
	}
	if c.EndpointNode != c.Nodes[len(c.Nodes)-1] {
		return fmt.Errorf("%w: endpoint_node must equal last chain node", ErrInvalidGrant)
	}
	if !hasCapability(c.Capabilities, CapabilityNodeContext) {
		return fmt.Errorf("%w: node context requires %s capability", ErrMissingCapability, CapabilityNodeContext)
	}
	for _, cap := range c.Capabilities {
		if !knownCapability(cap) {
			return fmt.Errorf("%w: unknown capability %q", ErrInvalidGrant, cap)
		}
	}
	if c.IssuedAtUnix <= 0 || c.ExpiresAtUnix <= 0 || c.ExpiresAtUnix <= c.IssuedAtUnix {
		return fmt.Errorf("%w: invalid node context validity window", ErrInvalidGrant)
	}
	return nil
}

func CanonicalNodeContextBytes(c NodeContext) ([]byte, error) {
	c = c.Normalized()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

func SignNodeContext(c NodeContext, privateKey ed25519.PrivateKey) (SignedNodeContext, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedNodeContext{}, fmt.Errorf("%w: Ed25519 private key must be %d bytes", ErrInvalidGrant, ed25519.PrivateKeySize)
	}
	canonical, err := CanonicalNodeContextBytes(c)
	if err != nil {
		return SignedNodeContext{}, err
	}
	sig := ed25519.Sign(privateKey, canonical)
	return SignedNodeContext{Context: c.Normalized(), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

func VerifySignedNodeContext(sc SignedNodeContext, publicKey ed25519.PublicKey, opts NodeContextVerifyOptions) (NodeContext, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return NodeContext{}, fmt.Errorf("%w: Ed25519 public key must be %d bytes", ErrInvalidGrant, ed25519.PublicKeySize)
	}
	ctx := sc.Context.Normalized()
	if err := ctx.Validate(); err != nil {
		return NodeContext{}, err
	}
	canonical, err := CanonicalNodeContextBytes(ctx)
	if err != nil {
		return NodeContext{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(sc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return NodeContext{}, ErrInvalidSignature
	}
	if !ed25519.Verify(publicKey, canonical, sig) {
		return NodeContext{}, ErrInvalidSignature
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowUnix := now.Unix()
	if nowUnix < ctx.IssuedAtUnix {
		return NodeContext{}, ErrNotYetValid
	}
	if nowUnix >= ctx.ExpiresAtUnix {
		return NodeContext{}, ErrExpiredGrant
	}
	if opts.MaxTTL > 0 && time.Duration(ctx.ExpiresAtUnix-ctx.IssuedAtUnix)*time.Second > opts.MaxTTL {
		return NodeContext{}, ErrGrantTTLTooLong
	}
	if opts.Audience != "" && ctx.Audience != opts.Audience {
		return NodeContext{}, ErrWrongAudience
	}
	if opts.ChainID != "" && ctx.ChainID != opts.ChainID {
		return NodeContext{}, fmt.Errorf("%w: wrong chain id", ErrWrongChainHash)
	}
	if opts.ChainSHA256 != "" && ctx.ChainSHA256 != strings.ToLower(strings.TrimSpace(opts.ChainSHA256)) {
		return NodeContext{}, ErrWrongChainHash
	}
	if opts.CurrentNode != "" && ctx.CurrentNode != strings.TrimSpace(opts.CurrentNode) {
		return NodeContext{}, ErrWrongSubject
	}
	if err := opts.ReplayCache.CheckAndStore(ctx.Nonce, ctx.ExpiresAtUnix, now); err != nil {
		return NodeContext{}, err
	}
	return ctx, nil
}

func normalizeNodeContextNodes(nodes []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		node = strings.TrimSpace(node)
		if node == "" || seen[node] {
			continue
		}
		seen[node] = true
		out = append(out, node)
	}
	return out
}

func nodeInContext(nodes []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, node := range nodes {
		if node == want {
			return true
		}
	}
	return false
}
