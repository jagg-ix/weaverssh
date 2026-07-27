// Package hopproof authenticates recursive weaverssh SSH hops. Each hop is
// signed with OpenSSH SSHSIG and linked to the preceding record by SHA-256.
package hopproof

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"weaverssh/authproof"
)

const (
	ChainVersion    = "weaverssh.hop-chain.v1"
	HopVersion      = "weaverssh.hop.v1"
	SignatureDomain = "weaverssh-hop@weaverssh"
	MaxHops         = 16
	MaxEncodedBytes = 48 << 10
)

var (
	ErrInvalidChain   = errors.New("hopproof: invalid hop chain")
	ErrWrongHop       = errors.New("hopproof: hop does not match signed topology")
	ErrExpiredHop     = errors.New("hopproof: hop proof expired")
	ErrReplay         = errors.New("hopproof: replayed hop nonce")
	ErrSignature      = errors.New("hopproof: invalid SSH signature")
	ErrNoNextNode     = errors.New("hopproof: current node has no next topology node")
	ErrNoPreviousNode = errors.New("hopproof: current node has no previous topology node")
)

// Hop is one signed transition from one concrete topology node to the next.
type Hop struct {
	Version              string `json:"version"`
	ChainID               string `json:"chain_id"`
	ChainSHA256           string `json:"chain_sha256"`
	RootNode              string `json:"root_node"`
	FromNode              string `json:"from_node"`
	ToNode                string `json:"to_node"`
	HopIndex              int    `json:"hop_index"`
	ParentHopSHA256       string `json:"parent_hop_sha256,omitempty"`
	ParentSessionBinding  string `json:"parent_session_binding,omitempty"`
	Nonce                 string `json:"nonce"`
	IssuedAtUnix          int64  `json:"issued_at_unix"`
	ExpiresAtUnix         int64  `json:"expires_at_unix"`
}

// SignedHop is one SSHSIG-authenticated hop. Principal must equal Hop.FromNode
// and is looked up in the verifier's allowed-signers policy.
type SignedHop struct {
	Principal string `json:"principal"`
	Hop       Hop    `json:"hop"`
	Signature string `json:"signature"`
}

// Chain is the complete, bounded, recursively verifiable path to the current
// node. Every recipient verifies all signatures, not only the last record.
type Chain struct {
	Version string      `json:"version"`
	Hops    []SignedHop `json:"hops"`
}

// Signer signs canonical hop bytes in the dedicated SSHSIG namespace.
type Signer interface {
	Sign(context.Context, string, []byte) ([]byte, error)
}

// Verifier verifies canonical hop bytes for the supplied node principal.
type Verifier interface {
	Verify(context.Context, string, []byte, []byte) error
}

// VerifyOptions controls time and replay validation.
type VerifyOptions struct {
	Now         time.Time
	MaxTTL      time.Duration
	ClockSkew   time.Duration
	ReplayCache *authproof.NonceCache
}

// CurrentIndex returns the current node's position in its validated topology.
func CurrentIndex(ctx authproof.NodeContext) (int, error) {
	ctx = ctx.Normalized()
	if err := ctx.Validate(); err != nil {
		return -1, err
	}
	for index, node := range ctx.Nodes {
		if node == ctx.CurrentNode {
			return index, nil
		}
	}
	return -1, fmt.Errorf("%w: current node %q missing", ErrInvalidChain, ctx.CurrentNode)
}

// PreviousNode returns the immediate predecessor expected in WVORIGIN.
func PreviousNode(ctx authproof.NodeContext) (string, error) {
	index, err := CurrentIndex(ctx)
	if err != nil {
		return "", err
	}
	if index <= 0 {
		return "", ErrNoPreviousNode
	}
	return ctx.Normalized().Nodes[index-1], nil
}

// NextNode returns the immediate node to receive a newly appended proof.
func NextNode(ctx authproof.NodeContext) (string, error) {
	index, err := CurrentIndex(ctx)
	if err != nil {
		return "", err
	}
	normalized := ctx.Normalized()
	if index+1 >= len(normalized.Nodes) {
		return "", ErrNoNextNode
	}
	return normalized.Nodes[index+1], nil
}

// Append signs and appends the next topology hop. parent must already have been
// verified for ctx.CurrentNode. parentBinding is mandatory after the first hop.
func Append(
	ctx context.Context,
	nodeContext authproof.NodeContext,
	parent Chain,
	parentBinding string,
	ttl time.Duration,
	now time.Time,
	signer Signer,
) (Chain, error) {
	if signer == nil {
		return Chain{}, errors.New("hopproof: nil signer")
	}
	nodeContext = nodeContext.Normalized()
	index, err := CurrentIndex(nodeContext)
	if err != nil {
		return Chain{}, err
	}
	if index+1 >= len(nodeContext.Nodes) {
		return Chain{}, ErrNoNextNode
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if now.IsZero() {
		now = time.Now()
	}
	if len(parent.Hops) != index {
		return Chain{}, fmt.Errorf("%w: parent has %d hops, current index is %d", ErrInvalidChain, len(parent.Hops), index)
	}
	if index > 0 && strings.TrimSpace(parentBinding) == "" {
		return Chain{}, fmt.Errorf("%w: recursive hop requires parent session binding", ErrInvalidChain)
	}
	if index == 0 {
		parent = Chain{Version: ChainVersion}
		parentBinding = ""
	}

	parentDigest := ""
	if len(parent.Hops) > 0 {
		parentDigest, err = SignedHopDigest(parent.Hops[len(parent.Hops)-1])
		if err != nil {
			return Chain{}, err
		}
	}
	nonce, err := randomNonce()
	if err != nil {
		return Chain{}, err
	}
	hop := Hop{
		Version:             HopVersion,
		ChainID:              nodeContext.ChainID,
		ChainSHA256:          nodeContext.ChainSHA256,
		RootNode:             nodeContext.Nodes[0],
		FromNode:             nodeContext.CurrentNode,
		ToNode:               nodeContext.Nodes[index+1],
		HopIndex:             index + 1,
		ParentHopSHA256:      parentDigest,
		ParentSessionBinding: strings.TrimSpace(parentBinding),
		Nonce:                nonce,
		IssuedAtUnix:         now.Unix(),
		ExpiresAtUnix:        now.Add(ttl).Unix(),
	}
	message, err := CanonicalHopBytes(hop)
	if err != nil {
		return Chain{}, err
	}
	signature, err := signer.Sign(ctx, hop.FromNode, message)
	if err != nil {
		return Chain{}, err
	}
	if len(signature) == 0 {
		return Chain{}, fmt.Errorf("%w: empty signature", ErrSignature)
	}
	signed := SignedHop{
		Principal: hop.FromNode,
		Hop:       hop,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	out := Chain{Version: ChainVersion, Hops: append([]SignedHop(nil), parent.Hops...)}
	out.Hops = append(out.Hops, signed)
	if len(out.Hops) > MaxHops {
		return Chain{}, fmt.Errorf("%w: hop count exceeds %d", ErrInvalidChain, MaxHops)
	}
	return out, nil
}

// Verify validates the complete path ending at nodeContext.CurrentNode.
func Verify(
	ctx context.Context,
	nodeContext authproof.NodeContext,
	chain Chain,
	verifier Verifier,
	options VerifyOptions,
) error {
	if verifier == nil {
		return errors.New("hopproof: nil verifier")
	}
	nodeContext = nodeContext.Normalized()
	index, err := CurrentIndex(nodeContext)
	if err != nil {
		return err
	}
	if index <= 0 {
		return ErrNoPreviousNode
	}
	if chain.Version != ChainVersion || len(chain.Hops) != index || len(chain.Hops) > MaxHops {
		return fmt.Errorf("%w: hop count=%d expected=%d", ErrInvalidChain, len(chain.Hops), index)
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxTTL := options.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 10 * time.Minute
	}
	skew := options.ClockSkew
	if skew < 0 {
		skew = 0
	}
	previousDigest := ""
	for hopIndex, signed := range chain.Hops {
		hop := normalizeHop(signed.Hop)
		expectedFrom := nodeContext.Nodes[hopIndex]
		expectedTo := nodeContext.Nodes[hopIndex+1]
		if signed.Principal != expectedFrom || hop.FromNode != expectedFrom || hop.ToNode != expectedTo ||
			hop.HopIndex != hopIndex+1 || hop.RootNode != nodeContext.Nodes[0] ||
			hop.ChainID != nodeContext.ChainID || hop.ChainSHA256 != nodeContext.ChainSHA256 ||
			hop.ParentHopSHA256 != previousDigest {
			return fmt.Errorf("%w: record %d", ErrWrongHop, hopIndex)
		}
		if hopIndex == 0 && hop.ParentSessionBinding != "" {
			return fmt.Errorf("%w: first hop has parent binding", ErrWrongHop)
		}
		if hopIndex > 0 && hop.ParentSessionBinding == "" {
			return fmt.Errorf("%w: recursive hop %d lacks parent binding", ErrWrongHop, hopIndex)
		}
		if hop.IssuedAtUnix <= 0 || hop.ExpiresAtUnix <= hop.IssuedAtUnix ||
			time.Duration(hop.ExpiresAtUnix-hop.IssuedAtUnix)*time.Second > maxTTL {
			return fmt.Errorf("%w: invalid validity at record %d", ErrInvalidChain, hopIndex)
		}
		if now.Add(skew).Unix() < hop.IssuedAtUnix {
			return fmt.Errorf("%w: record %d not yet valid", ErrInvalidChain, hopIndex)
		}
		if now.Add(-skew).Unix() >= hop.ExpiresAtUnix {
			return fmt.Errorf("%w: record %d", ErrExpiredHop, hopIndex)
		}
		message, err := CanonicalHopBytes(hop)
		if err != nil {
			return err
		}
		signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
		if err != nil || len(signature) == 0 {
			return fmt.Errorf("%w: decode record %d", ErrSignature, hopIndex)
		}
		if err := verifier.Verify(ctx, signed.Principal, message, signature); err != nil {
			return fmt.Errorf("%w: record %d: %v", ErrSignature, hopIndex, err)
		}
		if options.ReplayCache != nil {
			if err := options.ReplayCache.CheckAndStore(hop.Nonce, hop.ExpiresAtUnix, now); err != nil {
				return fmt.Errorf("%w: record %d: %v", ErrReplay, hopIndex, err)
			}
		}
		previousDigest, err = SignedHopDigest(SignedHop{Principal: signed.Principal, Hop: hop, Signature: signed.Signature})
		if err != nil {
			return err
		}
	}
	if chain.Hops[len(chain.Hops)-1].Hop.ToNode != nodeContext.CurrentNode {
		return fmt.Errorf("%w: chain does not terminate at current node", ErrWrongHop)
	}
	return nil
}

// ImmediatePrevious returns the authenticated previous node from a verified chain.
func ImmediatePrevious(chain Chain) (string, error) {
	if len(chain.Hops) == 0 {
		return "", ErrInvalidChain
	}
	return chain.Hops[len(chain.Hops)-1].Hop.FromNode, nil
}

// Encode serializes a bounded chain for the WVHOP environment variable.
func Encode(chain Chain) (string, error) {
	if chain.Version != ChainVersion || len(chain.Hops) == 0 || len(chain.Hops) > MaxHops {
		return "", ErrInvalidChain
	}
	payload, err := json.Marshal(chain)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	if len(encoded) > MaxEncodedBytes {
		return "", fmt.Errorf("%w: encoded chain exceeds %d bytes", ErrInvalidChain, MaxEncodedBytes)
	}
	return encoded, nil
}

// Decode parses one bounded WVHOP environment value.
func Decode(encoded string) (Chain, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || len(encoded) > MaxEncodedBytes {
		return Chain{}, ErrInvalidChain
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Chain{}, fmt.Errorf("%w: base64: %v", ErrInvalidChain, err)
	}
	var chain Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return Chain{}, fmt.Errorf("%w: json: %v", ErrInvalidChain, err)
	}
	if chain.Version != ChainVersion || len(chain.Hops) == 0 || len(chain.Hops) > MaxHops {
		return Chain{}, ErrInvalidChain
	}
	return chain, nil
}

// CanonicalHopBytes returns the exact SSHSIG message for one hop.
func CanonicalHopBytes(hop Hop) ([]byte, error) {
	hop = normalizeHop(hop)
	if err := validateHop(hop); err != nil {
		return nil, err
	}
	return json.Marshal(hop)
}

// SignedHopDigest links a later hop to the exact preceding signed record.
func SignedHopDigest(hop SignedHop) (string, error) {
	hop.Principal = strings.TrimSpace(hop.Principal)
	hop.Hop = normalizeHop(hop.Hop)
	if hop.Principal == "" || hop.Signature == "" {
		return "", ErrInvalidChain
	}
	payload, err := json.Marshal(hop)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeHop(hop Hop) Hop {
	if hop.Version == "" {
		hop.Version = HopVersion
	}
	hop.ChainID = strings.TrimSpace(hop.ChainID)
	hop.ChainSHA256 = strings.ToLower(strings.TrimSpace(hop.ChainSHA256))
	hop.RootNode = strings.TrimSpace(hop.RootNode)
	hop.FromNode = strings.TrimSpace(hop.FromNode)
	hop.ToNode = strings.TrimSpace(hop.ToNode)
	hop.ParentHopSHA256 = strings.ToLower(strings.TrimSpace(hop.ParentHopSHA256))
	hop.ParentSessionBinding = strings.TrimSpace(hop.ParentSessionBinding)
	hop.Nonce = strings.TrimSpace(hop.Nonce)
	return hop
}

func validateHop(hop Hop) error {
	if hop.Version != HopVersion || hop.ChainID == "" || hop.RootNode == "" || hop.FromNode == "" || hop.ToNode == "" || hop.Nonce == "" || hop.HopIndex <= 0 {
		return ErrInvalidChain
	}
	if len(hop.ChainSHA256) != 64 {
		return ErrInvalidChain
	}
	if hop.ParentHopSHA256 != "" && len(hop.ParentHopSHA256) != 64 {
		return ErrInvalidChain
	}
	if hop.ExpiresAtUnix <= hop.IssuedAtUnix {
		return ErrInvalidChain
	}
	return nil
}

func randomNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
