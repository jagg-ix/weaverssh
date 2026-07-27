package authproof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ReconnectIdentityVersion  = "weaverssh.reconnect-identity.v1"
	AudienceReconnectIdentity = "wv-reconnect-identity"
)

var ErrInvalidReconnectIdentity = errors.New("invalid reconnect identity")

type ReconnectIdentity struct {
	Version       string      `json:"version"`
	Algorithm     string      `json:"algorithm"`
	Audience      string      `json:"audience"`
	Context       NodeContext `json:"context"`
	NodePublicKey string      `json:"node_public_key"`
	NodeKeySHA256 string      `json:"node_key_sha256"`
}

type SignedReconnectIdentity struct {
	Identity  ReconnectIdentity `json:"identity"`
	Signature string            `json:"signature"`
}

type ReconnectIdentityVerifyOptions struct {
	Now         time.Time
	Audience    string
	ChainID     string
	ChainSHA256 string
	CurrentNode string
	MaxTTL      time.Duration
}

func NewReconnectIdentity(context NodeContext, nodePublicKey ed25519.PublicKey) (ReconnectIdentity, error) {
	if len(nodePublicKey) != ed25519.PublicKeySize {
		return ReconnectIdentity{}, ErrInvalidReconnectIdentity
	}
	identity := ReconnectIdentity{
		Context:       context,
		NodePublicKey: base64.RawURLEncoding.EncodeToString(nodePublicKey),
		NodeKeySHA256: publicKeySHA256(nodePublicKey),
	}
	identity = identity.Normalized()
	if err := identity.Validate(); err != nil {
		return ReconnectIdentity{}, err
	}
	return identity, nil
}

func (i ReconnectIdentity) Normalized() ReconnectIdentity {
	out := i
	if out.Version == "" {
		out.Version = ReconnectIdentityVersion
	}
	if out.Algorithm == "" {
		out.Algorithm = Algorithm
	}
	if out.Audience == "" {
		out.Audience = AudienceReconnectIdentity
	}
	out.Version = strings.TrimSpace(out.Version)
	out.Algorithm = strings.TrimSpace(out.Algorithm)
	out.Audience = strings.TrimSpace(out.Audience)
	out.Context = out.Context.Normalized()
	out.NodePublicKey = strings.TrimSpace(out.NodePublicKey)
	out.NodeKeySHA256 = strings.ToLower(strings.TrimSpace(out.NodeKeySHA256))
	if key, err := decodeReconnectPublicKey(out.NodePublicKey); err == nil {
		out.NodePublicKey = base64.RawURLEncoding.EncodeToString(key)
		if out.NodeKeySHA256 == "" {
			out.NodeKeySHA256 = publicKeySHA256(key)
		}
	}
	return out
}

func (i ReconnectIdentity) Validate() error {
	i = i.Normalized()
	if i.Version != ReconnectIdentityVersion || i.Algorithm != Algorithm || i.Audience != AudienceReconnectIdentity {
		return ErrInvalidReconnectIdentity
	}
	if err := i.Context.Validate(); err != nil {
		return fmt.Errorf("%w: node context: %v", ErrInvalidReconnectIdentity, err)
	}
	if i.Context.Audience != AudienceNodeContext {
		return fmt.Errorf("%w: wrong embedded context audience", ErrInvalidReconnectIdentity)
	}
	key, err := decodeReconnectPublicKey(i.NodePublicKey)
	if err != nil {
		return err
	}
	if i.NodeKeySHA256 != publicKeySHA256(key) {
		return fmt.Errorf("%w: node public key digest mismatch", ErrInvalidReconnectIdentity)
	}
	return nil
}

func (i ReconnectIdentity) PublicKey() (ed25519.PublicKey, error) {
	i = i.Normalized()
	if err := i.Validate(); err != nil {
		return nil, err
	}
	return decodeReconnectPublicKey(i.NodePublicKey)
}

func SignReconnectIdentity(identity ReconnectIdentity, authorityPrivateKey ed25519.PrivateKey) (SignedReconnectIdentity, error) {
	if len(authorityPrivateKey) != ed25519.PrivateKeySize {
		return SignedReconnectIdentity{}, ErrInvalidReconnectIdentity
	}
	canonical, normalized, err := canonicalReconnectIdentity(identity)
	if err != nil {
		return SignedReconnectIdentity{}, err
	}
	signature := ed25519.Sign(authorityPrivateKey, canonical)
	return SignedReconnectIdentity{
		Identity:  normalized,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func VerifySignedReconnectIdentity(
	signed SignedReconnectIdentity,
	authorityPublicKey ed25519.PublicKey,
	options ReconnectIdentityVerifyOptions,
) (ReconnectIdentity, error) {
	if len(authorityPublicKey) != ed25519.PublicKeySize {
		return ReconnectIdentity{}, ErrInvalidSignature
	}
	canonical, identity, err := canonicalReconnectIdentity(signed.Identity)
	if err != nil {
		return ReconnectIdentity{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signed.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(authorityPublicKey, canonical, signature) {
		return ReconnectIdentity{}, ErrInvalidSignature
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	context := identity.Context
	switch {
	case now.Unix() < context.IssuedAtUnix:
		return ReconnectIdentity{}, ErrNotYetValid
	case now.Unix() >= context.ExpiresAtUnix:
		return ReconnectIdentity{}, ErrExpiredGrant
	case options.MaxTTL > 0 && time.Duration(context.ExpiresAtUnix-context.IssuedAtUnix)*time.Second > options.MaxTTL:
		return ReconnectIdentity{}, ErrGrantTTLTooLong
	case strings.TrimSpace(options.Audience) != "" && identity.Audience != strings.TrimSpace(options.Audience):
		return ReconnectIdentity{}, ErrWrongAudience
	case strings.TrimSpace(options.ChainID) != "" && context.ChainID != strings.TrimSpace(options.ChainID):
		return ReconnectIdentity{}, ErrWrongChainHash
	case strings.TrimSpace(options.ChainSHA256) != "" && context.ChainSHA256 != strings.ToLower(strings.TrimSpace(options.ChainSHA256)):
		return ReconnectIdentity{}, ErrWrongChainHash
	case strings.TrimSpace(options.CurrentNode) != "" && context.CurrentNode != strings.TrimSpace(options.CurrentNode):
		return ReconnectIdentity{}, ErrWrongSubject
	}
	return identity, nil
}

func ReconnectIdentitySHA256(signed SignedReconnectIdentity) (string, error) {
	_, identity, err := canonicalReconnectIdentity(signed.Identity)
	if err != nil {
		return "", err
	}
	signature := strings.TrimSpace(signed.Signature)
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return "", ErrInvalidSignature
	}
	envelope, err := json.Marshal(struct {
		Identity  ReconnectIdentity `json:"identity"`
		Signature string            `json:"signature"`
	}{Identity: identity, Signature: signature})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalReconnectIdentity(identity ReconnectIdentity) ([]byte, ReconnectIdentity, error) {
	normalized := identity.Normalized()
	if err := normalized.Validate(); err != nil {
		return nil, ReconnectIdentity{}, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, ReconnectIdentity{}, err
	}
	return canonical, normalized, nil
}

func decodeReconnectPublicKey(raw string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: node public key must be %d-byte base64url Ed25519 key", ErrInvalidReconnectIdentity, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

func publicKeySHA256(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}
