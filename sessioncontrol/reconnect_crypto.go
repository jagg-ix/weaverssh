package sessioncontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"weaverssh/authproof"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
)

func NewReconnectChallenge(
	localContext authproof.NodeContext,
	peerNode string,
	transportID sessionlink.TransportID,
	sessionBinding string,
	ttl time.Duration,
	now time.Time,
) (ReconnectChallenge, error) {
	localContext = localContext.Normalized()
	if err := localContext.Validate(); err != nil {
		return ReconnectChallenge{}, fmt.Errorf("%w: local context: %v", ErrReconnectChallenge, err)
	}
	peerNode = strings.TrimSpace(peerNode)
	if err := sessionlink.ValidateTransportID(transportID); err != nil || !validReconnectText(sessionBinding, 512) {
		return ReconnectChallenge{}, ErrReconnectChallenge
	}
	if ttl <= 0 || ttl > MaxReconnectChallengeTTL {
		return ReconnectChallenge{}, ErrReconnectChallenge
	}
	linkID, err := sessionlink.DeriveID(sessionlink.Descriptor{
		ChainSHA256: localContext.ChainSHA256,
		Topology:    localContext.Nodes,
		LocalNode:   localContext.CurrentNode,
		PeerNode:    peerNode,
	})
	if err != nil {
		return ReconnectChallenge{}, fmt.Errorf("%w: %v", ErrReconnectChallenge, err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	challengeID, err := randomReconnectNonce(24)
	if err != nil {
		return ReconnectChallenge{}, err
	}
	challenge := ReconnectChallenge{
		Version:        ReconnectChallengeVersion,
		Algorithm:      authproof.Algorithm,
		ChallengeID:    challengeID,
		LinkID:         linkID,
		TransportID:    transportID,
		SessionBinding: strings.TrimSpace(sessionBinding),
		ChainSHA256:    localContext.ChainSHA256,
		AcceptorNode:   localContext.CurrentNode,
		ProverNode:     peerNode,
		IssuedAtUnix:   now.Unix(),
		ExpiresAtUnix:  now.Add(ttl).Unix(),
	}
	if err := challenge.Validate(now); err != nil {
		return ReconnectChallenge{}, err
	}
	return challenge, nil
}

func (c ReconnectChallenge) Validate(now time.Time) error {
	c = c.Normalized()
	if c.Version != ReconnectChallengeVersion || c.Algorithm != authproof.Algorithm ||
		!validReconnectText(c.ChallengeID, 512) || sessionlink.ValidateID(c.LinkID) != nil ||
		sessionlink.ValidateTransportID(c.TransportID) != nil || !validReconnectText(c.SessionBinding, 512) ||
		!validSHA256(c.ChainSHA256) || !validReconnectText(c.AcceptorNode, 256) ||
		!validReconnectText(c.ProverNode, 256) || c.AcceptorNode == c.ProverNode ||
		c.IssuedAtUnix <= 0 || c.ExpiresAtUnix <= c.IssuedAtUnix ||
		time.Duration(c.ExpiresAtUnix-c.IssuedAtUnix)*time.Second > MaxReconnectChallengeTTL {
		return ErrReconnectChallenge
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() < c.IssuedAtUnix || now.Unix() >= c.ExpiresAtUnix {
		return ErrReconnectChallenge
	}
	return nil
}

func BuildReconnectProof(
	challenge ReconnectChallenge,
	identity authproof.SignedReconnectIdentity,
	nodePrivateKey ed25519.PrivateKey,
	services []sessionmux.ServiceID,
	now time.Time,
) (ReconnectProof, error) {
	challenge = challenge.Normalized()
	if err := challenge.Validate(now); err != nil {
		return ReconnectProof{}, err
	}
	if len(nodePrivateKey) != ed25519.PrivateKeySize {
		return ReconnectProof{}, ErrReconnectProof
	}
	normalizedIdentity := identity.Identity.Normalized()
	if err := normalizedIdentity.Validate(); err != nil {
		return ReconnectProof{}, err
	}
	if err := identityMatchesChallenge(normalizedIdentity, challenge); err != nil {
		return ReconnectProof{}, err
	}
	certifiedKey, err := normalizedIdentity.PublicKey()
	if err != nil || !certifiedKey.Equal(nodePrivateKey.Public()) {
		return ReconnectProof{}, fmt.Errorf("%w: private key does not match certified node key", ErrReconnectProof)
	}
	normalizedServices, err := normalizeReconnectServices(services)
	if err != nil {
		return ReconnectProof{}, err
	}
	statement, err := expectedReconnectStatement(challenge, identity, normalizedServices)
	if err != nil {
		return ReconnectProof{}, err
	}
	canonical, err := canonicalReconnectStatement(statement)
	if err != nil {
		return ReconnectProof{}, err
	}
	signature := ed25519.Sign(nodePrivateKey, canonical)
	return ReconnectProof{Statement: statement, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func VerifyReconnectProof(
	challenge ReconnectChallenge,
	identity authproof.SignedReconnectIdentity,
	proof ReconnectProof,
	authorityPublicKey ed25519.PublicKey,
	maxIdentityTTL time.Duration,
	replayCache *authproof.NonceCache,
	now time.Time,
) (authproof.ReconnectIdentity, []sessionmux.ServiceID, error) {
	challenge = challenge.Normalized()
	if err := challenge.Validate(now); err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	verifiedIdentity, err := authproof.VerifySignedReconnectIdentity(identity, authorityPublicKey, authproof.ReconnectIdentityVerifyOptions{
		Now:         now,
		Audience:    authproof.AudienceReconnectIdentity,
		ChainSHA256: challenge.ChainSHA256,
		CurrentNode: challenge.ProverNode,
		MaxTTL:      maxIdentityTTL,
	})
	if err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	if err := identityMatchesChallenge(verifiedIdentity, challenge); err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	normalizedServices, err := normalizeReconnectServices(proof.Statement.Services)
	if err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	expected, err := expectedReconnectStatement(challenge, identity, normalizedServices)
	if err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	statement := proof.Statement.Normalized()
	if !equalReconnectStatement(statement, expected) {
		return authproof.ReconnectIdentity{}, nil, ErrReconnectProof
	}
	canonical, err := canonicalReconnectStatement(statement)
	if err != nil {
		return authproof.ReconnectIdentity{}, nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(proof.Signature))
	publicKey, keyErr := verifiedIdentity.PublicKey()
	if err != nil || keyErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return authproof.ReconnectIdentity{}, nil, authproof.ErrInvalidSignature
	}
	if replayCache != nil && !replayCache.Accept(challenge.ChallengeID, challenge.ExpiresAtUnix, nowOrCurrent(now)) {
		return authproof.ReconnectIdentity{}, nil, authproof.ErrReplay
	}
	return verifiedIdentity, normalizedServices, nil
}

func identityMatchesChallenge(identity authproof.ReconnectIdentity, challenge ReconnectChallenge) error {
	context := identity.Context.Normalized()
	if context.ChainSHA256 != challenge.ChainSHA256 || context.CurrentNode != challenge.ProverNode {
		return ErrReconnectProof
	}
	linkID, err := sessionlink.DeriveID(sessionlink.Descriptor{
		ChainSHA256: context.ChainSHA256,
		Topology:    context.Nodes,
		LocalNode:   challenge.AcceptorNode,
		PeerNode:    context.CurrentNode,
	})
	if err != nil || linkID != challenge.LinkID {
		return ErrReconnectProof
	}
	return nil
}

func expectedReconnectStatement(
	challenge ReconnectChallenge,
	identity authproof.SignedReconnectIdentity,
	services []sessionmux.ServiceID,
) (ReconnectStatement, error) {
	challengeDigest, err := reconnectJSONSHA256(challenge.Normalized())
	if err != nil {
		return ReconnectStatement{}, err
	}
	identityDigest, err := authproof.ReconnectIdentitySHA256(identity)
	if err != nil {
		return ReconnectStatement{}, err
	}
	statement := ReconnectStatement{
		Version: ReconnectStatementVersion, Algorithm: authproof.Algorithm,
		ChallengeSHA256: challengeDigest, IdentitySHA256: identityDigest,
		LinkID: challenge.LinkID, TransportID: challenge.TransportID,
		SessionBinding: challenge.SessionBinding, ChainSHA256: challenge.ChainSHA256,
		AcceptorNode: challenge.AcceptorNode, ProverNode: challenge.ProverNode,
		Services: append([]sessionmux.ServiceID(nil), services...),
	}
	return statement.Normalized(), nil
}

func canonicalReconnectStatement(statement ReconnectStatement) ([]byte, error) {
	normalized := statement.Normalized()
	if normalized.Version != ReconnectStatementVersion || normalized.Algorithm != authproof.Algorithm ||
		!validSHA256(normalized.ChallengeSHA256) || !validSHA256(normalized.IdentitySHA256) ||
		sessionlink.ValidateID(normalized.LinkID) != nil || sessionlink.ValidateTransportID(normalized.TransportID) != nil ||
		!validReconnectText(normalized.SessionBinding, 512) || !validSHA256(normalized.ChainSHA256) ||
		!validReconnectText(normalized.AcceptorNode, 256) || !validReconnectText(normalized.ProverNode, 256) ||
		normalized.AcceptorNode == normalized.ProverNode {
		return nil, ErrReconnectProof
	}
	if _, err := normalizeReconnectServices(normalized.Services); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func equalReconnectStatement(left, right ReconnectStatement) bool {
	a, errA := canonicalReconnectStatement(left)
	b, errB := canonicalReconnectStatement(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func normalizeReconnectServices(raw []sessionmux.ServiceID) ([]sessionmux.ServiceID, error) {
	if len(raw) > 64 {
		return nil, ErrReconnectProof
	}
	seen := make(map[sessionmux.ServiceID]bool, len(raw))
	out := make([]sessionmux.ServiceID, 0, len(raw))
	for _, service := range raw {
		if !service.Valid() || service == sessionmux.ServiceControl {
			return nil, ErrReconnectProof
		}
		if !seen[service] {
			seen[service] = true
			out = append(out, service)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func reconnectJSONSHA256(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func randomReconnectNonce(size int) (string, error) {
	if size <= 0 {
		size = 24
	}
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validReconnectText(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func nowOrCurrent(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now()
	}
	return now
}
