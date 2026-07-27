package socksproof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"weaverssh/authproof"
)

const PolicyVersion = "weaverssh.socks-policy.v1"

type PrincipalPolicy struct {
	ID           string   `json:"id"`
	PublicKey    string   `json:"public_key"`
	Capabilities []string `json:"capabilities"`
	Destinations []string `json:"destinations"`
	MaxTTL       string   `json:"max_ttl,omitempty"`
}

type Policy struct {
	Version    string            `json:"version"`
	ServerID   string            `json:"server_id"`
	Principals []PrincipalPolicy `json:"principals"`
}

type verifiedPrincipal struct {
	policy PrincipalPolicy
	key    ed25519.PublicKey
	allow  destinationPolicy
	maxTTL time.Duration
}

type Verifier struct {
	ServerID       string
	PolicySHA256   string
	principals     map[string]verifiedPrincipal
	identityReplay *ReplayCache
	connectReplay  *ReplayCache
}

func LoadPolicyFile(path string) (Policy, error) {
	payload, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return Policy{}, err
	}
	var policy Policy
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("socksproof: trailing policy JSON data")
	}
	return NormalizePolicy(policy)
}

func NormalizePolicy(policy Policy) (Policy, error) {
	if policy.Version == "" {
		policy.Version = PolicyVersion
	}
	policy.ServerID = strings.TrimSpace(policy.ServerID)
	if policy.Version != PolicyVersion || policy.ServerID == "" || len(policy.Principals) == 0 {
		return Policy{}, ErrInvalidProof
	}
	out := Policy{Version: PolicyVersion, ServerID: policy.ServerID}
	seen := map[string]bool{}
	for _, raw := range policy.Principals {
		principal, err := normalizePrincipal(raw)
		if err != nil {
			return Policy{}, err
		}
		if seen[principal.policy.ID] {
			return Policy{}, fmt.Errorf("socksproof: duplicate principal %q", principal.policy.ID)
		}
		seen[principal.policy.ID] = true
		out.Principals = append(out.Principals, principal.policy)
	}
	sort.Slice(out.Principals, func(i, j int) bool { return out.Principals[i].ID < out.Principals[j].ID })
	return out, nil
}

func PolicyDigest(policy Policy) (string, error) {
	normalized, err := NormalizePolicy(policy)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func NewVerifier(policy Policy) (*Verifier, error) {
	normalized, err := NormalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	digest, err := PolicyDigest(normalized)
	if err != nil {
		return nil, err
	}
	verifier := &Verifier{
		ServerID:      normalized.ServerID,
		PolicySHA256:  digest,
		principals:     map[string]verifiedPrincipal{},
		identityReplay: NewReplayCache(),
		connectReplay:  NewReplayCache(),
	}
	for _, raw := range normalized.Principals {
		principal, err := normalizePrincipal(raw)
		if err != nil {
			return nil, err
		}
		verifier.principals[principal.policy.ID] = principal
	}
	return verifier, nil
}

func (v *Verifier) VerifyIdentity(challenge Challenge, proof SignedIdentity, now time.Time) (PrincipalPolicy, error) {
	if v == nil {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if challenge.ServerID != v.ServerID || challenge.PolicySHA256 != v.PolicySHA256 {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	statement := proof.Statement
	if statement.Protocol != ProtocolVersion || strings.TrimSpace(statement.Principal) == "" || strings.TrimSpace(statement.Nonce) == "" || strings.TrimSpace(proof.Signature) == "" {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.ChallengeSHA256 != DigestChallenge(challenge) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.IssuedAtUnix < challenge.IssuedAtUnix || statement.ExpiresAtUnix > challenge.ExpiresAtUnix {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	principal, ok := v.principals[strings.TrimSpace(statement.Principal)]
	if !ok {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if err := ValidateTime(statement.IssuedAtUnix, statement.ExpiresAtUnix, principal.maxTTL, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := VerifySignature(principal.key, statement, proof.Signature); err != nil {
		return PrincipalPolicy{}, err
	}
	if !contains(statement.Capabilities, CapabilityConnect) || !contains(principal.policy.Capabilities, CapabilityConnect) {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if err := v.identityReplay.Check(statement.Nonce, statement.ExpiresAtUnix, now); err != nil {
		return PrincipalPolicy{}, err
	}
	return principal.policy, nil
}

func (v *Verifier) VerifyConnect(challenge Challenge, identity SignedIdentity, proof SignedConnect, expectedNetwork, expectedAddress, expectedBinding, expectedNode string, now time.Time) (PrincipalPolicy, error) {
	if v == nil {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if challenge.ServerID != v.ServerID || challenge.PolicySHA256 != v.PolicySHA256 {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	network, address, err := NormalizeAddress(expectedNetwork, expectedAddress)
	if err != nil {
		return PrincipalPolicy{}, err
	}
	expectedBinding = strings.TrimSpace(expectedBinding)
	expectedNode = strings.TrimSpace(expectedNode)
	if expectedBinding == "" || expectedNode == "" {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	statement := proof.Statement
	if statement.Protocol != ProtocolVersion || statement.Command != 0x01 || strings.TrimSpace(statement.Principal) == "" || strings.TrimSpace(statement.Nonce) == "" || strings.TrimSpace(proof.Signature) == "" {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.Principal != identity.Statement.Principal || statement.ChallengeSHA256 != DigestChallenge(challenge) || statement.IdentitySHA256 != DigestIdentity(identity) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.Network != network || statement.Address != address || statement.SessionBinding != expectedBinding || statement.SelectedNode != expectedNode {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.IssuedAtUnix < identity.Statement.IssuedAtUnix || statement.ExpiresAtUnix > identity.Statement.ExpiresAtUnix || statement.ExpiresAtUnix > challenge.ExpiresAtUnix {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	principal, ok := v.principals[strings.TrimSpace(statement.Principal)]
	if !ok {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if err := ValidateTime(statement.IssuedAtUnix, statement.ExpiresAtUnix, principal.maxTTL, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := VerifySignature(principal.key, statement, proof.Signature); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := principal.allow.Authorize(address); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := v.connectReplay.Check(statement.Nonce, statement.ExpiresAtUnix, now); err != nil {
		return PrincipalPolicy{}, err
	}
	return principal.policy, nil
}

func (v *Verifier) Principal(id string) (PrincipalPolicy, bool) {
	if v == nil {
		return PrincipalPolicy{}, false
	}
	principal, ok := v.principals[strings.TrimSpace(id)]
	return principal.policy, ok
}

func normalizePrincipal(raw PrincipalPolicy) (verifiedPrincipal, error) {
	raw.ID = strings.TrimSpace(raw.ID)
	raw.PublicKey = strings.TrimSpace(raw.PublicKey)
	if raw.ID == "" || raw.PublicKey == "" {
		return verifiedPrincipal{}, ErrInvalidProof
	}
	key, err := authproof.DecodePublicKey(raw.PublicKey)
	if err != nil {
		return verifiedPrincipal{}, fmt.Errorf("socksproof: principal %s public key: %w", raw.ID, err)
	}
	raw.PublicKey = authproof.EncodePublicKey(key)
	raw.Capabilities = normalizeStrings(raw.Capabilities)
	if !contains(raw.Capabilities, CapabilityConnect) {
		return verifiedPrincipal{}, fmt.Errorf("%w: principal %s lacks %s", ErrUnauthorized, raw.ID, CapabilityConnect)
	}
	raw.Destinations = normalizeStrings(raw.Destinations)
	allow, err := newDestinationPolicy(raw.Destinations)
	if err != nil {
		return verifiedPrincipal{}, fmt.Errorf("socksproof: principal %s destinations: %w", raw.ID, err)
	}
	maxTTL := 30 * time.Second
	if strings.TrimSpace(raw.MaxTTL) != "" {
		maxTTL, err = time.ParseDuration(strings.TrimSpace(raw.MaxTTL))
		if err != nil || maxTTL <= 0 || maxTTL > 5*time.Minute {
			return verifiedPrincipal{}, errors.New("socksproof: invalid principal max_ttl")
		}
	}
	raw.MaxTTL = maxTTL.String()
	return verifiedPrincipal{policy: raw, key: key, allow: allow, maxTTL: maxTTL}, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
