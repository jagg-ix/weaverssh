package authproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Version   = "weaverssh.auth.v1"
	Algorithm = "Ed25519"

	CapabilityX11Relay         = "x11.relay"
	CapabilityWebSocketUpgrade = "websocket.upgrade"
	CapabilitySocksProxy       = "socks.proxy"
	CapabilityFileBackhaul     = "file.backhaul"
	CapabilityVFSMesh          = "vfs.mesh"
	CapabilityNodeContext      = "node.context"
	CapabilityMapReduce        = "compute.mapreduce"
)

var (
	ErrInvalidGrant       = errors.New("invalid grant")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrExpiredGrant       = errors.New("expired grant")
	ErrNotYetValid        = errors.New("grant not yet valid")
	ErrWrongAudience      = errors.New("wrong audience")
	ErrWrongSubject       = errors.New("wrong subject peer")
	ErrMissingCapability  = errors.New("missing required capability")
	ErrWrongX11CookieHash = errors.New("wrong x11 cookie hash")
	ErrWrongChainHash     = errors.New("wrong chain hash")
	ErrGrantTTLTooLong    = errors.New("grant TTL too long")
	ErrReplay             = errors.New("replayed nonce")
)

// Grant is the canonical payload signed by a trusted peer. It intentionally
// contains no signature field; signatures are over compact JSON for this struct.
type Grant struct {
	Version         string   `json:"version"`
	Algorithm       string   `json:"algorithm"`
	IssuerPeerID    string   `json:"issuer_peer_id"`
	SubjectPeerID   string   `json:"subject_peer_id"`
	Audience        string   `json:"audience"`
	SessionID       string   `json:"session_id"`
	Capabilities    []string `json:"capabilities"`
	SecurityLevel   string   `json:"security_level,omitempty"`
	X11CookieSHA256 string   `json:"x11_cookie_sha256"`
	ChainSHA256     string   `json:"chain_sha256"`
	Nonce           string   `json:"nonce"`
	IssuedAtUnix    int64    `json:"issued_at_unix"`
	ExpiresAtUnix   int64    `json:"expires_at_unix"`
}

// SignedGrant is the wire proof object carried in the first auth control frame.
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}

// VerifyOptions constrains proof verification to the current session context.
type VerifyOptions struct {
	Now                  time.Time
	Audience             string
	SubjectPeerID        string
	RequiredCapabilities []string
	SecurityLevel        string
	X11CookieSHA256      string
	ChainSHA256          string
	MaxTTL               time.Duration
	ReplayCache          *NonceCache
}

// NonceCache tracks accepted proof nonces until their grant expiry.
type NonceCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

func NewNonceCache() *NonceCache {
	return &NonceCache{seen: make(map[string]int64)}
}

func (c *NonceCache) CheckAndStore(nonce string, expiresAtUnix int64, now time.Time) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	nowUnix := now.Unix()
	for n, exp := range c.seen {
		if exp <= nowUnix {
			delete(c.seen, n)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return ErrReplay
	}
	c.seen[nonce] = expiresAtUnix
	return nil
}

// Accept is the boolean form of CheckAndStore: it returns true when the nonce
// was newly recorded and false when it was already present (a replay). It backs
// callers that treat a replay as a plain rejection rather than a returned error.
func (c *NonceCache) Accept(nonce string, expiresAtUnix int64, now time.Time) bool {
	return c.CheckAndStore(nonce, expiresAtUnix, now) == nil
}

func NewRandomNonce(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 24
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (g Grant) Normalized() Grant {
	out := g
	if out.Version == "" {
		out.Version = Version
	}
	if out.Algorithm == "" {
		out.Algorithm = Algorithm
	}
	out.IssuerPeerID = strings.TrimSpace(out.IssuerPeerID)
	out.SubjectPeerID = strings.TrimSpace(out.SubjectPeerID)
	out.Audience = strings.TrimSpace(out.Audience)
	out.SessionID = strings.TrimSpace(out.SessionID)
	out.Nonce = strings.TrimSpace(out.Nonce)
	out.X11CookieSHA256 = strings.ToLower(strings.TrimSpace(out.X11CookieSHA256))
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.Capabilities = normalizeCapabilities(out.Capabilities)
	out.SecurityLevel = NormalizeSecurityLevel(out.SecurityLevel)
	if out.SecurityLevel == SecurityLevelCompat {
		out.SecurityLevel = ""
	}
	return out
}

func (g Grant) Validate() error {
	g = g.Normalized()
	if g.Version != Version {
		return fmt.Errorf("%w: unsupported version %q", ErrInvalidGrant, g.Version)
	}
	if g.Algorithm != Algorithm {
		return fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidGrant, g.Algorithm)
	}
	for name, value := range map[string]string{
		"issuer_peer_id":    g.IssuerPeerID,
		"subject_peer_id":   g.SubjectPeerID,
		"audience":          g.Audience,
		"session_id":        g.SessionID,
		"nonce":             g.Nonce,
		"x11_cookie_sha256": g.X11CookieSHA256,
		"chain_sha256":      g.ChainSHA256,
	} {
		if value == "" {
			return fmt.Errorf("%w: missing %s", ErrInvalidGrant, name)
		}
	}
	if len(g.Capabilities) == 0 {
		return fmt.Errorf("%w: missing capabilities", ErrInvalidGrant)
	}
	if g.SecurityLevel != "" && !KnownSecurityLevel(g.SecurityLevel) {
		return fmt.Errorf("%w: %q", ErrInvalidSecurityLevel, g.SecurityLevel)
	}
	if !isLowerHexSHA256(g.X11CookieSHA256) {
		return fmt.Errorf("%w: x11_cookie_sha256 must be 64 lowercase hex chars", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(g.ChainSHA256) {
		return fmt.Errorf("%w: chain_sha256 must be 64 lowercase hex chars", ErrInvalidGrant)
	}
	if g.IssuedAtUnix <= 0 || g.ExpiresAtUnix <= 0 || g.ExpiresAtUnix <= g.IssuedAtUnix {
		return fmt.Errorf("%w: invalid validity window", ErrInvalidGrant)
	}
	for _, cap := range g.Capabilities {
		if !knownCapability(cap) {
			return fmt.Errorf("%w: unknown capability %q", ErrInvalidGrant, cap)
		}
	}
	return nil
}

func CanonicalBytes(g Grant) ([]byte, error) {
	g = g.Normalized()
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(g)
}

func SignGrant(g Grant, privateKey ed25519.PrivateKey) (SignedGrant, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedGrant{}, fmt.Errorf("%w: Ed25519 private key must be %d bytes", ErrInvalidGrant, ed25519.PrivateKeySize)
	}
	canonical, err := CanonicalBytes(g)
	if err != nil {
		return SignedGrant{}, err
	}
	sig := ed25519.Sign(privateKey, canonical)
	return SignedGrant{Grant: g.Normalized(), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

func VerifySignedGrant(sg SignedGrant, publicKey ed25519.PublicKey, opts VerifyOptions) (Grant, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Grant{}, fmt.Errorf("%w: Ed25519 public key must be %d bytes", ErrInvalidGrant, ed25519.PublicKeySize)
	}
	grant := sg.Grant.Normalized()
	if err := grant.Validate(); err != nil {
		return Grant{}, err
	}
	canonical, err := CanonicalBytes(grant)
	if err != nil {
		return Grant{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(sg.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Grant{}, ErrInvalidSignature
	}
	if !ed25519.Verify(publicKey, canonical, sig) {
		return Grant{}, ErrInvalidSignature
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowUnix := now.Unix()
	if nowUnix < grant.IssuedAtUnix {
		return Grant{}, ErrNotYetValid
	}
	if nowUnix >= grant.ExpiresAtUnix {
		return Grant{}, ErrExpiredGrant
	}
	if opts.MaxTTL > 0 && time.Duration(grant.ExpiresAtUnix-grant.IssuedAtUnix)*time.Second > opts.MaxTTL {
		return Grant{}, ErrGrantTTLTooLong
	}
	if opts.Audience != "" && grant.Audience != opts.Audience {
		return Grant{}, ErrWrongAudience
	}
	if opts.SubjectPeerID != "" && grant.SubjectPeerID != opts.SubjectPeerID {
		return Grant{}, ErrWrongSubject
	}
	for _, required := range opts.RequiredCapabilities {
		if !hasCapability(grant.Capabilities, required) {
			return Grant{}, ErrMissingCapability
		}
	}
	if opts.SecurityLevel != "" {
		expectedLevel := NormalizeSecurityLevel(opts.SecurityLevel)
		grantLevel := NormalizeSecurityLevel(grant.SecurityLevel)
		if grantLevel != expectedLevel {
			return Grant{}, ErrWrongSecurityLevel
		}
	}
	if opts.X11CookieSHA256 != "" && grant.X11CookieSHA256 != strings.ToLower(strings.TrimSpace(opts.X11CookieSHA256)) {
		return Grant{}, ErrWrongX11CookieHash
	}
	if opts.ChainSHA256 != "" && grant.ChainSHA256 != strings.ToLower(strings.TrimSpace(opts.ChainSHA256)) {
		return Grant{}, ErrWrongChainHash
	}
	if err := opts.ReplayCache.CheckAndStore(grant.Nonce, grant.ExpiresAtUnix, now); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func EncodePublicKey(publicKey ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

func DecodePublicKey(raw string) (ed25519.PublicKey, error) {
	if publicKey, _, ok, err := DecodeOpenSSHEd25519PublicKey(raw); ok || err != nil {
		return publicKey, err
	}
	buf, err := decodeRawKey(raw)
	if err != nil {
		return nil, err
	}
	if len(buf) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must decode to %d bytes", ErrInvalidGrant, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(buf), nil
}

func EncodePrivateKey(privateKey ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(privateKey)
}

func DecodePrivateKey(raw string) (ed25519.PrivateKey, error) {
	buf, err := decodeRawKey(raw)
	if err != nil {
		return nil, err
	}
	switch len(buf) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(buf), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(buf), nil
	default:
		return nil, fmt.Errorf("%w: Ed25519 private key must decode to %d-byte seed or %d-byte private key", ErrInvalidGrant, ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func normalizeCapabilities(caps []string) []string {
	seen := make(map[string]struct{}, len(caps))
	out := make([]string, 0, len(caps))
	for _, cap := range caps {
		cap = strings.TrimSpace(cap)
		if cap == "" {
			continue
		}
		if _, ok := seen[cap]; ok {
			continue
		}
		seen[cap] = struct{}{}
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}

func hasCapability(caps []string, required string) bool {
	required = strings.TrimSpace(required)
	for _, cap := range caps {
		if cap == required {
			return true
		}
	}
	return false
}

func knownCapability(cap string) bool {
	switch cap {
	case CapabilityX11Relay, CapabilityWebSocketUpgrade, CapabilitySocksProxy, CapabilityFileBackhaul, CapabilityVFSMesh, CapabilityNodeContext, CapabilityMapReduce:
		return true
	default:
		return false
	}
}

func isLowerHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func decodeRawKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty key", ErrInvalidGrant)
	}
	// Prefer exact-length hex because deterministic test seeds are hex strings
	// and many hex strings are also syntactically valid base64url text.
	if isHexKeyCandidate(raw) {
		if buf, err := hex.DecodeString(raw); err == nil {
			return buf, nil
		}
	}
	if buf, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return buf, nil
	}
	if buf, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return buf, nil
	}
	if buf, err := hex.DecodeString(raw); err == nil {
		return buf, nil
	}
	return nil, fmt.Errorf("%w: key must be base64url, base64, or hex", ErrInvalidGrant)
}

func isHexKeyCandidate(raw string) bool {
	if len(raw) != ed25519.SeedSize*2 && len(raw) != ed25519.PublicKeySize*2 && len(raw) != ed25519.PrivateKeySize*2 {
		return false
	}
	for _, ch := range raw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

var ErrWrongFrameType = errors.New("wrong auth control frame type")

// ControlFrame is the first WebSocket control message sent before relay bytes.
type ControlFrame struct {
	Type  string      `json:"type"`
	Proof SignedGrant `json:"proof"`
}

func NewControlFrame(proof SignedGrant) ControlFrame {
	return ControlFrame{Type: Version, Proof: proof}
}

func MarshalControlFrame(proof SignedGrant) ([]byte, error) {
	return json.Marshal(NewControlFrame(proof))
}

func ParseControlFrame(data []byte) (SignedGrant, error) {
	var frame ControlFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		return SignedGrant{}, err
	}
	if frame.Type != Version {
		return SignedGrant{}, ErrWrongFrameType
	}
	return frame.Proof, nil
}
