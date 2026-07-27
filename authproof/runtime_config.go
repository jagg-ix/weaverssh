package authproof

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	ProofModeOff      = "off"
	ProofModeRequired = "required"

	AudienceAgent = "wv-agent"
	AudienceSocks = "wv-socks"

	DefaultProofTTL = time.Minute
)

const defaultChainMaterial = "weaverssh-default-chain"
const chainBindingSeparator = "\x00"

var (
	ErrInvalidProofMode = errors.New("invalid proof mode")
	ErrProofDisabled    = errors.New("authproof is disabled")
)

// RuntimeConfig is the shared CLI/config shape used by signer and verifier
// binaries. Mode defaults to off so existing deployments remain compatible.
type RuntimeConfig struct {
	Mode                 string
	SecurityLevel        string
	IssuerPeerID         string
	SubjectPeerID        string
	Audience             string
	PublicKey            string
	PublicKeyFile        string
	PrivateKey           string
	PrivateKeyFile       string
	SignerProvider       string
	Identity             string
	IdentityFile         string
	AgentSocket          string
	SessionID            string
	X11CookieSHA256      string
	ChainSHA256          string
	TTL                  time.Duration
	RequiredCapabilities []string
	ReplayCache          *NonceCache
}

func NormalizeProofMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ProofModeOff:
		return ProofModeOff
	case ProofModeRequired:
		return ProofModeRequired
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func DefaultChainSHA256() string {
	return SHA256Hex([]byte(defaultChainMaterial))
}

func ChainBindingSHA256(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			normalized = append(normalized, part)
		}
	}
	return SHA256Hex([]byte(strings.Join(normalized, chainBindingSeparator)))
}

func HashX11Cookie(cookie string) string {
	return SHA256Hex([]byte(strings.TrimSpace(cookie)))
}

func DefaultRelayCapabilities() []string {
	return []string{CapabilityWebSocketUpgrade, CapabilityX11Relay}
}

func (c RuntimeConfig) Normalized() RuntimeConfig {
	out := c
	out.Mode = NormalizeProofMode(out.Mode)
	out.SecurityLevel = NormalizeSecurityLevel(out.SecurityLevel)
	out.IssuerPeerID = strings.TrimSpace(out.IssuerPeerID)
	out.SubjectPeerID = strings.TrimSpace(out.SubjectPeerID)
	out.Audience = strings.TrimSpace(out.Audience)
	out.PublicKey = strings.TrimSpace(out.PublicKey)
	out.PublicKeyFile = strings.TrimSpace(out.PublicKeyFile)
	out.PrivateKey = strings.TrimSpace(out.PrivateKey)
	out.PrivateKeyFile = strings.TrimSpace(out.PrivateKeyFile)
	out.SignerProvider = strings.TrimSpace(out.SignerProvider)
	out.Identity = strings.TrimSpace(out.Identity)
	out.IdentityFile = strings.TrimSpace(out.IdentityFile)
	out.AgentSocket = strings.TrimSpace(out.AgentSocket)
	out.SessionID = strings.TrimSpace(out.SessionID)
	out.X11CookieSHA256 = strings.ToLower(strings.TrimSpace(out.X11CookieSHA256))
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	if out.TTL <= 0 {
		out.TTL = DefaultProofTTL
	}
	out.RequiredCapabilities = normalizeCapabilities(out.RequiredCapabilities)
	if len(out.RequiredCapabilities) == 0 {
		out.RequiredCapabilities = DefaultRelayCapabilities()
	}
	return out
}

func (c RuntimeConfig) Required() bool {
	cfg := c.Normalized()
	return cfg.Mode == ProofModeRequired || SecurityLevelRequiresSignedProof(cfg.SecurityLevel)
}

func (c RuntimeConfig) ValidateMode() error {
	mode := NormalizeProofMode(c.Mode)
	if mode != ProofModeOff && mode != ProofModeRequired {
		return fmt.Errorf("%w: %q", ErrInvalidProofMode, c.Mode)
	}
	if err := ValidateSecurityLevel(c.SecurityLevel); err != nil {
		return err
	}
	return nil
}

func (c RuntimeConfig) ValidateVerifier() error {
	cfg := c.Normalized()
	if err := cfg.ValidateMode(); err != nil {
		return err
	}
	if !cfg.Required() {
		return nil
	}
	if cfg.SubjectPeerID == "" {
		return fmt.Errorf("%w: verifier subject peer id required", ErrInvalidGrant)
	}
	if cfg.Audience == "" {
		return fmt.Errorf("%w: verifier audience required", ErrInvalidGrant)
	}
	if cfg.X11CookieSHA256 == "" {
		return fmt.Errorf("%w: verifier x11 cookie hash required", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(cfg.X11CookieSHA256) {
		return fmt.Errorf("%w: verifier x11 cookie hash must be sha256 hex", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(cfg.ChainSHA256) {
		return fmt.Errorf("%w: verifier chain hash must be sha256 hex", ErrInvalidGrant)
	}
	if _, err := cfg.LoadPublicKey(); err != nil {
		return err
	}
	return nil
}

func (c RuntimeConfig) ValidateSignerKeyConfig() error {
	cfg := c.Normalized()
	if err := cfg.ValidateMode(); err != nil {
		return err
	}
	if !cfg.Required() {
		return nil
	}
	if cfg.IssuerPeerID == "" {
		return fmt.Errorf("%w: signer issuer peer id required", ErrInvalidGrant)
	}
	if cfg.SubjectPeerID == "" {
		return fmt.Errorf("%w: signer subject peer id required", ErrInvalidGrant)
	}
	if cfg.Audience == "" {
		return fmt.Errorf("%w: signer audience required", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(cfg.ChainSHA256) {
		return fmt.Errorf("%w: signer chain hash must be sha256 hex", ErrInvalidGrant)
	}
	if err := cfg.ValidateSignerProvider(); err != nil {
		return err
	}
	return nil
}

func (c RuntimeConfig) ValidateSigner() error {
	cfg := c.Normalized()
	if err := cfg.ValidateMode(); err != nil {
		return err
	}
	if !cfg.Required() {
		return nil
	}
	if cfg.IssuerPeerID == "" {
		return fmt.Errorf("%w: signer issuer peer id required", ErrInvalidGrant)
	}
	if cfg.SubjectPeerID == "" {
		return fmt.Errorf("%w: signer subject peer id required", ErrInvalidGrant)
	}
	if cfg.Audience == "" {
		return fmt.Errorf("%w: signer audience required", ErrInvalidGrant)
	}
	if cfg.X11CookieSHA256 == "" {
		return fmt.Errorf("%w: signer x11 cookie hash required", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(cfg.X11CookieSHA256) {
		return fmt.Errorf("%w: signer x11 cookie hash must be sha256 hex", ErrInvalidGrant)
	}
	if !isLowerHexSHA256(cfg.ChainSHA256) {
		return fmt.Errorf("%w: signer chain hash must be sha256 hex", ErrInvalidGrant)
	}
	if err := cfg.ValidateSignerProvider(); err != nil {
		return err
	}
	return nil
}

func (c RuntimeConfig) LoadPublicKey() (ed25519.PublicKey, error) {
	raw, err := loadTextValue(c.PublicKey, c.PublicKeyFile)
	if err != nil {
		return nil, err
	}
	return DecodePublicKey(raw)
}

func (c RuntimeConfig) LoadPrivateKey() (ed25519.PrivateKey, error) {
	raw, err := loadTextValue(c.PrivateKey, c.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	return DecodePrivateKey(raw)
}

func (c RuntimeConfig) BuildGrant(now time.Time, nonce string) (Grant, error) {
	cfg := c.Normalized()
	if !cfg.Required() {
		return Grant{}, ErrProofDisabled
	}
	if now.IsZero() {
		now = time.Now()
	}
	if strings.TrimSpace(nonce) == "" {
		generated, err := NewRandomNonce(24)
		if err != nil {
			return Grant{}, err
		}
		nonce = generated
	}
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s-%d", cfg.SubjectPeerID, now.UnixNano())
	}
	grant := Grant{
		Version:         Version,
		Algorithm:       Algorithm,
		IssuerPeerID:    cfg.IssuerPeerID,
		SubjectPeerID:   cfg.SubjectPeerID,
		Audience:        cfg.Audience,
		SessionID:       sessionID,
		Capabilities:    cfg.RequiredCapabilities,
		SecurityLevel:   securityLevelForGrant(cfg.SecurityLevel),
		X11CookieSHA256: cfg.X11CookieSHA256,
		ChainSHA256:     cfg.ChainSHA256,
		Nonce:           nonce,
		IssuedAtUnix:    now.Unix(),
		ExpiresAtUnix:   now.Add(cfg.TTL).Unix(),
	}
	if err := grant.Validate(); err != nil {
		return Grant{}, err
	}
	return grant.Normalized(), nil
}

func (c RuntimeConfig) Sign(now time.Time) (SignedGrant, error) {
	cfg := c.Normalized()
	provider := cfg.normalizedSignerProvider()
	if provider == SignerProviderSSHAgent || provider == SignerProviderGPGAgent {
		return cfg.SignWithAgent(now, provider)
	}
	if err := cfg.ValidateSigner(); err != nil {
		return SignedGrant{}, err
	}
	privateKey, err := cfg.LoadPrivateKey()
	if err != nil {
		return SignedGrant{}, err
	}
	grant, err := cfg.BuildGrant(now, "")
	if err != nil {
		return SignedGrant{}, err
	}
	return SignGrant(grant, privateKey)
}

func (c RuntimeConfig) Verify(proof SignedGrant, now time.Time) (Grant, error) {
	cfg := c.Normalized()
	if err := cfg.ValidateVerifier(); err != nil {
		return Grant{}, err
	}
	publicKey, err := cfg.LoadPublicKey()
	if err != nil {
		return Grant{}, err
	}
	return VerifySignedGrant(proof, publicKey, VerifyOptions{
		Now:                  now,
		Audience:             cfg.Audience,
		SubjectPeerID:        cfg.SubjectPeerID,
		RequiredCapabilities: cfg.RequiredCapabilities,
		SecurityLevel:        securityLevelForVerify(cfg.SecurityLevel),
		X11CookieSHA256:      cfg.X11CookieSHA256,
		ChainSHA256:          cfg.ChainSHA256,
		MaxTTL:               cfg.TTL,
		ReplayCache:          cfg.ReplayCache,
	})
}

func loadTextValue(inlineValue, filePath string) (string, error) {
	inlineValue = strings.TrimSpace(inlineValue)
	filePath = strings.TrimSpace(filePath)
	if inlineValue != "" {
		return inlineValue, nil
	}
	if filePath == "" {
		return "", fmt.Errorf("%w: missing key material", ErrInvalidGrant)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read key file %s: %w", filePath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func securityLevelForGrant(level string) string {
	normalized := NormalizeSecurityLevel(level)
	if normalized == SecurityLevelCompat {
		return ""
	}
	return normalized
}

func securityLevelForVerify(level string) string {
	normalized := NormalizeSecurityLevel(level)
	if normalized == SecurityLevelCompat {
		return ""
	}
	return normalized
}
