package authproof

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeConfigSignsAndVerifiesWithKeyFiles(t *testing.T) {
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "origin.ed25519")
	publicPath := filepath.Join(dir, "origin.ed25519.pub")
	if err := os.WriteFile(privatePath, []byte(EncodePrivateKey(privateKey)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(publicPath, []byte(EncodePublicKey(publicKey)), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	now := time.Unix(1781234567, 0)
	cookieHash := HashX11Cookie("runtime-cookie")
	chainHash := DefaultChainSHA256()
	signer := RuntimeConfig{
		Mode:                 ProofModeRequired,
		IssuerPeerID:         "origin-alise-workstation",
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		PrivateKeyFile:       privatePath,
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: []string{CapabilityX11Relay, CapabilityWebSocketUpgrade},
	}
	proof, err := signer.Sign(now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifier := RuntimeConfig{
		Mode:                 ProofModeRequired,
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		PublicKeyFile:        publicPath,
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: []string{CapabilityWebSocketUpgrade, CapabilityX11Relay},
		ReplayCache:          NewNonceCache(),
	}
	grant, err := verifier.Verify(proof, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if grant.IssuerPeerID != signer.IssuerPeerID || grant.SubjectPeerID != signer.SubjectPeerID {
		t.Fatalf("wrong grant peers: %+v", grant)
	}
}

func TestRuntimeConfigRequiredModeRejectsMissingKeys(t *testing.T) {
	cfg := RuntimeConfig{
		Mode:            ProofModeRequired,
		SubjectPeerID:   "agent-linode-a",
		Audience:        AudienceAgent,
		X11CookieSHA256: HashX11Cookie("cookie"),
		ChainSHA256:     DefaultChainSHA256(),
	}
	if err := cfg.ValidateVerifier(); err == nil {
		t.Fatal("expected verifier key validation failure")
	}

	cfg.IssuerPeerID = "origin"
	if err := cfg.ValidateSigner(); err == nil {
		t.Fatal("expected signer key validation failure")
	}
}

func TestRuntimeConfigRequiredModeRejectsMissingChainBinding(t *testing.T) {
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	base := RuntimeConfig{
		Mode:            ProofModeRequired,
		IssuerPeerID:    "origin-alise-workstation",
		SubjectPeerID:   "agent-linode-a",
		Audience:        AudienceAgent,
		PrivateKey:      EncodePrivateKey(privateKey),
		PublicKey:       EncodePublicKey(publicKey),
		X11CookieSHA256: HashX11Cookie("runtime-cookie"),
		TTL:             time.Minute,
	}
	if err := base.ValidateSigner(); err == nil {
		t.Fatal("expected signer validation to reject missing chain binding")
	}
	if err := base.ValidateSignerKeyConfig(); err == nil {
		t.Fatal("expected signer key validation to reject missing chain binding")
	}
	if err := base.ValidateVerifier(); err == nil {
		t.Fatal("expected verifier validation to reject missing chain binding")
	}
}

func TestChainBindingSHA256IsExplicitAndDeterministic(t *testing.T) {
	got := ChainBindingSHA256("origin-alise", "jump-a", "agent-linode-a")
	again := ChainBindingSHA256(" origin-alise ", "jump-a", "agent-linode-a")
	if got == "" || got != again {
		t.Fatalf("chain binding should be deterministic after trimming: got=%q again=%q", got, again)
	}
	if got == DefaultChainSHA256() {
		t.Fatal("explicit chain binding should not collapse to the legacy test default")
	}
}

func TestRuntimeConfigOffModeDoesNotRequireKeys(t *testing.T) {
	cfg := RuntimeConfig{Mode: ProofModeOff}
	if err := cfg.ValidateVerifier(); err != nil {
		t.Fatalf("off verifier should not require keys: %v", err)
	}
	if err := cfg.ValidateSigner(); err != nil {
		t.Fatalf("off signer should not require keys: %v", err)
	}
	if _, err := cfg.BuildGrant(time.Now(), "nonce"); !errors.Is(err, ErrProofDisabled) {
		t.Fatalf("expected ErrProofDisabled, got %v", err)
	}
}

func TestVerifySignedGrantRejectsTTLAboveVerifierLimit(t *testing.T) {
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	now := time.Unix(1781234567, 0)
	grant := Grant{
		Version:         Version,
		Algorithm:       Algorithm,
		IssuerPeerID:    "origin",
		SubjectPeerID:   "agent",
		Audience:        AudienceAgent,
		SessionID:       "long-ttl-session",
		Capabilities:    DefaultRelayCapabilities(),
		X11CookieSHA256: HashX11Cookie("cookie"),
		ChainSHA256:     DefaultChainSHA256(),
		Nonce:           "nonce-long-ttl",
		IssuedAtUnix:    now.Unix(),
		ExpiresAtUnix:   now.Add(10 * time.Minute).Unix(),
	}
	proof, err := SignGrant(grant, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = VerifySignedGrant(proof, publicKey, VerifyOptions{
		Now:                  now.Add(time.Second),
		Audience:             AudienceAgent,
		SubjectPeerID:        "agent",
		RequiredCapabilities: DefaultRelayCapabilities(),
		X11CookieSHA256:      grant.X11CookieSHA256,
		ChainSHA256:          grant.ChainSHA256,
		MaxTTL:               time.Minute,
	})
	if !errors.Is(err, ErrGrantTTLTooLong) {
		t.Fatalf("expected ErrGrantTTLTooLong, got %v", err)
	}
}

func TestAuthoritySecurityLevelsEvaluateEvidence(t *testing.T) {
	cases := []struct {
		name     string
		level    string
		evidence AuthorityEvidence
		allowed  bool
		missing  string
	}{
		{
			name:     "same UID local admission",
			level:    SecurityLevelSameUID,
			evidence: AuthorityEvidence{SameUID: true, PrincipalUID: "501", ComponentUID: "501"},
			allowed:  true,
		},
		{
			name:     "cookie level requires same UID and MIT cookie",
			level:    SecurityLevelX11Cookie,
			evidence: AuthorityEvidence{SameUID: true, X11CookieMatched: true},
			allowed:  true,
		},
		{
			name:     "agent proof does not require same UID across SSH chain",
			level:    SecurityLevelAgentProof,
			evidence: AuthorityEvidence{X11CookieMatched: true, AgentKeyProofVerified: true},
			allowed:  true,
		},
		{
			name:     "agent socket alone is not authority",
			level:    SecurityLevelAgentProof,
			evidence: AuthorityEvidence{X11CookieMatched: true, AgentSocketPresent: true},
			allowed:  false,
			missing:  RequirementAgentKeyProof,
		},
		{
			name:     "strict requires same UID cookie and key proof",
			level:    SecurityLevelStrict,
			evidence: AuthorityEvidence{SameUID: true, X11CookieMatched: true},
			allowed:  false,
			missing:  RequirementAgentKeyProof,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := EvaluateAuthority(tc.level, tc.evidence)
			if tc.allowed && err != nil {
				t.Fatalf("expected allowed decision, got err=%v decision=%+v", err, decision)
			}
			if !tc.allowed && !errors.Is(err, ErrInsufficientAuthority) {
				t.Fatalf("expected ErrInsufficientAuthority, got err=%v decision=%+v", err, decision)
			}
			if decision.Allowed != tc.allowed {
				t.Fatalf("allowed mismatch: %+v", decision)
			}
			if tc.missing != "" {
				found := false
				for _, item := range decision.Missing {
					if item == tc.missing {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing requirements %v did not include %q", decision.Missing, tc.missing)
				}
			}
		})
	}
}

func TestRuntimeConfigAgentProofSecurityLevelRequiresKeysEvenWhenModeOff(t *testing.T) {
	cfg := RuntimeConfig{
		Mode:            ProofModeOff,
		SecurityLevel:   SecurityLevelAgentProof,
		SubjectPeerID:   "agent-linode-a",
		Audience:        AudienceAgent,
		X11CookieSHA256: HashX11Cookie("cookie"),
		ChainSHA256:     DefaultChainSHA256(),
	}
	if !cfg.Required() {
		t.Fatal("agent_proof security level should require signed proof even with proof mode off")
	}
	if err := cfg.ValidateVerifier(); err == nil {
		t.Fatal("expected missing public key validation failure")
	}
}

func TestRuntimeConfigSignsAndVerifiesSecurityLevelBinding(t *testing.T) {
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	now := time.Unix(1781234567, 0)
	cookieHash := HashX11Cookie("runtime-cookie")
	chainHash := DefaultChainSHA256()
	signer := RuntimeConfig{
		Mode:                 ProofModeOff,
		SecurityLevel:        SecurityLevelAgentProof,
		IssuerPeerID:         "origin-alise-workstation",
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		PrivateKey:           EncodePrivateKey(privateKey),
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: DefaultRelayCapabilities(),
	}
	proof, err := signer.Sign(now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if proof.Grant.SecurityLevel != SecurityLevelAgentProof {
		t.Fatalf("proof did not bind security level: %+v", proof.Grant)
	}
	verifier := RuntimeConfig{
		Mode:                 ProofModeOff,
		SecurityLevel:        SecurityLevelAgentProof,
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		PublicKey:            EncodePublicKey(publicKey),
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: DefaultRelayCapabilities(),
		ReplayCache:          NewNonceCache(),
	}
	if _, err := verifier.Verify(proof, now.Add(time.Second)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	verifier.SecurityLevel = SecurityLevelStrict
	_, err = verifier.Verify(proof, now.Add(2*time.Second))
	if !errors.Is(err, ErrWrongSecurityLevel) {
		t.Fatalf("expected ErrWrongSecurityLevel, got %v", err)
	}
}
