package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"weaverssh/authproof"
)

const EnvRuntimeProofRefresh = "WEAVERSSH_PROOF_REFRESH"

type RuntimeProofRequest struct {
	Generation uint64
	Cookie string
	CookieSHA256 string
	NodeContext authproof.NodeContext
	PreviousNode string
	IssuedAt time.Time
}

type RuntimeProofProvider interface { RuntimeProof(context.Context, RuntimeProofRequest) (*authproof.SignedGrant, error) }
type RuntimeProofProviderFunc func(context.Context, RuntimeProofRequest) (*authproof.SignedGrant, error)
func (f RuntimeProofProviderFunc) RuntimeProof(ctx context.Context, request RuntimeProofRequest) (*authproof.SignedGrant, error) { if f == nil { return nil, errors.New("runtime proof provider: nil provider") }; return f(ctx, request) }

type RuntimeProofSigner struct { Template authproof.RuntimeConfig }

func (s RuntimeProofSigner) RuntimeProof(ctx context.Context, request RuntimeProofRequest) (*authproof.SignedGrant, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	cookieHash := strings.ToLower(strings.TrimSpace(request.CookieSHA256)); if cookieHash == "" { cookieHash = authproof.HashX11Cookie(request.Cookie) }
	chainHash := strings.ToLower(strings.TrimSpace(request.NodeContext.ChainSHA256))
	if cookieHash == "" || chainHash == "" { return nil, errors.New("runtime proof provider: current cookie and chain binding are required") }
	cfg := s.Template; cfg.Mode = authproof.ProofModeRequired; cfg.X11CookieSHA256 = cookieHash; cfg.ChainSHA256 = chainHash
	prefix := strings.TrimSpace(cfg.SessionID); if prefix == "" { prefix = strings.TrimSpace(request.NodeContext.CurrentNode) }; if prefix == "" { prefix = "wv-transport" }
	cfg.SessionID = fmt.Sprintf("%s-g%d-%d", prefix, request.Generation, request.IssuedAt.UnixNano())
	signed, err := cfg.Sign(request.IssuedAt); if err != nil { return nil, fmt.Errorf("runtime proof provider: sign generation %d: %w", request.Generation, err) }
	return &signed, nil
}

func RuntimeProofProviderFromEnvironment() (RuntimeProofProvider, bool, error) {
	mode := authproof.NormalizeProofMode(os.Getenv("WEAVERSSH_PROOF_MODE"))
	provider := authproof.NormalizeSignerProvider(firstNonempty(os.Getenv("WEAVERSSH_PROOF_SIGNER_PROVIDER"), os.Getenv("WEAVERSSH_PROOF_SIGNER")))
	hasSigner := strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY")) != "" || strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY_FILE")) != "" || strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_IDENTITY")) != "" || strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_IDENTITY_FILE")) != "" || strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_AGENT_SOCKET")) != ""
	enabled := envBoolValue(os.Getenv(EnvRuntimeProofRefresh)) || (mode == authproof.ProofModeRequired && hasSigner)
	if !enabled { return nil, false, nil }
	ttl := authproof.DefaultProofTTL
	if raw := strings.TrimSpace(os.Getenv("WEAVERSSH_PROOF_TTL")); raw != "" { parsed, err := time.ParseDuration(raw); if err != nil || parsed <= 0 { return nil, false, fmt.Errorf("runtime proof provider: invalid WEAVERSSH_PROOF_TTL %q", raw) }; ttl = parsed }
	capabilities := splitProofCapabilities(os.Getenv("WEAVERSSH_PROOF_CAPABILITIES")); if len(capabilities) == 0 { capabilities = authproof.DefaultRelayCapabilities() }
	template := authproof.RuntimeConfig{
		Mode: authproof.ProofModeRequired,
		SecurityLevel: getenvDefault("WEAVERSSH_PROOF_SECURITY_LEVEL", authproof.SecurityLevelCompat),
		IssuerPeerID: getenvDefault("WEAVERSSH_PROOF_ISSUER_ID", defaultPeerID("wv-attach")),
		SubjectPeerID: getenvDefault("WEAVERSSH_PROOF_SUBJECT_ID", "wv-session-host"),
		Audience: authproof.AudienceAgent,
		PrivateKey: os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY"),
		PrivateKeyFile: os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY_FILE"),
		SignerProvider: provider,
		Identity: os.Getenv("WEAVERSSH_PROOF_IDENTITY"),
		IdentityFile: os.Getenv("WEAVERSSH_PROOF_IDENTITY_FILE"),
		AgentSocket: os.Getenv("WEAVERSSH_PROOF_AGENT_SOCKET"),
		SessionID: os.Getenv("WEAVERSSH_PROOF_SESSION_ID"),
		TTL: ttl,
		RequiredCapabilities: capabilities,
		// Validation requires a syntactically valid chain binding. This value is
		// never issued: RuntimeProof replaces it with the current node context.
		ChainSHA256: authproof.DefaultChainSHA256(),
	}
	if err := template.ValidateSignerKeyConfig(); err != nil { return nil, false, fmt.Errorf("runtime proof provider: signer configuration: %w", err) }
	return RuntimeProofSigner{Template: template}, true, nil
}

func splitProofCapabilities(raw string) []string { seen := map[string]bool{}; var out []string; for _, value := range strings.Split(raw, ",") { value = strings.TrimSpace(value); if value != "" && !seen[value] { seen[value] = true; out = append(out, value) } }; return out }
func firstNonempty(values ...string) string { for _, value := range values { if strings.TrimSpace(value) != "" { return value } }; return "" }

func attachFuncWithRuntimeProofProvider(base func(context.Context, AttachConfig) (*AttachedSession, error), provider RuntimeProofProvider) func(context.Context, AttachConfig) (*AttachedSession, error) {
	if base == nil { base = AttachDynamicSession }
	var attempt atomic.Uint64
	return func(ctx context.Context, raw AttachConfig) (*AttachedSession, error) {
		generation := attempt.Add(1)
		cookie := strings.TrimSpace(raw.AuthCookie)
		if cookie == "" { resolved, err := getSystemX11Cookie(); if err != nil { return nil, fmt.Errorf("attach supervisor: resolve X11 cookie for proof generation %d: %w", generation, err) }; cookie = strings.TrimSpace(resolved); raw.AuthCookie = cookie }
		issuedAt := time.Now()
		proof, err := provider.RuntimeProof(ctx, RuntimeProofRequest{Generation:generation, Cookie:cookie, CookieSHA256:authproof.HashX11Cookie(cookie), NodeContext:raw.SignedContext.Context.Normalized(), PreviousNode:strings.TrimSpace(raw.PreviousNode), IssuedAt:issuedAt})
		if err != nil { return nil, err }
		if proof == nil { return nil, errors.New("attach supervisor: runtime proof provider returned nil proof") }
		raw.RuntimeProof = proof
		return base(ctx, raw)
	}
}

func NewProofRefreshingAttachSupervisor(config AttachSupervisorConfig, provider RuntimeProofProvider) (*AttachSupervisor, error) { if provider == nil { return nil, errors.New("attach supervisor: runtime proof provider is required") }; config.RuntimeProofProvider = provider; return NewAttachSupervisor(config) }
