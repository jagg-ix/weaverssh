package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"weaverssh/authproof"
)

type authproofSummary struct {
	Valid         bool     `json:"valid"`
	Verified      bool     `json:"verified"`
	ProofSHA256   string   `json:"proof_sha256"`
	Issuer        string   `json:"issuer_peer_id"`
	Subject       string   `json:"subject_peer_id"`
	Audience      string   `json:"audience"`
	SessionID     string   `json:"session_id"`
	Capabilities  []string `json:"capabilities"`
	SecurityLevel string   `json:"security_level,omitempty"`
	CookieSHA256  string   `json:"x11_cookie_sha256"`
	ChainSHA256   string   `json:"chain_sha256"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	TTL           string   `json:"ttl"`
}

func cmdAuthproof(args []string) int {
	if len(args) == 0 {
		printAuthproofUsage()
		return 2
	}
	switch args[0] {
	case "issue", "sign", "create":
		return cmdAuthproofIssue(args[1:])
	case "verify", "check":
		return cmdAuthproofVerify(args[1:])
	case "show", "inspect":
		return cmdAuthproofShow(args[1:])
	case "hash-cookie", "cookie-hash":
		return cmdAuthproofHashCookie(args[1:])
	case "hash-chain", "chain-hash":
		return cmdAuthproofHashChain(args[1:])
	case "help", "-h", "--help":
		printAuthproofUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "authproof: unknown command %q\n", args[0])
		printAuthproofUsage()
		return 2
	}
}

func cmdAuthproofIssue(args []string) int {
	fs := flag.NewFlagSet("authproof issue", flag.ContinueOnError)
	issuer := fs.String("issuer", envOr("WEAVERSSH_PROOF_ISSUER_ID", ""), "trusted issuer peer id")
	subject := fs.String("subject", envOr("WEAVERSSH_PROOF_SUBJECT_ID", ""), "expected verifier/subject peer id")
	audience := fs.String("audience", envOr("WEAVERSSH_PROOF_AUDIENCE", authproof.AudienceAgent), "proof audience")
	sessionID := fs.String("session-id", envOr("WEAVERSSH_PROOF_SESSION_ID", ""), "optional session id")
	securityLevel := fs.String("security-level", envOr("WEAVERSSH_PROOF_SECURITY_LEVEL", authproof.SecurityLevelCompat), "compat|same_uid|x11_cookie|agent_proof|strict")
	cookie := fs.String("x11-cookie", "", "raw X11 cookie")
	cookieFile := fs.String("x11-cookie-file", "", "file containing raw X11 cookie")
	cookieHash := fs.String("x11-cookie-sha256", envOr("WEAVERSSH_PROOF_X11_COOKIE_SHA256", ""), "precomputed X11 cookie SHA-256")
	chainRef := fs.String("chain", "", "stored chain label or number")
	nodesText := fs.String("nodes", "", "comma/arrow-separated chain nodes")
	chainHash := fs.String("chain-sha256", envOr("WEAVERSSH_PROOF_CHAIN_SHA256", ""), "precomputed chain SHA-256")
	ttl := fs.Duration("ttl", authproof.DefaultProofTTL, "grant validity duration")
	privateKey := fs.String("private-key", envOr("WEAVERSSH_PROOF_PRIVATE_KEY", ""), "inline Ed25519 private key")
	privateKeyFile := fs.String("private-key-file", envOr("WEAVERSSH_PROOF_PRIVATE_KEY_FILE", ""), "Ed25519 private key file")
	signerProvider := fs.String("signer-provider", "key", "key|ssh-agent|gpg-agent")
	identity := fs.String("identity", "", "agent identity comment, fingerprint, or public key")
	identityFile := fs.String("identity-file", "", "agent identity selector/public-key file")
	agentSocket := fs.String("agent-socket", "", "ssh-agent or gpg-agent SSH socket")
	out := fs.String("out", "", "write signed proof JSON to file")
	force := fs.Bool("force", false, "replace an existing output file")
	var capabilities commaListFlag
	fs.Var(&capabilities, "capability", "grant capability; repeatable or comma-separated")
	fs.Var(&capabilities, "capabilities", "alias for --capability")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv authproof issue --issuer ID --subject ID [--audience wv-agent] (--x11-cookie COOKIE|--x11-cookie-sha256 HEX) (--chain NAME|--nodes A,B|--chain-sha256 HEX) [signer flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*issuer) == "" || strings.TrimSpace(*subject) == "" {
		fs.Usage()
		return 2
	}
	resolvedCookieHash, err := resolveProofCookieHash(*cookie, *cookieFile, *cookieHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof issue: %v\n", err)
		return 2
	}
	resolvedChainHash, err := resolveProofChainHash(*nodesText, *chainRef, *chainHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof issue: %v\n", err)
		return 2
	}
	caps := normalizedUniqueStrings(capabilities)
	if len(caps) == 0 {
		caps = authproof.DefaultRelayCapabilities()
	}
	config := authproof.RuntimeConfig{
		Mode:                 authproof.ProofModeRequired,
		SecurityLevel:        *securityLevel,
		IssuerPeerID:         *issuer,
		SubjectPeerID:        *subject,
		Audience:             *audience,
		PrivateKey:           *privateKey,
		PrivateKeyFile:       *privateKeyFile,
		SignerProvider:       *signerProvider,
		Identity:             *identity,
		IdentityFile:         *identityFile,
		AgentSocket:          *agentSocket,
		SessionID:            *sessionID,
		X11CookieSHA256:      resolvedCookieHash,
		ChainSHA256:          resolvedChainHash,
		TTL:                  *ttl,
		RequiredCapabilities: caps,
	}
	signed, err := config.Sign(time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof issue: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*out) == "" {
		if err := emitJSONArtifact(os.Stdout, signed); err != nil {
			fmt.Fprintf(os.Stderr, "authproof issue: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeJSONArtifact(*out, signed, 0o600, *force); err != nil {
		fmt.Fprintf(os.Stderr, "authproof issue: %v\n", err)
		return 1
	}
	fmt.Printf("authproof: wrote %s\n", *out)
	return 0
}

func cmdAuthproofVerify(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("authproof verify", flag.ContinueOnError)
	filePath := fs.String("file", "", "signed proof JSON file")
	inline := fs.String("proof", "", "inline signed proof JSON")
	publicKey := fs.String("public-key", envOr("WEAVERSSH_PROOF_PUBLIC_KEY", ""), "trusted Ed25519 public key")
	publicKeyFile := fs.String("public-key-file", envOr("WEAVERSSH_PROOF_PUBLIC_KEY_FILE", ""), "trusted Ed25519 public-key file")
	audience := fs.String("audience", "", "expected audience")
	subject := fs.String("subject", "", "expected subject peer id")
	securityLevel := fs.String("security-level", "", "expected security level")
	cookie := fs.String("x11-cookie", "", "expected raw X11 cookie")
	cookieFile := fs.String("x11-cookie-file", "", "file containing expected X11 cookie")
	cookieHash := fs.String("x11-cookie-sha256", "", "expected X11 cookie SHA-256")
	chainRef := fs.String("chain", "", "expected stored chain")
	nodesText := fs.String("nodes", "", "expected chain nodes")
	chainHash := fs.String("chain-sha256", "", "expected chain SHA-256")
	maxTTL := fs.Duration("max-ttl", authproof.DefaultProofTTL, "maximum accepted grant TTL")
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	var capabilities commaListFlag
	fs.Var(&capabilities, "require-capability", "required capability; repeatable or comma-separated")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv authproof verify PROOF.json --public-key-file KEY [expected binding flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if strings.TrimSpace(*filePath) == "" && len(operands) == 1 {
		*filePath = operands[0]
	} else if len(operands) != 0 {
		fs.Usage()
		return 2
	}
	signed, err := loadSignedGrant(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
		return 1
	}
	key, err := loadEd25519PublicKey(*publicKey, *publicKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
		return 1
	}
	resolvedCookieHash := ""
	if *cookie != "" || *cookieFile != "" || *cookieHash != "" {
		resolvedCookieHash, err = resolveProofCookieHash(*cookie, *cookieFile, *cookieHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
			return 2
		}
	}
	resolvedChainHash := ""
	if *nodesText != "" || *chainRef != "" || *chainHash != "" {
		resolvedChainHash, err = resolveProofChainHash(*nodesText, *chainRef, *chainHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
			return 2
		}
	}
	grant, err := authproof.VerifySignedGrant(signed, key, authproof.VerifyOptions{
		Now:                  time.Now(),
		Audience:             strings.TrimSpace(*audience),
		SubjectPeerID:        strings.TrimSpace(*subject),
		RequiredCapabilities: normalizedUniqueStrings(capabilities),
		SecurityLevel:        strings.TrimSpace(*securityLevel),
		X11CookieSHA256:      resolvedCookieHash,
		ChainSHA256:          resolvedChainHash,
		MaxTTL:               *maxTTL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
		return 1
	}
	summary, err := summarizeSignedGrant(signed, grant, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof verify: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(summary)
	}
	printAuthproofSummary(summary)
	return 0
}

func cmdAuthproofShow(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("authproof show", flag.ContinueOnError)
	filePath := fs.String("file", "", "signed proof JSON file")
	inline := fs.String("proof", "", "inline signed proof JSON")
	jsonOut := fs.Bool("json", false, "emit normalized signed proof JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if strings.TrimSpace(*filePath) == "" && len(operands) == 1 {
		*filePath = operands[0]
	} else if len(operands) != 0 {
		return 2
	}
	signed, err := loadSignedGrant(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof show: %v\n", err)
		return 1
	}
	grant := signed.Grant.Normalized()
	if err := grant.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "authproof show: %v\n", err)
		return 1
	}
	if err := validateEncodedEd25519Signature(signed.Signature); err != nil {
		fmt.Fprintf(os.Stderr, "authproof show: %v\n", err)
		return 1
	}
	if *jsonOut {
		signed.Grant = grant
		return printJSON(signed)
	}
	summary, err := summarizeSignedGrant(signed, grant, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof show: %v\n", err)
		return 1
	}
	printAuthproofSummary(summary)
	fmt.Println("signature: unverified")
	return 0
}

func cmdAuthproofHashCookie(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("authproof hash-cookie", flag.ContinueOnError)
	cookie := fs.String("cookie", "", "raw X11 cookie")
	filePath := fs.String("file", "", "file containing raw X11 cookie")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if *cookie == "" && *filePath == "" && len(operands) == 1 {
		*cookie = operands[0]
	} else if len(operands) != 0 {
		return 2
	}
	hash, err := resolveProofCookieHash(*cookie, *filePath, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof hash-cookie: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(map[string]string{"x11_cookie_sha256": hash})
	}
	fmt.Println(hash)
	return 0
}

func cmdAuthproofHashChain(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("authproof hash-chain", flag.ContinueOnError)
	chainRef := fs.String("chain", "", "stored chain label or number")
	nodesText := fs.String("nodes", "", "comma/arrow-separated nodes")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if *chainRef == "" && *nodesText == "" && len(operands) == 1 {
		*nodesText = operands[0]
	} else if len(operands) != 0 {
		return 2
	}
	hash, err := resolveProofChainHash(*nodesText, *chainRef, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "authproof hash-chain: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(map[string]string{"chain_sha256": hash})
	}
	fmt.Println(hash)
	return 0
}

func loadSignedGrant(inline, filePath string) (authproof.SignedGrant, error) {
	raw := strings.TrimSpace(inline)
	if raw == "" {
		if strings.TrimSpace(filePath) == "" {
			return authproof.SignedGrant{}, errors.New("missing signed proof")
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return authproof.SignedGrant{}, err
		}
		raw = string(data)
	}
	var signed authproof.SignedGrant
	if err := decodeStrictJSON([]byte(raw), &signed); err != nil {
		return authproof.SignedGrant{}, err
	}
	return signed, nil
}

func validateEncodedEd25519Signature(encoded string) error {
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(signature) != 64 {
		return fmt.Errorf("invalid Ed25519 signature length %d", len(signature))
	}
	return nil
}

func resolveProofCookieHash(cookie, cookieFile, precomputed string) (string, error) {
	if value := strings.ToLower(strings.TrimSpace(precomputed)); value != "" {
		return validateSHA256Text("x11 cookie", value)
	}
	raw := strings.TrimSpace(cookie)
	if raw == "" && strings.TrimSpace(cookieFile) != "" {
		data, err := os.ReadFile(cookieFile)
		if err != nil {
			return "", err
		}
		raw = strings.TrimSpace(string(data))
	}
	if raw == "" {
		return "", errors.New("x11 cookie or x11 cookie SHA-256 is required")
	}
	return authproof.HashX11Cookie(raw), nil
}

func resolveProofChainHash(nodesText, chainRef, precomputed string) (string, error) {
	if value := strings.ToLower(strings.TrimSpace(precomputed)); value != "" {
		return validateSHA256Text("chain", value)
	}
	nodes, _, err := resolveNodeContextNodes(nodesText, chainRef)
	if err != nil {
		return "", err
	}
	return authproof.ChainBindingSHA256(nodes...), nil
}

func validateSHA256Text(label, value string) (string, error) {
	if len(value) != 64 {
		return "", fmt.Errorf("%s SHA-256 must be 64 lowercase hex characters", label)
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return "", fmt.Errorf("%s SHA-256 must be lowercase hexadecimal", label)
		}
	}
	return value, nil
}

func summarizeSignedGrant(signed authproof.SignedGrant, grant authproof.Grant, verified bool) (authproofSummary, error) {
	normalized := grant.Normalized()
	signed.Grant = normalized
	payload, err := json.Marshal(signed)
	if err != nil {
		return authproofSummary{}, err
	}
	caps := append([]string(nil), normalized.Capabilities...)
	sort.Strings(caps)
	return authproofSummary{
		Valid:         true,
		Verified:      verified,
		ProofSHA256:   authproof.SHA256Hex(payload),
		Issuer:        normalized.IssuerPeerID,
		Subject:       normalized.SubjectPeerID,
		Audience:      normalized.Audience,
		SessionID:     normalized.SessionID,
		Capabilities:  caps,
		SecurityLevel: normalized.SecurityLevel,
		CookieSHA256:  normalized.X11CookieSHA256,
		ChainSHA256:   normalized.ChainSHA256,
		IssuedAt:      time.Unix(normalized.IssuedAtUnix, 0).Format(time.RFC3339),
		ExpiresAt:     time.Unix(normalized.ExpiresAtUnix, 0).Format(time.RFC3339),
		TTL:           (time.Duration(normalized.ExpiresAtUnix-normalized.IssuedAtUnix) * time.Second).String(),
	}, nil
}

func printAuthproofSummary(summary authproofSummary) {
	fmt.Printf("valid:        %t\n", summary.Valid)
	fmt.Printf("verified:     %t\n", summary.Verified)
	fmt.Printf("proof-sha256: %s\n", summary.ProofSHA256)
	fmt.Printf("issuer:       %s\n", summary.Issuer)
	fmt.Printf("subject:      %s\n", summary.Subject)
	fmt.Printf("audience:     %s\n", summary.Audience)
	fmt.Printf("session:      %s\n", summary.SessionID)
	fmt.Printf("capabilities: %s\n", strings.Join(summary.Capabilities, ","))
	if summary.SecurityLevel != "" {
		fmt.Printf("security:     %s\n", summary.SecurityLevel)
	}
	fmt.Printf("cookie-hash:  %s\n", summary.CookieSHA256)
	fmt.Printf("chain-hash:   %s\n", summary.ChainSHA256)
	fmt.Printf("issued:       %s\n", summary.IssuedAt)
	fmt.Printf("expires:      %s\n", summary.ExpiresAt)
	fmt.Printf("ttl:          %s\n", summary.TTL)
}

func printAuthproofUsage() {
	fmt.Print(`wv authproof - issue and inspect weaverssh.auth.v1 runtime grants

Usage:
  wv authproof issue --issuer ID --subject ID [binding and signer flags]
  wv authproof verify PROOF.json --public-key-file KEY [expected binding flags]
  wv authproof show PROOF.json [--json]
  wv authproof hash-cookie COOKIE
  wv authproof hash-chain --chain LABEL
  wv authproof hash-chain --nodes origin,jump,endpoint

Signer providers:
  key        Ed25519 private key from --private-key[-file]
  ssh-agent  Ed25519 identity selected from SSH_AUTH_SOCK
  gpg-agent  Ed25519 identity selected from the gpg-agent SSH socket

Issue requires an X11 cookie hash and chain hash. Raw cookies and stored chains may
be supplied and are hashed locally. Output files are mode 0600 and are not
replaced unless --force is set.
`)
}
