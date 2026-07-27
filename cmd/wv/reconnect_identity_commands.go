package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
)

type reconnectIdentitySummary struct {
	Valid         bool     `json:"valid"`
	Verified      bool     `json:"verified"`
	Digest        string   `json:"reconnect_identity_sha256"`
	ChainID       string   `json:"chain_id"`
	ChainSHA256   string   `json:"chain_sha256"`
	Nodes         []string `json:"nodes"`
	CurrentNode   string   `json:"current_node"`
	NodeKeySHA256 string   `json:"node_key_sha256"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	TTL           string   `json:"ttl"`
	PrivateMatch  *bool    `json:"private_key_matches,omitempty"`
}

func cmdReconnectIdentity(args []string) int {
	if len(args) == 0 {
		printReconnectIdentityUsage()
		return 2
	}
	switch args[0] {
	case "issue", "sign", "create":
		return cmdReconnectIdentityIssue(args[1:])
	case "verify", "check":
		return cmdReconnectIdentityVerify(args[1:])
	case "show", "inspect":
		return cmdReconnectIdentityShow(args[1:])
	case "digest", "sha256":
		return cmdReconnectIdentityDigest(args[1:])
	case "keygen":
		return cmdReconnectIdentityKeygen(args[1:])
	case "help", "-h", "--help":
		printReconnectIdentityUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "reconnect-identity: unknown command %q\n", args[0])
		printReconnectIdentityUsage()
		return 2
	}
}

func cmdReconnectIdentityIssue(args []string) int {
	fs := flag.NewFlagSet("reconnect-identity issue", flag.ContinueOnError)
	contextFile := fs.String("node-context", "", "authority-signed node-context JSON file")
	contextInline := fs.String("node-context-json", "", "inline authority-signed node-context JSON")
	authorityPrivate := fs.String("authority-private-key", "", "inline authority Ed25519 private key")
	authorityPrivateFile := fs.String("authority-private-key-file", "", "authority Ed25519 private-key file")
	nodePrivate := fs.String("node-private-key", "", "inline certified node Ed25519 private key")
	nodePrivateFile := fs.String("node-private-key-file", "", "certified node Ed25519 private-key file")
	nodePublic := fs.String("node-public-key", "", "inline certified node Ed25519 public key")
	nodePublicFile := fs.String("node-public-key-file", "", "certified node Ed25519 public-key file")
	maxTTL := fs.Duration("max-context-ttl", 24*time.Hour, "maximum accepted embedded node-context TTL")
	currentNode := fs.String("node", "", "expected current node")
	out := fs.String("out", "", "write signed reconnect identity JSON to file")
	force := fs.Bool("force", false, "replace existing output file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv reconnect-identity issue --node-context CONTEXT.json --authority-private-key-file AUTH.key (--node-private-key-file NODE.key|--node-public-key-file NODE.pub) [--out FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	signedContext, err := loadSignedNodeContext(*contextInline, *contextFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	authorityKey, err := loadEd25519PrivateKey(*authorityPrivate, *authorityPrivateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	authorityPublic, ok := authorityKey.Public().(ed25519.PublicKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "reconnect-identity issue: authority key is not Ed25519")
		return 1
	}
	context, err := authproof.VerifySignedNodeContext(signedContext, authorityPublic, authproof.NodeContextVerifyOptions{
		Now:         time.Now(),
		Audience:    authproof.AudienceNodeContext,
		CurrentNode: strings.TrimSpace(*currentNode),
		MaxTTL:      *maxTTL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: verify node context: %v\n", err)
		return 1
	}
	nodeKey, err := resolveReconnectNodePublicKey(*nodePrivate, *nodePrivateFile, *nodePublic, *nodePublicFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	identity, err := authproof.NewReconnectIdentity(context, nodeKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	signed, err := authproof.SignReconnectIdentity(identity, authorityKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*out) == "" {
		if err := emitJSONArtifact(os.Stdout, signed); err != nil {
			fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeJSONArtifact(*out, signed, 0o600, *force); err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity issue: %v\n", err)
		return 1
	}
	fmt.Printf("reconnect-identity: wrote %s\n", *out)
	return 0
}

func cmdReconnectIdentityVerify(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("reconnect-identity verify", flag.ContinueOnError)
	filePath := fs.String("file", "", "signed reconnect identity JSON file")
	inline := fs.String("identity", "", "inline signed reconnect identity JSON")
	authorityPublic := fs.String("authority-public-key", "", "inline authority Ed25519 public key")
	authorityPublicFile := fs.String("authority-public-key-file", "", "authority Ed25519 public-key file")
	chainID := fs.String("chain-id", "", "expected chain id")
	chainSHA := fs.String("chain-sha256", "", "expected chain SHA-256")
	currentNode := fs.String("node", "", "expected current node")
	maxTTL := fs.Duration("max-ttl", 24*time.Hour, "maximum accepted embedded context TTL")
	nodePrivate := fs.String("node-private-key", "", "optional inline node private key to match")
	nodePrivateFile := fs.String("node-private-key-file", "", "optional node private-key file to match")
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv reconnect-identity verify IDENTITY.json --authority-public-key-file AUTH.pub [expected binding flags]")
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
	signed, err := loadSignedReconnectIdentity(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
		return 1
	}
	key, err := loadEd25519PublicKey(*authorityPublic, *authorityPublicFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
		return 1
	}
	identity, err := authproof.VerifySignedReconnectIdentity(signed, key, authproof.ReconnectIdentityVerifyOptions{
		Now:         time.Now(),
		Audience:    authproof.AudienceReconnectIdentity,
		ChainID:     strings.TrimSpace(*chainID),
		ChainSHA256: strings.TrimSpace(*chainSHA),
		CurrentNode: strings.TrimSpace(*currentNode),
		MaxTTL:      *maxTTL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
		return 1
	}
	var privateMatch *bool
	if *nodePrivate != "" || *nodePrivateFile != "" {
		privateKey, err := loadEd25519PrivateKey(*nodePrivate, *nodePrivateFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
			return 1
		}
		certified, err := identity.PublicKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
			return 1
		}
		derived, _ := privateKey.Public().(ed25519.PublicKey)
		matched := bytes.Equal(certified, derived)
		privateMatch = &matched
		if !matched {
			fmt.Fprintln(os.Stderr, "reconnect-identity verify: node private key does not match certified public key")
			return 1
		}
	}
	summary, err := summarizeReconnectIdentity(signed, identity, true, privateMatch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity verify: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(summary)
	}
	printReconnectIdentitySummary(summary)
	return 0
}

func cmdReconnectIdentityShow(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("reconnect-identity show", flag.ContinueOnError)
	filePath := fs.String("file", "", "signed reconnect identity JSON file")
	inline := fs.String("identity", "", "inline signed reconnect identity JSON")
	jsonOut := fs.Bool("json", false, "emit normalized signed identity JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if strings.TrimSpace(*filePath) == "" && len(operands) == 1 {
		*filePath = operands[0]
	} else if len(operands) != 0 {
		return 2
	}
	signed, err := loadSignedReconnectIdentity(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity show: %v\n", err)
		return 1
	}
	identity := signed.Identity.Normalized()
	if err := identity.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity show: %v\n", err)
		return 1
	}
	if err := validateEncodedEd25519Signature(signed.Signature); err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity show: %v\n", err)
		return 1
	}
	if *jsonOut {
		signed.Identity = identity
		return printJSON(signed)
	}
	summary, err := summarizeReconnectIdentity(signed, identity, false, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity show: %v\n", err)
		return 1
	}
	printReconnectIdentitySummary(summary)
	fmt.Println("signature: unverified")
	return 0
}

func cmdReconnectIdentityDigest(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("reconnect-identity digest", flag.ContinueOnError)
	filePath := fs.String("file", "", "signed reconnect identity JSON file")
	inline := fs.String("identity", "", "inline signed reconnect identity JSON")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if strings.TrimSpace(*filePath) == "" && len(operands) == 1 {
		*filePath = operands[0]
	} else if len(operands) != 0 {
		return 2
	}
	signed, err := loadSignedReconnectIdentity(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity digest: %v\n", err)
		return 1
	}
	digest, err := authproof.ReconnectIdentitySHA256(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconnect-identity digest: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(map[string]string{"reconnect_identity_sha256": digest})
	}
	fmt.Println(digest)
	return 0
}

func cmdReconnectIdentityKeygen(args []string) int {
	hasPrivate, hasPublic := false, false
	for _, arg := range args {
		if arg == "--private" || arg == "-private" || strings.HasPrefix(arg, "--private=") || strings.HasPrefix(arg, "-private=") {
			hasPrivate = true
		}
		if arg == "--public" || arg == "-public" || strings.HasPrefix(arg, "--public=") || strings.HasPrefix(arg, "-public=") {
			hasPublic = true
		}
	}
	prefix := make([]string, 0, 4+len(args))
	if !hasPrivate {
		prefix = append(prefix, "--private", "node-reconnect.key")
	}
	if !hasPublic {
		prefix = append(prefix, "--public", "node-reconnect.key.pub")
	}
	return cmdKeygen(append(prefix, args...))
}

func loadSignedReconnectIdentity(inline, filePath string) (authproof.SignedReconnectIdentity, error) {
	raw := strings.TrimSpace(inline)
	if raw == "" {
		if strings.TrimSpace(filePath) == "" {
			return authproof.SignedReconnectIdentity{}, errors.New("missing signed reconnect identity")
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return authproof.SignedReconnectIdentity{}, err
		}
		raw = string(data)
	}
	var signed authproof.SignedReconnectIdentity
	if err := decodeStrictJSON([]byte(raw), &signed); err != nil {
		return authproof.SignedReconnectIdentity{}, err
	}
	return signed, nil
}

func resolveReconnectNodePublicKey(privateInline, privateFile, publicInline, publicFile string) (ed25519.PublicKey, error) {
	hasPrivate := strings.TrimSpace(privateInline) != "" || strings.TrimSpace(privateFile) != ""
	hasPublic := strings.TrimSpace(publicInline) != "" || strings.TrimSpace(publicFile) != ""
	if !hasPrivate && !hasPublic {
		return nil, errors.New("node private or public key is required")
	}
	var derived ed25519.PublicKey
	if hasPrivate {
		privateKey, err := loadEd25519PrivateKey(privateInline, privateFile)
		if err != nil {
			return nil, err
		}
		derived, _ = privateKey.Public().(ed25519.PublicKey)
	}
	if !hasPublic {
		return derived, nil
	}
	provided, err := loadEd25519PublicKey(publicInline, publicFile)
	if err != nil {
		return nil, err
	}
	if hasPrivate && !bytes.Equal(derived, provided) {
		return nil, errors.New("node private and public keys do not match")
	}
	return provided, nil
}

func summarizeReconnectIdentity(signed authproof.SignedReconnectIdentity, identity authproof.ReconnectIdentity, verified bool, privateMatch *bool) (reconnectIdentitySummary, error) {
	digest, err := authproof.ReconnectIdentitySHA256(signed)
	if err != nil {
		return reconnectIdentitySummary{}, err
	}
	context := identity.Context.Normalized()
	return reconnectIdentitySummary{
		Valid:         true,
		Verified:      verified,
		Digest:        digest,
		ChainID:       context.ChainID,
		ChainSHA256:   context.ChainSHA256,
		Nodes:         append([]string(nil), context.Nodes...),
		CurrentNode:   context.CurrentNode,
		NodeKeySHA256: identity.NodeKeySHA256,
		IssuedAt:      time.Unix(context.IssuedAtUnix, 0).Format(time.RFC3339),
		ExpiresAt:     time.Unix(context.ExpiresAtUnix, 0).Format(time.RFC3339),
		TTL:           (time.Duration(context.ExpiresAtUnix-context.IssuedAtUnix) * time.Second).String(),
		PrivateMatch:  privateMatch,
	}, nil
}

func printReconnectIdentitySummary(summary reconnectIdentitySummary) {
	fmt.Printf("valid:        %t\n", summary.Valid)
	fmt.Printf("verified:     %t\n", summary.Verified)
	fmt.Printf("identity-sha: %s\n", summary.Digest)
	fmt.Printf("chain:        %s\n", summary.ChainID)
	fmt.Printf("chain-sha:    %s\n", summary.ChainSHA256)
	fmt.Printf("nodes:        %s\n", strings.Join(summary.Nodes, " -> "))
	fmt.Printf("current:      %s\n", summary.CurrentNode)
	fmt.Printf("node-key-sha: %s\n", summary.NodeKeySHA256)
	fmt.Printf("issued:       %s\n", summary.IssuedAt)
	fmt.Printf("expires:      %s\n", summary.ExpiresAt)
	fmt.Printf("ttl:          %s\n", summary.TTL)
	if summary.PrivateMatch != nil {
		fmt.Printf("private-key:  matches=%t\n", *summary.PrivateMatch)
	}
}

func printReconnectIdentityUsage() {
	fmt.Print(`wv reconnect-identity - manage challenge-bound reconnect credentials

Usage:
  wv reconnect-identity keygen [--private FILE] [--public FILE]
  wv reconnect-identity issue --node-context CONTEXT.json --authority-private-key-file AUTH.key --node-private-key-file NODE.key [--out FILE]
  wv reconnect-identity verify IDENTITY.json --authority-public-key-file AUTH.pub [--node NODE] [--node-private-key-file NODE.key]
  wv reconnect-identity show IDENTITY.json [--json]
  wv reconnect-identity digest IDENTITY.json

The embedded node context is verified before issuance. The certified node public
key is digest-bound into the identity. Output files are mode 0600 and are not
replaced unless --force is set.
`)
}
