package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/vfs"
)

const (
	envNodeContext              = "WEAVERSSH_NODE_CONTEXT"
	envNodeContextFile          = "WEAVERSSH_NODE_CONTEXT_FILE"
	envNodeContextPublicKey     = "WEAVERSSH_NODE_CONTEXT_PUBLIC_KEY"
	envNodeContextPublicKeyFile = "WEAVERSSH_NODE_CONTEXT_PUBLIC_KEY_FILE"
	envChainID                  = "WEAVERSSH_CHAIN_ID"
)

func cmdNodeContext(args []string) int {
	if len(args) == 0 {
		printNodeContextUsage()
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "sign", "export":
		return cmdNodeContextSign(rest)
	case "verify", "show", "env":
		return cmdNodeContextVerify(sub, rest)
	case "status", "whoami", "identity":
		return cmdNodeContextStatus(rest)
	case "help", "-h", "--help":
		printNodeContextUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "node-context: unknown subcommand %q\n", sub)
		printNodeContextUsage()
		return 2
	}
}

func printNodeContextUsage() {
	fmt.Fprintln(os.Stderr, "usage: wv node-context sign   [--chain NAME|--nodes A,B,C] --private-key-file KEY [--node NODE] [--out FILE]")
	fmt.Fprintln(os.Stderr, "       wv node-context verify --file FILE --public-key-file PUB [--env|--json]")
	fmt.Fprintln(os.Stderr, "       wv node-context env    --file FILE --public-key-file PUB")
	fmt.Fprintln(os.Stderr, "       wv node-context status [--json]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Creates or verifies a signed, short-lived node context for resolving origin/self/endpoint safely.")
}

func cmdNodeContextSign(args []string) int {
	fs := flag.NewFlagSet("node-context sign", flag.ContinueOnError)
	chainRef := fs.String("chain", "", "stored chain label or number (default: active chain)")
	nodesText := fs.String("nodes", "", "comma-separated node list, used instead of --chain")
	currentNode := fs.String("node", firstNodeEnv(), "current node name (default: WV_NODE/WEAVERSSH_NODE_ID or detected node)")
	issuer := fs.String("issuer", defaultNodeContextIssuer(), "issuer peer id")
	privateKey := fs.String("private-key", "", "base64url/base64/hex Ed25519 private key")
	privateKeyFile := fs.String("private-key-file", "", "file containing Ed25519 private key")
	ttl := fs.Duration("ttl", 5*time.Minute, "node context validity duration")
	outPath := fs.String("out", "", "write signed context JSON to FILE instead of stdout")
	jsonOut := fs.Bool("json", true, "emit JSON (reserved for CLI consistency)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv node-context sign [--chain NAME|--nodes A,B,C] --private-key-file KEY [--node NODE] [--out FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	nodes, chainID, err := resolveNodeContextNodes(*nodesText, *chainRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign: %v\n", err)
		return 1
	}
	current := strings.TrimSpace(*currentNode)
	if current == "" {
		current = detectCurrentChainNode(nodes)
	}
	if current == "" {
		current = nodes[0]
	}
	if !stringInSlice(nodes, current) {
		fmt.Fprintf(os.Stderr, "node-context sign: current node %q is not in chain %s\n", current, strings.Join(nodes, ","))
		return 2
	}
	key, err := loadEd25519PrivateKey(*privateKey, *privateKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign: %v\n", err)
		return 1
	}
	nonce, err := authproof.NewRandomNonce(24)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign: nonce: %v\n", err)
		return 1
	}
	now := time.Now()
	ctx := authproof.NodeContext{
		IssuerPeerID:  *issuer,
		Audience:      authproof.AudienceNodeContext,
		ChainID:       chainID,
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   current,
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         nonce,
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(*ttl).Unix(),
	}
	signed, err := authproof.SignNodeContext(ctx, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign: %v\n", err)
		return 1
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign: marshal: %v\n", err)
		return 1
	}
	data = append(data, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "node-context sign: write %s: %v\n", *outPath, err)
			return 1
		}
		fmt.Printf("node-context: wrote %s\n", *outPath)
		return 0
	}
	if !*jsonOut {
		fmt.Printf("chain: %s\n", signed.Context.ChainID)
		fmt.Printf("nodes: %s\n", strings.Join(signed.Context.Nodes, " -> "))
		fmt.Printf("current: %s\n", signed.Context.CurrentNode)
		return 0
	}
	fmt.Print(string(data))
	return 0
}

func cmdNodeContextVerify(mode string, args []string) int {
	fs := flag.NewFlagSet("node-context verify", flag.ContinueOnError)
	inline := fs.String("context", "", "inline signed node-context JSON")
	filePath := fs.String("file", "", "signed node-context JSON file")
	publicKey := fs.String("public-key", "", "base64url/base64/hex/OpenSSH Ed25519 public key")
	publicKeyFile := fs.String("public-key-file", "", "file containing trusted Ed25519 public key")
	chainRef := fs.String("chain", "", "stored chain label/number to verify chain binding")
	currentNode := fs.String("node", "", "expected current node")
	maxTTL := fs.Duration("max-ttl", 10*time.Minute, "maximum accepted context TTL")
	envOut := fs.Bool("env", mode == "env", "print shell exports after verification")
	jsonOut := fs.Bool("json", false, "print verified context JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv node-context verify --file FILE --public-key-file PUB [--env|--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	signed, err := loadSignedNodeContext(*inline, *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context verify: %v\n", err)
		return 1
	}
	key, err := loadEd25519PublicKey(*publicKey, *publicKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context verify: %v\n", err)
		return 1
	}
	opts := authproof.NodeContextVerifyOptions{
		Now:      time.Now(),
		Audience: authproof.AudienceNodeContext,
		MaxTTL:   *maxTTL,
	}
	if strings.TrimSpace(*chainRef) != "" {
		store, err := loadConnStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "node-context verify: %v\n", err)
			return 1
		}
		chain, _, ok := resolveChain(store, *chainRef)
		if !ok {
			fmt.Fprintf(os.Stderr, "node-context verify: chain %q not found\n", *chainRef)
			return 1
		}
		nodes := normalizeNodeList(chain.Nodes)
		opts.ChainID = chain.Label
		opts.ChainSHA256 = authproof.ChainBindingSHA256(nodes...)
	}
	if strings.TrimSpace(*currentNode) != "" {
		opts.CurrentNode = strings.TrimSpace(*currentNode)
	}
	ctx, err := authproof.VerifySignedNodeContext(signed, key, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context verify: %v\n", err)
		return 1
	}
	if *envOut {
		printNodeContextEnv(ctx)
		return 0
	}
	if *jsonOut {
		return printJSON(ctx)
	}
	fmt.Println("node-context: verified")
	fmt.Printf("chain:    %s\n", ctx.ChainID)
	fmt.Printf("nodes:    %s\n", strings.Join(ctx.Nodes, " -> "))
	fmt.Printf("origin:   %s\n", ctx.OriginNode)
	fmt.Printf("current:  %s\n", ctx.CurrentNode)
	fmt.Printf("endpoint: %s\n", ctx.EndpointNode)
	fmt.Printf("expires:  %s\n", time.Unix(ctx.ExpiresAtUnix, 0).Format(time.RFC3339))
	return 0
}

type nodeContextStatusPayload struct {
	ChainID      string   `json:"chain_id,omitempty"`
	Nodes        []string `json:"nodes"`
	OriginNode   string   `json:"origin_node"`
	CurrentNode  string   `json:"current_node,omitempty"`
	EndpointNode string   `json:"endpoint_node"`
	Source       string   `json:"source"`
	Trusted      bool     `json:"trusted"`
}

func cmdNodeContextStatus(args []string) int {
	fs := flag.NewFlagSet("node-context status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv node-context status [--json]")
		fmt.Fprintln(os.Stderr, "  Shows the resolved origin/current/endpoint identity for this node.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	payload, err := resolvedNodeContextStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context status: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(payload)
	}
	fmt.Printf("source:   %s\n", payload.Source)
	if payload.Trusted {
		fmt.Printf("trusted:  yes\n")
	} else {
		fmt.Printf("trusted:  no\n")
	}
	if payload.ChainID != "" {
		fmt.Printf("chain:    %s\n", payload.ChainID)
	}
	fmt.Printf("nodes:    %s\n", strings.Join(payload.Nodes, " -> "))
	fmt.Printf("origin:   %s\n", payload.OriginNode)
	if payload.CurrentNode != "" {
		fmt.Printf("current:  %s\n", payload.CurrentNode)
	}
	fmt.Printf("endpoint: %s\n", payload.EndpointNode)
	return 0
}

func resolvedNodeContextStatus() (nodeContextStatusPayload, error) {
	if ok, err := hydrateSignedNodeContextEnv(); err != nil {
		return nodeContextStatusPayload{}, err
	} else if ok {
		return nodeContextStatusFromEnv("signed-node-context", true), nil
	}
	if err := hydrateVFSNodeRefEnv(); err != nil {
		return nodeContextStatusPayload{}, err
	}
	payload := nodeContextStatusFromEnv("active-chain", false)
	if payload.OriginNode == "" || payload.EndpointNode == "" || len(payload.Nodes) == 0 {
		return nodeContextStatusPayload{}, fmt.Errorf("no node context available; set %s/%s with a signed context or configure `wv connections --nodes ... --active`", envNodeContextFile, envNodeContextPublicKeyFile)
	}
	return payload, nil
}

func nodeContextStatusFromEnv(source string, trusted bool) nodeContextStatusPayload {
	nodes := normalizeNodeList(splitChainNodes(os.Getenv(vfs.EnvChainNodes)))
	origin := strings.TrimSpace(os.Getenv(vfs.EnvOriginNode))
	current := strings.TrimSpace(os.Getenv(vfs.EnvCurrentNode))
	endpoint := strings.TrimSpace(os.Getenv(vfs.EnvEndpointNode))
	if origin == "" && len(nodes) > 0 {
		origin = nodes[0]
	}
	if endpoint == "" && len(nodes) > 0 {
		endpoint = nodes[len(nodes)-1]
	}
	if current == "" {
		current = firstNodeEnv()
	}
	return nodeContextStatusPayload{
		ChainID:      strings.TrimSpace(os.Getenv(envChainID)),
		Nodes:        nodes,
		OriginNode:   origin,
		CurrentNode:  current,
		EndpointNode: endpoint,
		Source:       source,
		Trusted:      trusted,
	}
}

func resolveNodeContextNodes(nodesText, chainRef string) ([]string, string, error) {
	if strings.TrimSpace(nodesText) != "" {
		nodes := normalizeNodeList(splitChainNodes(nodesText))
		if len(nodes) == 0 {
			return nil, "", fmt.Errorf("--nodes did not contain any valid nodes")
		}
		return nodes, "adhoc", validateChainNodes(nodes)
	}
	store, err := loadConnStore()
	if err != nil {
		return nil, "", err
	}
	chain, _, ok := resolveChain(store, chainRef)
	if !ok {
		if strings.TrimSpace(chainRef) == "" {
			return nil, "", fmt.Errorf("no active chain; pass --nodes or configure `wv connections --nodes ... --active`")
		}
		return nil, "", fmt.Errorf("chain %q not found", chainRef)
	}
	nodes := normalizeNodeList(chain.Nodes)
	if len(nodes) == 0 {
		return nil, "", fmt.Errorf("chain %q has no nodes", chain.Label)
	}
	return nodes, chain.Label, validateChainNodes(nodes)
}

func loadSignedNodeContext(inlineValue, filePath string) (authproof.SignedNodeContext, error) {
	raw := strings.TrimSpace(inlineValue)
	if raw == "" {
		if strings.TrimSpace(filePath) == "" {
			return authproof.SignedNodeContext{}, fmt.Errorf("missing signed node context")
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return authproof.SignedNodeContext{}, fmt.Errorf("read %s: %w", filePath, err)
		}
		raw = string(data)
	}
	var signed authproof.SignedNodeContext
	if err := json.Unmarshal([]byte(raw), &signed); err != nil {
		return authproof.SignedNodeContext{}, fmt.Errorf("parse signed node context: %w", err)
	}
	return signed, nil
}

func loadEd25519PrivateKey(inlineValue, filePath string) (ed25519.PrivateKey, error) {
	raw, err := loadTextValueForWV(inlineValue, filePath, "private key")
	if err != nil {
		return nil, err
	}
	return authproof.DecodePrivateKey(raw)
}

func loadEd25519PublicKey(inlineValue, filePath string) (ed25519.PublicKey, error) {
	raw, err := loadTextValueForWV(inlineValue, filePath, "public key")
	if err != nil {
		return nil, err
	}
	return authproof.DecodePublicKey(raw)
}

func loadTextValueForWV(inlineValue, filePath, label string) (string, error) {
	if strings.TrimSpace(inlineValue) != "" {
		return strings.TrimSpace(inlineValue), nil
	}
	if strings.TrimSpace(filePath) == "" {
		return "", fmt.Errorf("missing %s", label)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filePath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func firstNodeEnv() string {
	for _, key := range []string{vfs.EnvCurrentNode, vfs.EnvCurrentNodeShort} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func defaultNodeContextIssuer() string {
	if user := strings.TrimSpace(os.Getenv("USER")); user != "" {
		return "wv:" + user
	}
	return "wv:local"
}

func printNodeContextEnv(ctx authproof.NodeContext) {
	ctx = ctx.Normalized()
	for _, item := range []struct{ key, value string }{
		{envChainID, ctx.ChainID},
		{vfs.EnvChainNodes, strings.Join(ctx.Nodes, ",")},
		{vfs.EnvOriginNode, ctx.OriginNode},
		{vfs.EnvEndpointNode, ctx.EndpointNode},
		{vfs.EnvCurrentNode, ctx.CurrentNode},
	} {
		fmt.Printf("export %s=%s\n", item.key, nodeContextShellQuote(item.value))
	}
}

func nodeContextShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func stringInSlice(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
