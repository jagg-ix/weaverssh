package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
)

// cmdNodeContextSignServices signs a node context with an explicit capability
// set. It is intentionally separate from the compatibility sign command, whose
// historical default remains node.context + vfs.mesh.
func cmdNodeContextSignServices(args []string) int {
	fs := flag.NewFlagSet("node-context sign-services", flag.ContinueOnError)
	chainRef := fs.String("chain", "", "stored chain label or number (default: active chain)")
	nodesText := fs.String("nodes", "", "comma-separated node list, used instead of --chain")
	currentNode := fs.String("node", firstNodeEnv(), "current node name")
	issuer := fs.String("issuer", defaultNodeContextIssuer(), "issuer peer id")
	capabilitiesText := fs.String("capabilities", "", "comma-separated capabilities: node.context,vfs.mesh,file.backhaul,socks.proxy")
	privateKey := fs.String("private-key", "", "base64url/base64/hex Ed25519 private key")
	privateKeyFile := fs.String("private-key-file", "", "file containing Ed25519 private key")
	ttl := fs.Duration("ttl", 5*time.Minute, "node context validity duration")
	outPath := fs.String("out", "", "write signed context JSON to FILE instead of stdout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv node-context sign-services --capabilities LIST [--nodes A,B] --private-key-file KEY [--node NODE] [--out FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	capabilities, err := parseNodeCapabilities(*capabilitiesText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: %v\n", err)
		return 2
	}
	nodes, chainID, err := resolveNodeContextNodes(*nodesText, *chainRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "node-context sign-services: current node %q is not in chain %s\n", current, strings.Join(nodes, ","))
		return 2
	}
	key, err := loadEd25519PrivateKey(*privateKey, *privateKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: %v\n", err)
		return 1
	}
	nonce, err := authproof.NewRandomNonce(24)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: nonce: %v\n", err)
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
		Capabilities:  capabilities,
		Nonce:         nonce,
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(*ttl).Unix(),
	}
	signed, err := authproof.SignNodeContext(ctx, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: %v\n", err)
		return 1
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "node-context sign-services: marshal: %v\n", err)
		return 1
	}
	data = append(data, '\n')
	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(*outPath, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "node-context sign-services: write %s: %v\n", *outPath, err)
			return 1
		}
		fmt.Printf("node-context: wrote %s\n", *outPath)
		return 0
	}
	fmt.Print(string(data))
	return 0
}

func parseNodeCapabilities(raw string) ([]string, error) {
	allowed := map[string]bool{
		authproof.CapabilityNodeContext:  true,
		authproof.CapabilityVFSMesh:      true,
		authproof.CapabilityFileBackhaul: true,
		authproof.CapabilitySocksProxy:   true,
	}
	seen := map[string]bool{}
	var capabilities []string
	for _, field := range strings.Split(raw, ",") {
		capability := strings.TrimSpace(field)
		if capability == "" {
			continue
		}
		if !allowed[capability] {
			return nil, fmt.Errorf("unknown or unsupported capability %q", capability)
		}
		if !seen[capability] {
			seen[capability] = true
			capabilities = append(capabilities, capability)
		}
	}
	if !seen[authproof.CapabilityNodeContext] {
		capabilities = append(capabilities, authproof.CapabilityNodeContext)
	}
	if len(capabilities) == 1 {
		return capabilities, nil
	}
	return capabilities, nil
}
