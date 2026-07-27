package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/vfs"
	"weaverssh/internal/vfscli"
)

func runVFSCommand(args []string) int {
	if err := hydrateVFSNodeRefEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "node-context: %v\n", err)
		return 1
	}
	return vfscli.Main("wtool", args)
}

func hydrateVFSNodeRefEnv() error {
	if ok, err := hydrateSignedNodeContextEnv(); ok || err != nil {
		return err
	}
	store, err := loadConnStore()
	if err != nil {
		return err
	}
	chain, _, ok := resolveChain(store, "")
	if !ok || len(chain.Nodes) == 0 {
		return nil
	}
	nodes := normalizeNodeList(chain.Nodes)
	if len(nodes) == 0 {
		return nil
	}
	setEnvIfAllEmpty(chain.Label, envChainID)
	setEnvIfAllEmpty(strings.Join(nodes, ","), vfs.EnvChainNodes)
	setEnvIfAllEmpty(nodes[0], vfs.EnvOriginNode, vfs.EnvOriginNodeShort)
	setEnvIfAllEmpty(nodes[len(nodes)-1], vfs.EnvEndpointNode, vfs.EnvEndpointNodeShort)
	if current := detectCurrentChainNode(nodes); current != "" {
		setEnvIfAllEmpty(current, vfs.EnvCurrentNode, vfs.EnvCurrentNodeShort)
	}
	return nil
}

func hydrateSignedNodeContextEnv() (bool, error) {
	inline := strings.TrimSpace(os.Getenv(envNodeContext))
	filePath := strings.TrimSpace(os.Getenv(envNodeContextFile))
	publicKey := strings.TrimSpace(os.Getenv(envNodeContextPublicKey))
	publicKeyFile := strings.TrimSpace(os.Getenv(envNodeContextPublicKeyFile))
	configured := inline != "" || filePath != "" || publicKey != "" || publicKeyFile != ""
	if !configured {
		return false, nil
	}
	if inline == "" && filePath == "" {
		return true, fmt.Errorf("%s or %s is required when node-context verification is configured", envNodeContext, envNodeContextFile)
	}
	if publicKey == "" && publicKeyFile == "" {
		return true, fmt.Errorf("%s or %s is required to verify signed node context", envNodeContextPublicKey, envNodeContextPublicKeyFile)
	}
	signed, err := loadSignedNodeContext(inline, filePath)
	if err != nil {
		return true, err
	}
	key, err := loadEd25519PublicKey(publicKey, publicKeyFile)
	if err != nil {
		return true, err
	}
	ctx, err := authproof.VerifySignedNodeContext(signed, key, authproof.NodeContextVerifyOptions{
		Now:      time.Now(),
		Audience: authproof.AudienceNodeContext,
		MaxTTL:   10 * time.Minute,
	})
	if err != nil {
		return true, err
	}
	applySignedNodeContextEnv(ctx)
	return true, nil
}

func applySignedNodeContextEnv(ctx authproof.NodeContext) {
	ctx = ctx.Normalized()
	setEnvForce(strings.Join(ctx.Nodes, ","), vfs.EnvChainNodes)
	setEnvForce(ctx.OriginNode, vfs.EnvOriginNode)
	setEnvForce(ctx.EndpointNode, vfs.EnvEndpointNode)
	setEnvForce(ctx.CurrentNode, vfs.EnvCurrentNode)
	setEnvForce(ctx.ChainID, envChainID)
}

func setEnvIfAllEmpty(value string, keys ...string) {
	if strings.TrimSpace(value) == "" || len(keys) == 0 {
		return
	}
	for _, key := range keys {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return
		}
	}
	_ = os.Setenv(keys[0], value)
}

func setEnvForce(value, key string) {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(key) == "" {
		return
	}
	_ = os.Setenv(key, value)
}

func detectCurrentChainNode(nodes []string) string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	candidates := map[string]bool{host: true}
	if short, _, ok := strings.Cut(host, "."); ok && short != "" {
		candidates[short] = true
	}
	for _, node := range nodes {
		if candidates[strings.ToLower(node)] {
			return node
		}
	}
	return ""
}
