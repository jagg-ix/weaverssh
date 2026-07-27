package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/hopproof"
	"weaverssh/sessionbroker"
	"weaverssh/sshagent"
)

type RecursiveHopConfig struct {
	NodeContext        authproof.NodeContext
	IncomingChain      string
	SigningKeyFile     string
	AllowedSignersFile string
	SSHKeygenBinary    string
	SSHAddBinary       string
	AgentAddKeyFile    string
	AgentAddLifetime   string
	AgentAddConfirm    bool
	AgentTestSign      bool
	TTL                time.Duration
	Now                time.Time
	Signer             hopproof.Signer
	Verifier           hopproof.Verifier
	AgentClient        *sshagent.Client
}

// RecursiveHopEnvironment contains both the verified ancestry of the current
// node and the newly signed environment for the next child node.
type RecursiveHopEnvironment struct {
	Origin          string
	HopChain        string
	NextNode        string
	HopDepth        int
	PreviousNode    string
	IncomingChain   string
	CurrentDepth    int
	SigningIdentity sshagent.Identity

	// Compatibility aliases retained for lifecycle callers introduced while the
	// ancestry/output distinction was being formalized.
	IncomingHopChain string
	IncomingHopDepth int
}

func PrepareRecursiveHop(ctx context.Context, config RecursiveHopConfig) (RecursiveHopEnvironment, error) {
	config = recursiveHopAgentEnvironment(config)
	nodeContext := config.NodeContext.Normalized()
	index, err := hopproof.CurrentIndex(nodeContext)
	if err != nil {
		return RecursiveHopEnvironment{}, err
	}
	if _, err := hopproof.NextNode(nodeContext); err != nil {
		return RecursiveHopEnvironment{}, err
	}

	verifier := config.Verifier
	if verifier == nil {
		if strings.TrimSpace(config.AllowedSignersFile) == "" {
			return RecursiveHopEnvironment{}, errors.New("recursive hop requires --hop-allowed-signers")
		}
		verifier = hopproof.SSHKeygenVerifier{Binary: config.SSHKeygenBinary, AllowedSignersFile: config.AllowedSignersFile}
	}
	signer := config.Signer
	var signingIdentity sshagent.Identity
	if signer == nil {
		if strings.TrimSpace(config.SigningKeyFile) == "" {
			return RecursiveHopEnvironment{}, errors.New("recursive hop requires --hop-signing-key public key file")
		}
		agentClient := sshagent.Client{Binary: config.SSHAddBinary}
		if config.AgentClient != nil {
			agentClient = *config.AgentClient
			if strings.TrimSpace(agentClient.Binary) == "" {
				agentClient.Binary = config.SSHAddBinary
			}
		}
		if strings.TrimSpace(config.AgentAddKeyFile) != "" {
			if err := agentClient.Add(ctx, config.AgentAddKeyFile, sshagent.AddOptions{
				Lifetime: config.AgentAddLifetime,
				Confirm:  config.AgentAddConfirm,
				Quiet:    true,
			}); err != nil {
				return RecursiveHopEnvironment{}, fmt.Errorf("load recursive hop identity with ssh-add: %w", err)
			}
		}
		signingIdentity, err = agentClient.EnsureLoaded(ctx, config.SigningKeyFile)
		if err != nil {
			return RecursiveHopEnvironment{}, fmt.Errorf("recursive hop ssh-agent preflight: %w", err)
		}
		if config.AgentTestSign {
			if err := agentClient.Test(ctx, config.SigningKeyFile); err != nil {
				return RecursiveHopEnvironment{}, fmt.Errorf("recursive hop ssh-agent signing test: %w", err)
			}
		}
		signer = hopproof.SSHKeygenSigner{Binary: config.SSHKeygenBinary, KeyFile: config.SigningKeyFile}
	}
	now := config.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := config.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	parent := hopproof.Chain{}
	parentBinding, previousNode, incomingEncoded := "", "", ""
	if index > 0 {
		state, err := sessionbroker.ActiveState()
		if err != nil {
			return RecursiveHopEnvironment{}, fmt.Errorf("recursive hop requires active parent session: %w", err)
		}
		if state.Node != nodeContext.CurrentNode {
			return RecursiveHopEnvironment{}, fmt.Errorf("active parent session node %q does not match current node %q", state.Node, nodeContext.CurrentNode)
		}
		incomingEncoded = strings.TrimSpace(config.IncomingChain)
		receivedOrigin := strings.TrimSpace(os.Getenv(EnvWVOrigin))
		if incomingEncoded == "" || receivedOrigin == "" {
			hopState, hopStateErr := sessionbroker.ActiveHopState()
			if hopStateErr != nil {
				return RecursiveHopEnvironment{}, fmt.Errorf("recursive hop at node %q requires inherited %s/%s or verified local hop state: %w", nodeContext.CurrentNode, EnvWVOrigin, EnvWVHop, hopStateErr)
			}
			if incomingEncoded == "" {
				incomingEncoded = hopState.HopChain
			}
			if receivedOrigin == "" {
				receivedOrigin = hopState.PreviousNode
			}
		}
		parent, err = hopproof.Decode(incomingEncoded)
		if err != nil {
			return RecursiveHopEnvironment{}, err
		}
		if err := hopproof.Verify(ctx, nodeContext, parent, verifier, hopproof.VerifyOptions{Now: now, MaxTTL: 10 * time.Minute, ReplayCache: authproof.NewNonceCache()}); err != nil {
			return RecursiveHopEnvironment{}, fmt.Errorf("verify incoming recursive hop chain: %w", err)
		}
		previousNode, err = hopproof.ImmediatePrevious(parent)
		if err != nil {
			return RecursiveHopEnvironment{}, err
		}
		if receivedOrigin != previousNode {
			return RecursiveHopEnvironment{}, fmt.Errorf("%s=%q does not match verified previous hop %q", EnvWVOrigin, receivedOrigin, previousNode)
		}
		parentBinding = state.Binding
	} else if strings.TrimSpace(config.IncomingChain) != "" || strings.TrimSpace(os.Getenv(EnvWVHop)) != "" {
		return RecursiveHopEnvironment{}, errors.New("root recursive session-host must not inherit WVHOP")
	}

	chain, err := hopproof.Append(ctx, nodeContext, parent, parentBinding, ttl, now, signer)
	if err != nil {
		return RecursiveHopEnvironment{}, fmt.Errorf("sign next recursive hop: %w", err)
	}
	nextNode, err := hopproof.NextNode(nodeContext)
	if err != nil {
		return RecursiveHopEnvironment{}, err
	}
	nextContext := nodeContext
	nextContext.CurrentNode = nextNode
	if err := hopproof.Verify(ctx, nextContext, chain, verifier, hopproof.VerifyOptions{Now: now, MaxTTL: 10 * time.Minute, ReplayCache: authproof.NewNonceCache()}); err != nil {
		return RecursiveHopEnvironment{}, fmt.Errorf("verify newly signed recursive chain: %w", err)
	}
	encoded, err := hopproof.Encode(chain)
	if err != nil {
		return RecursiveHopEnvironment{}, err
	}
	origin, err := SignedWVOrigin(nodeContext)
	if err != nil {
		return RecursiveHopEnvironment{}, err
	}
	currentDepth := len(parent.Hops)
	return RecursiveHopEnvironment{
		Origin:              origin,
		HopChain:            encoded,
		NextNode:            nextNode,
		HopDepth:            len(chain.Hops),
		PreviousNode:        previousNode,
		IncomingChain:       incomingEncoded,
		CurrentDepth:        currentDepth,
		SigningIdentity:     signingIdentity,
		IncomingHopChain:    incomingEncoded,
		IncomingHopDepth:    currentDepth,
	}, nil
}

func recursiveHopAgentEnvironment(config RecursiveHopConfig) RecursiveHopConfig {
	if strings.TrimSpace(config.SSHAddBinary) == "" {
		config.SSHAddBinary = recursiveAgentEnvDefault("WEAVERSSH_SSH_ADD", "ssh-add")
	}
	if strings.TrimSpace(config.AgentAddKeyFile) == "" {
		config.AgentAddKeyFile = strings.TrimSpace(os.Getenv("WEAVERSSH_HOP_AGENT_ADD"))
	}
	if strings.TrimSpace(config.AgentAddLifetime) == "" {
		config.AgentAddLifetime = strings.TrimSpace(os.Getenv("WEAVERSSH_HOP_AGENT_LIFETIME"))
	}
	if !config.AgentAddConfirm {
		config.AgentAddConfirm = recursiveAgentEnvBoolean("WEAVERSSH_HOP_AGENT_CONFIRM")
	}
	if !config.AgentTestSign {
		config.AgentTestSign = recursiveAgentEnvBoolean("WEAVERSSH_HOP_AGENT_TEST_SIGN")
	}
	return config
}

func recursiveAgentEnvDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func recursiveAgentEnvBoolean(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func RecursiveRuntimePaths(defaultSocket, defaultState, node string) (string, string) {
	digest := sha256.Sum256([]byte(strings.TrimSpace(node)))
	suffix := hex.EncodeToString(digest[:6])
	return filepath.Join(filepath.Dir(defaultSocket), "session-host-"+suffix+".sock"), filepath.Join(filepath.Dir(defaultState), "session-host-"+suffix+".json")
}
