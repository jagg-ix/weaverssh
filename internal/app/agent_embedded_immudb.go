package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"weaverssh/evidencebinding"
)

const (
	AgentEmbeddedImmuDBPathEnv     = "WEAVERSSH_AGENT_IMMUDB_PATH"
	AgentEmbeddedImmuDBProviderEnv = "WEAVERSSH_AGENT_IMMUDB_PROVIDER"
)

// AgentEmbeddedImmuDBConfig enables an in-process immudb evidence store for an
// embedded WeaverSSH agent runtime. Path must identify a persistent, owner-only
// directory. ProviderName is the identity used by threshold policies and
// receipts; it defaults to "agent-embedded-immudb".
type AgentEmbeddedImmuDBConfig struct {
	Path         string
	ProviderName string
}

func AgentEmbeddedImmuDBConfigFromEnv(getenv func(string) string) AgentEmbeddedImmuDBConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	return AgentEmbeddedImmuDBConfig{
		Path:         strings.TrimSpace(getenv(AgentEmbeddedImmuDBPathEnv)),
		ProviderName: strings.TrimSpace(getenv(AgentEmbeddedImmuDBProviderEnv)),
	}
}

func (c AgentEmbeddedImmuDBConfig) Validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("embedded agent evidence requires %s or an explicit path", AgentEmbeddedImmuDBPathEnv)
	}
	return nil
}

// AgentRuntimeWithEmbeddedImmuDB couples the normal agent runtime with a local
// embedded immudb anchor provider. Closing the wrapper closes the evidence store
// and the underlying agent runtime exactly once.
type AgentRuntimeWithEmbeddedImmuDB struct {
	*AgentRuntime
	provider evidencebinding.NamedAnchorProvider
	closeOnce sync.Once
	closeErr  error
}

func NewAgentRuntimeWithEmbeddedImmuDB(config AgentConfig, authCookie string, embedded AgentEmbeddedImmuDBConfig) (*AgentRuntimeWithEmbeddedImmuDB, error) {
	if err := embedded.Validate(); err != nil {
		return nil, err
	}
	runtime, err := NewAgentRuntime(config, authCookie)
	if err != nil {
		return nil, err
	}
	anchor, err := evidencebinding.OpenEmbeddedImmuDBAnchor(embedded.Path)
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	providerName := strings.TrimSpace(embedded.ProviderName)
	if providerName == "" {
		providerName = "agent-embedded-immudb"
	}
	return &AgentRuntimeWithEmbeddedImmuDB{
		AgentRuntime: runtime,
		provider: evidencebinding.NamedAnchorProvider{ProviderName: providerName, Inner: anchor},
	}, nil
}

func (r *AgentRuntimeWithEmbeddedImmuDB) EvidenceProvider() evidencebinding.AnchorProvider {
	if r == nil || r.AgentRuntime == nil {
		return nil
	}
	return r.provider
}

func (r *AgentRuntimeWithEmbeddedImmuDB) AnchorEvidenceHead(ctx context.Context, head evidencebinding.Head) (evidencebinding.AnchorReceipt, error) {
	if r == nil || r.AgentRuntime == nil {
		return evidencebinding.AnchorReceipt{}, evidencebinding.ErrInvalidAnchor
	}
	return r.provider.Anchor(ctx, head)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) VerifyEvidenceReceipt(ctx context.Context, head evidencebinding.Head, receipt evidencebinding.AnchorReceipt) error {
	if r == nil || r.AgentRuntime == nil {
		return evidencebinding.ErrInvalidAnchor
	}
	return r.provider.Verify(ctx, head, receipt)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		var errs []error
		if err := r.provider.Close(); err != nil {
			errs = append(errs, err)
		}
		if r.AgentRuntime != nil {
			if err := r.AgentRuntime.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}
