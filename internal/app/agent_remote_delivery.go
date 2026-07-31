package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"weaverssh/evidencebinding"
)

const (
	AgentRemoteProvidersEnv = "WEAVERSSH_AGENT_REMOTE_PROVIDERS"
	AgentRemoteQueueEnv     = "WEAVERSSH_AGENT_REMOTE_QUEUE"
)

type AgentRemoteDeliveryConfig struct {
	ProviderConfigPath string
	QueuePath          string
	MinBackoff         time.Duration
	MaxBackoff         time.Duration
	PollEvery          time.Duration
	HTTPTimeout        time.Duration
}

func AgentRemoteDeliveryConfigFromEnv(root string, getenv func(string) string) AgentRemoteDeliveryConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	queuePath := strings.TrimSpace(getenv(AgentRemoteQueueEnv))
	if queuePath == "" && strings.TrimSpace(root) != "" {
		queuePath = filepath.Join(strings.TrimSpace(root), "remote-delivery.json")
	}
	return AgentRemoteDeliveryConfig{
		ProviderConfigPath: strings.TrimSpace(getenv(AgentRemoteProvidersEnv)),
		QueuePath: queuePath, MinBackoff: 5 * time.Second,
		MaxBackoff: 5 * time.Minute, PollEvery: time.Second, HTTPTimeout: 30 * time.Second,
	}
}

func OpenAgentRemoteDelivery(ctx context.Context, config AgentRemoteDeliveryConfig) (*evidencebinding.AgentRemoteAnchorQueue, error) {
	if strings.TrimSpace(config.ProviderConfigPath) == "" {
		return nil, nil
	}
	providerConfig, err := evidencebinding.LoadAnchorProviderConfig(config.ProviderConfigPath)
	if err != nil {
		return nil, err
	}
	for _, provider := range providerConfig.Providers {
		if strings.EqualFold(strings.TrimSpace(provider.Type), evidencebinding.EmbeddedImmuDBProviderName) {
			return nil, fmt.Errorf("remote delivery provider %s must not use embedded-immudb", provider.Name)
		}
	}
	if config.HTTPTimeout <= 0 {
		config.HTTPTimeout = 30 * time.Second
	}
	providers, policy, err := providerConfig.Build(&http.Client{Timeout: config.HTTPTimeout}, os.Getenv)
	if err != nil {
		return nil, err
	}
	queue, err := evidencebinding.OpenAgentRemoteAnchorQueue(ctx, evidencebinding.AgentRemoteQueueConfig{
		Path: config.QueuePath, MinBackoff: config.MinBackoff,
		MaxBackoff: config.MaxBackoff, PollEvery: config.PollEvery,
	}, providers, policy)
	if err != nil {
		return nil, err
	}
	return queue, nil
}
