package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"weaverssh/containerstream"
	"weaverssh/terminalsession"
)

const (
	EnvTerminalPolicy    = "WEAVERSSH_TERMINAL_POLICY"
	EnvTerminalRecording = "WEAVERSSH_TERMINAL_RECORDING"
)

type TerminalServiceConfig struct {
	PolicyPath    string
	RecordingPath string
	Router        *containerstream.Router
	// Spawner is an optional trusted execution-plane plugin. Nil uses the
	// provider-neutral ContainerSpawner. An external tmux-like backend can be
	// injected here without replacing WeaverSSH authorization, ownership,
	// replay, recording, or attachment-generation controls.
	Spawner terminalsession.Spawner
	// ResolvePrincipal may map broker-bound provenance to an SSO principal.
	// Command-line deployments leave it nil and use SourceNode as principal.
	ResolvePrincipal func(terminalsession.OpenMetadata) (string, error)
	MaxSessions      int
	SendTimeout      time.Duration
}

// ConfiguredTerminalService owns the policy, provider router, detached-session
// manager, and optional raw recording sink for one agent process.
type ConfiguredTerminalService struct {
	Server   *terminalsession.Server
	Manager  *terminalsession.Manager
	Router   *containerstream.Router
	recorder *terminalsession.HashChainRecorder
}

func NewConfiguredTerminalService(parent context.Context, config TerminalServiceConfig) (*ConfiguredTerminalService, error) {
	policyPath := strings.TrimSpace(config.PolicyPath)
	if policyPath == "" {
		return nil, errors.New("terminal service: policy path is required")
	}
	policy, err := terminalsession.LoadPolicyFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("terminal service: load policy: %w", err)
	}
	authorizer, err := terminalsession.NewPolicyAuthorizer(policy)
	if err != nil {
		return nil, fmt.Errorf("terminal service: policy: %w", err)
	}
	router := config.Router
	if router == nil {
		router, err = containerstream.NewEnvironmentRouter()
		if err != nil {
			return nil, fmt.Errorf("terminal service: provider router: %w", err)
		}
	}
	var recorder *terminalsession.HashChainRecorder
	if path := strings.TrimSpace(config.RecordingPath); path != "" {
		recorder, err = terminalsession.OpenHashChainRecordingFile(path)
		if err != nil {
			return nil, fmt.Errorf("terminal service: recording: %w", err)
		}
	}
	spawner := config.Spawner
	if spawner == nil {
		spawner = terminalsession.ContainerSpawner{Router: router}
	}
	manager, err := terminalsession.NewManager(parent, terminalsession.ManagerConfig{
		Authorizer: authorizer, Spawner: spawner,
		Recorder: recorder, MaxSessions: config.MaxSessions, SendTimeout: config.SendTimeout,
	})
	if err != nil {
		if recorder != nil {
			_ = recorder.Close()
		}
		return nil, fmt.Errorf("terminal service: manager: %w", err)
	}
	return &ConfiguredTerminalService{
		Server: &terminalsession.Server{Manager: manager, ResolvePrincipal: config.ResolvePrincipal}, Manager: manager, Router: router, recorder: recorder,
	}, nil
}

func (s *ConfiguredTerminalService) Close() error {
	if s == nil {
		return nil
	}
	var failures []error
	if s.Manager != nil {
		failures = append(failures, s.Manager.Close())
		s.Manager = nil
	}
	if s.recorder != nil {
		failures = append(failures, s.recorder.Close())
		s.recorder = nil
	}
	return errors.Join(failures...)
}
