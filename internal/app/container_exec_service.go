package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"weaverssh/containerexec"
	"weaverssh/containerstream"
	"weaverssh/terminalsession"
)

const EnvContainerExecPolicy = "WEAVERSSH_CONTAINER_EXEC_POLICY"

type ContainerExecServiceConfig struct {
	PolicyPath       string
	Router           *containerstream.Router
	ResolvePrincipal func(containerexec.OpenMetadata) (string, error)
	MaxSessions      int
}

// ConfiguredContainerExecService owns the shared non-interactive process
// manager. Its ProcessFS facade and typed Exec server are two views over the
// same process handles rather than separate execution implementations.
type ConfiguredContainerExecService struct {
	Server    *containerexec.Server
	Manager   *containerstream.ProcessManager
	ProcessFS *containerstream.ProcessFS
}

func NewConfiguredContainerExecService(parent context.Context, config ContainerExecServiceConfig) (*ConfiguredContainerExecService, error) {
	policyPath := strings.TrimSpace(config.PolicyPath)
	if policyPath == "" {
		return nil, errors.New("container exec service: policy path is required")
	}
	policy, err := terminalsession.LoadPolicyFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("container exec service: load policy: %w", err)
	}
	authorizer, err := terminalsession.NewPolicyAuthorizer(policy)
	if err != nil {
		return nil, fmt.Errorf("container exec service: policy: %w", err)
	}
	router := config.Router
	if router == nil {
		router, err = containerstream.NewEnvironmentRouter()
		if err != nil {
			return nil, fmt.Errorf("container exec service: provider router: %w", err)
		}
	}
	manager, err := containerstream.NewProcessManager(parent, router, authorizer, containerstream.ProcessManagerConfig{MaxSessions: config.MaxSessions})
	if err != nil {
		return nil, fmt.Errorf("container exec service: process manager: %w", err)
	}
	processFS, err := containerstream.NewProcessFSWithManager(manager, 0)
	if err != nil {
		_ = manager.Close()
		return nil, fmt.Errorf("container exec service: ProcessFS: %w", err)
	}
	return &ConfiguredContainerExecService{
		Server:  &containerexec.Server{Manager: manager, ProcessFS: processFS, ResolvePrincipal: config.ResolvePrincipal},
		Manager: manager, ProcessFS: processFS,
	}, nil
}

func (s *ConfiguredContainerExecService) Close() error {
	if s == nil || s.Manager == nil {
		return nil
	}
	err := s.Manager.Close()
	s.Manager = nil
	return err
}
