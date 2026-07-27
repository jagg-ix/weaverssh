package app

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"weaverssh/authproof"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionevents"
	"weaverssh/sessionexec"
	"weaverssh/sessionmux"
)

const (
	EnvExecPolicy    = "WEAVERSSH_EXEC_POLICY"
	EnvEventsPolicy  = "WEAVERSSH_EVENTS_POLICY"
	EnvPolicyRuntime = "WEAVERSSH_POLICY_RUNTIME"
)

var (
	localExecEngines  sync.Map
	localEventEngines sync.Map
)

func ExecConfigured() bool             { return strings.TrimSpace(os.Getenv(EnvExecPolicy)) != "" }
func EventsConfigured() bool           { return strings.TrimSpace(os.Getenv(EnvEventsPolicy)) != "" }
func extendedServicesConfigured() bool { return ExecConfigured() || EventsConfigured() }

func InstallConfiguredExtendedServices(local *LocalServices) error {
	if local == nil {
		return errors.New("extended services: local services are required")
	}
	if extendedServicesConfigured() && !hasProgrammableCapability(local) {
		return authproof.ErrMissingCapability
	}
	var execEngine *sessionexec.Engine
	if path := strings.TrimSpace(os.Getenv(EnvExecPolicy)); path != "" {
		policy, err := sessionexec.LoadPolicyFile(path)
		if err != nil {
			return err
		}
		execEngine, err = sessionexec.NewEngine(sessionexec.EngineConfig{
			Topology: append([]string(nil), local.Context.Nodes...), ChainSHA256: local.Context.ChainSHA256,
			CurrentNode: local.Context.CurrentNode, Policy: policy,
		})
		if err != nil {
			return err
		}
	}
	var eventEngine *sessionevents.Engine
	if path := strings.TrimSpace(os.Getenv(EnvEventsPolicy)); path != "" {
		policy, err := sessionevents.LoadPolicyFile(path)
		if err != nil {
			return err
		}
		eventEngine, err = sessionevents.NewEngine(sessionevents.EngineConfig{
			Topology: append([]string(nil), local.Context.Nodes...), ChainSHA256: local.Context.ChainSHA256,
			CurrentNode: local.Context.CurrentNode, Policy: policy,
		})
		if err != nil {
			return err
		}
	}
	// Publish only after every configured policy and engine validates, preventing
	// a failed second service from leaving stale advertised state behind.
	if execEngine != nil {
		ensureLocalService(local, sessionmux.ServiceExec)
		localExecEngines.Store(local, execEngine)
	}
	if eventEngine != nil {
		ensureLocalService(local, sessionmux.ServiceEvents)
		localEventEngines.Store(local, eventEngine)
	}
	return nil
}

func hasProgrammableCapability(local *LocalServices) bool {
	if local == nil {
		return false
	}
	for _, capability := range local.Context.Capabilities {
		if strings.TrimSpace(capability) == authproof.CapabilityMapReduce {
			return true
		}
	}
	return false
}

func installConfiguredExtendedServices(local *LocalServices) error {
	return InstallConfiguredExtendedServices(local)
}

func ensureLocalService(local *LocalServices, service sessionmux.ServiceID) {
	if local == nil {
		return
	}
	for _, existing := range local.services {
		if existing == service {
			return
		}
	}
	local.services = append(local.services, service)
}

func uninstallExtendedServices(local *LocalServices) {
	if local == nil {
		return
	}
	localExecEngines.Delete(local)
	if value, ok := localEventEngines.LoadAndDelete(local); ok {
		_ = sessionevents.SetRuntimeAuthorizer(value.(*sessionevents.Engine), nil)
	}
}

func (s *LocalServices) ExecEnabled() bool {
	if s == nil {
		return false
	}
	_, ok := localExecEngines.Load(s)
	return ok
}
func (s *LocalServices) EventsEnabled() bool {
	if s == nil {
		return false
	}
	_, ok := localEventEngines.Load(s)
	return ok
}

func dispatchExecEvents(ctx context.Context, local *LocalServices, accepted sessioncontrol.AcceptedTarget) bool {
	if accepted.Stream == nil {
		return false
	}
	switch accepted.Stream.Service() {
	case sessionmux.ServiceExec:
		if !sessionexec.IsOpenMetadata(accepted.Data) {
			return false
		}
		value, ok := localExecEngines.Load(local)
		if !ok {
			_ = accepted.Stream.Reset()
			return true
		}
		go func() { _ = value.(*sessionexec.Engine).Serve(ctx, accepted.Stream, accepted.Data) }()
		return true
	case sessionmux.ServiceEvents:
		if !sessionevents.IsOpenMetadata(accepted.Data) {
			return false
		}
		value, ok := localEventEngines.Load(local)
		if !ok {
			_ = accepted.Stream.Reset()
			return true
		}
		go func() { _ = value.(*sessionevents.Engine).Serve(ctx, accepted.Stream, accepted.Data) }()
		return true
	default:
		return false
	}
}

func openLocalExec(ctx context.Context, local *LocalServices, metadata []byte) (io.ReadWriteCloser, error) {
	value, ok := localExecEngines.Load(local)
	if !ok {
		return nil, errors.New("sessionexec: local engine unavailable")
	}
	server, client := net.Pipe()
	go func() { _ = value.(*sessionexec.Engine).Serve(ctx, server, metadata) }()
	return client, nil
}
func openLocalEvents(ctx context.Context, local *LocalServices, metadata []byte) (io.ReadWriteCloser, error) {
	value, ok := localEventEngines.Load(local)
	if !ok {
		return nil, errors.New("sessionevents: local engine unavailable")
	}
	server, client := net.Pipe()
	go func() { _ = value.(*sessionevents.Engine).Serve(ctx, server, metadata) }()
	return client, nil
}
