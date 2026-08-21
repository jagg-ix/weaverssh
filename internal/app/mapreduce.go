package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"weaverssh/authproof"
	"weaverssh/containerexec"
	"weaverssh/containerstream"
	"weaverssh/mapreduce"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionevents"
	"weaverssh/sessionexec"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/terminalsession"
)

const (
	EnvMapReducePolicy  = "WEAVERSSH_MAPREDUCE_POLICY"
	EnvMapReducePlugins = "WEAVERSSH_MAPREDUCE_PLUGINS"
)

var localMapReduceEngines sync.Map

// MapReduceConfigured is retained as the public compatibility predicate used by
// host and attach setup. It now reports any typed programmable service carried by
// the signed session: map/reduce, command actions, or routed events.
func MapReduceConfigured() bool {
	return strings.TrimSpace(os.Getenv(EnvMapReducePolicy)) != "" ||
		strings.TrimSpace(os.Getenv(EnvMapReducePlugins)) != "" ||
		extendedServicesConfigured()
}

func mapReduceEnvironmentConfigured() bool { return MapReduceConfigured() }

func loadConfiguredMapReduce(ctx authproof.NodeContext) (*mapreduce.Engine, error) {
	policyPath := strings.TrimSpace(os.Getenv(EnvMapReducePolicy))
	pluginsPath := strings.TrimSpace(os.Getenv(EnvMapReducePlugins))
	switch {
	case policyPath == "" && pluginsPath == "":
		return nil, nil
	case policyPath == "" || pluginsPath == "":
		return nil, fmt.Errorf("mapreduce: %s and %s must be configured together", EnvMapReducePolicy, EnvMapReducePlugins)
	}
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("mapreduce: read policy: %w", err)
	}
	policy, err := mapreduce.ParsePolicy(policyData)
	if err != nil {
		return nil, fmt.Errorf("mapreduce: parse policy: %w", err)
	}
	registry, err := mapreduce.LoadPluginFile(pluginsPath)
	if err != nil {
		return nil, fmt.Errorf("mapreduce: load plugins: %w", err)
	}
	return mapreduce.NewEngine(mapreduce.EngineConfig{
		Topology: mapreduce.Topology{ChainSHA256: ctx.ChainSHA256, Nodes: append([]string(nil), ctx.Nodes...), CurrentNode: ctx.CurrentNode},
		Registry: registry, Policy: policy,
	})
}

func InstallConfiguredMapReduce(local *LocalServices) error {
	if local == nil {
		return errors.New("mapreduce: local services are required")
	}
	engine, err := loadConfiguredMapReduce(local.Context)
	if err != nil {
		return err
	}
	installedMapReduce := false
	if engine != nil {
		if err := installMapReduce(local, engine); err != nil {
			return err
		}
		installedMapReduce = true
	}
	if err := InstallConfiguredExtendedServices(local); err != nil {
		if installedMapReduce {
			localMapReduceEngines.Delete(local)
		}
		uninstallExtendedServices(local)
		return err
	}
	return nil
}

func installConfiguredMapReduce(local *LocalServices) error { return InstallConfiguredMapReduce(local) }

func installMapReduce(local *LocalServices, engine *mapreduce.Engine) error {
	if local == nil || engine == nil {
		return errors.New("mapreduce: incomplete local installation")
	}
	if engine.Description().CurrentNode != local.Context.CurrentNode {
		return errors.New("mapreduce: engine node does not match local signed context")
	}
	ensureLocalService(local, sessionmux.ServiceExec)
	localMapReduceEngines.Store(local, engine)
	return nil
}

func uninstallMapReduce(local *LocalServices) {
	if local != nil {
		localMapReduceEngines.Delete(local)
		uninstallExtendedServices(local)
	}
}

func (s *LocalServices) MapReduceEnabled() bool {
	if s == nil {
		return false
	}
	_, ok := localMapReduceEngines.Load(s)
	return ok
}
func (s *LocalServices) MapReduceDescription() mapreduce.Description {
	if s == nil {
		return mapreduce.Description{}
	}
	value, ok := localMapReduceEngines.Load(s)
	if !ok {
		return mapreduce.Description{}
	}
	return value.(*mapreduce.Engine).Description()
}

// dispatchMapReduce recognizes only the established map/reduce metadata. Other
// ServiceExec protocols are offered to dispatchExtendedService instead of being
// reset merely because they share the same mux service ID.
func dispatchMapReduce(ctx context.Context, local *LocalServices, accepted sessioncontrol.AcceptedTarget) bool {
	if accepted.Stream != nil && accepted.Stream.Service() == sessionmux.ServiceExec && mapreduce.IsOpenMetadata(accepted.Data) {
		value, ok := localMapReduceEngines.Load(local)
		if !ok {
			_ = accepted.Stream.Reset()
			return true
		}
		go func() { _ = value.(*mapreduce.Engine).Serve(ctx, accepted.Stream, accepted.Data) }()
		return true
	}
	return dispatchExecEvents(ctx, local, accepted)
}

func openLocalMapReduce(ctx context.Context, local *LocalServices, metadata []byte) (io.ReadWriteCloser, error) {
	value, ok := localMapReduceEngines.Load(local)
	if !ok {
		return nil, errors.New("mapreduce: local engine unavailable")
	}
	server, client := net.Pipe()
	go func() { _ = value.(*mapreduce.Engine).Serve(ctx, server, metadata) }()
	return client, nil
}

func openLocalTerminal(ctx context.Context, local *LocalServices, metadata []byte) (io.ReadWriteCloser, error) {
	if local == nil || local.terminal == nil {
		return nil, errors.New("terminalsession: local terminal server unavailable")
	}
	server, client := net.Pipe()
	go func() { _ = local.terminal.ServeBound(ctx, server, metadata) }()
	return client, nil
}

func openLocalProcessFS(ctx context.Context, local *LocalServices, metadata []byte) (io.ReadWriteCloser, error) {
	if local == nil || local.processFS == nil {
		return nil, errors.New("ProcessFS: local server unavailable")
	}
	server, client := net.Pipe()
	go func() { _ = local.processFS.ServeBound(ctx, server, metadata) }()
	return client, nil
}

// OpenBrokerTarget binds source provenance at the same-user broker before any
// programmable service crosses a session. Forwarders preserve the original
// source/binding/chain and can only rewrite the concrete target.
func OpenBrokerTarget(ctx context.Context, local *LocalServices, router *sessionroute.Router, binding string, nodeContext authproof.NodeContext, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
	if router == nil {
		return nil, errors.New("programmable service router is required")
	}
	processFSOpen := request.Service == sessionmux.ServiceFS && containerstream.IsProcessFSOpenMetadata(request.Data)
	if request.Service != sessionmux.ServiceExec && request.Service != sessionmux.ServiceEvents && request.Service != sessionmux.ServiceTerminal && !processFSOpen {
		return router.OpenLocal(ctx, request.Node, request.Service, request.Data)
	}
	target, _, err := sessionroute.ResolveNode(nodeContext, request.Node)
	if err != nil {
		return nil, err
	}
	switch request.Service {
	case sessionmux.ServiceFS:
		if !processFSOpen || !processFSBrokerAuthorized(nodeContext) {
			return nil, errors.New("ProcessFS requires signed VFS and container-exec capabilities")
		}
		bound, err := containerstream.BindProcessFSSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
		if err != nil {
			return nil, err
		}
		if target == nodeContext.CurrentNode {
			return openLocalProcessFS(ctx, local, bound)
		}
		return router.OpenLocal(ctx, target, sessionmux.ServiceFS, bound)
	case sessionmux.ServiceExec:
		switch {
		case containerexec.IsOpenMetadata(request.Data):
			bound, err := containerexec.BindSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
			if err != nil {
				return nil, err
			}
			if target == nodeContext.CurrentNode {
				return openLocalContainerExec(ctx, local, bound)
			}
			return router.OpenLocal(ctx, target, sessionmux.ServiceExec, bound)
		case mapreduce.IsOpenMetadata(request.Data):
			bound, err := mapreduce.BindSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
			if err != nil {
				return nil, err
			}
			if target == nodeContext.CurrentNode {
				return openLocalMapReduce(ctx, local, bound)
			}
			return router.OpenLocal(ctx, target, sessionmux.ServiceExec, bound)
		case sessionexec.IsOpenMetadata(request.Data):
			bound, err := sessionexec.BindSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
			if err != nil {
				return nil, err
			}
			if target == nodeContext.CurrentNode {
				return openLocalExec(ctx, local, bound)
			}
			return router.OpenLocal(ctx, target, sessionmux.ServiceExec, bound)
		default:
			return nil, errors.New("ServiceExec requires typed container-exec, mapreduce, or host-exec metadata")
		}
	case sessionmux.ServiceEvents:
		if !sessionevents.IsOpenMetadata(request.Data) {
			return nil, errors.New("ServiceEvents requires weaverssh.events-open.v1 metadata")
		}
		bound, err := sessionevents.BindSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
		if err != nil {
			return nil, err
		}
		if target == nodeContext.CurrentNode {
			return openLocalEvents(ctx, local, bound)
		}
		return router.OpenLocal(ctx, target, sessionmux.ServiceEvents, bound)
	case sessionmux.ServiceTerminal:
		if !terminalsession.IsOpenMetadata(request.Data) {
			return nil, errors.New("ServiceTerminal requires weaverssh.terminal-open.v1 metadata")
		}
		bound, err := terminalsession.BindSource(request.Data, nodeContext.CurrentNode, binding, nodeContext.ChainSHA256, target)
		if err != nil {
			return nil, err
		}
		if target == nodeContext.CurrentNode {
			return openLocalTerminal(ctx, local, bound)
		}
		return router.OpenLocal(ctx, target, sessionmux.ServiceTerminal, bound)
	default:
		return nil, errors.New("unsupported programmable service")
	}
}

func processFSBrokerAuthorized(ctx authproof.NodeContext) bool {
	var vfs, exec bool
	for _, capability := range ctx.Capabilities {
		switch strings.TrimSpace(capability) {
		case authproof.CapabilityVFSMesh, authproof.CapabilityFileBackhaul:
			vfs = true
		case authproof.CapabilityContainerExec, authproof.CapabilityMapReduce:
			exec = true
		}
	}
	return vfs && exec
}
