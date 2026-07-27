package app

import (
	"context"
	"os"
	"strings"

	"weaverssh/apicontract"
	"weaverssh/authproof"
	"weaverssh/extension"
	"weaverssh/originruntime"
	"weaverssh/sessionapi"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionroute"
)

type SessionAPIConfig struct {
	Binding      string
	Context      authproof.NodeContext
	Local        *LocalServices
	Registry     *sessioncontrol.Registry
	PreviousNode string
	HopDepth     int
	EncodedWVHop string
	Router       *sessionroute.Router
	Extensions   *extension.Registry
	Contracts    apicontract.Provider
}

func NewSessionAPIServer(config SessionAPIConfig) *sessionapi.Server {
	server := &sessionapi.Server{Contracts: config.Contracts, Snapshot: func(context.Context) (sessionapi.Snapshot, error) {
		ctx := config.Context.Normalized()
		currentIndex := -1
		for index, node := range ctx.Nodes {
			if node == ctx.CurrentNode {
				currentIndex = index
				break
			}
		}
		previousNode := ""
		if currentIndex > 0 {
			previousNode = ctx.Nodes[currentIndex-1]
		}
		hopDepth := config.HopDepth
		encodedHop := strings.TrimSpace(config.EncodedWVHop)
		if hopDepth != currentIndex {
			hopDepth = currentIndex
			encodedHop = ""
		}
		if currentIndex <= 0 {
			hopDepth = 0
			encodedHop = ""
		}
		localServices := []string{}
		if config.Local != nil {
			for _, service := range config.Local.Services() {
				localServices = append(localServices, service.String())
			}
		}
		registered := map[string]sessioncontrol.Node{}
		if config.Registry != nil {
			for _, node := range config.Registry.Registered() {
				registered[node.ID] = node
			}
		}
		nodes := make([]sessionapi.Node, 0, len(ctx.Nodes))
		for index, nodeID := range ctx.Nodes {
			node := sessionapi.Node{ID: nodeID, Index: index}
			if registeredNode, ok := registered[nodeID]; ok {
				node.Registered = true
				for _, service := range registeredNode.Services() {
					node.Services = append(node.Services, service.String())
				}
			}
			if nodeID == ctx.CurrentNode {
				node.Registered = true
				if len(node.Services) == 0 {
					node.Services = append(node.Services, localServices...)
				}
			}
			nodes = append(nodes, node)
		}
		features := []string{"api.read.v1", "mux.window.v2", "route.plan.v1", "service.open.v1"}
		if config.Contracts != nil {
			features = append(features, "api.contracts.v1", "api.description.openapi.v1", "api.description.openrpc.v1", "api.description.asyncapi.v1", "api.description.json-schema.v1", "api.description.protobuf.v1")
		}
		if runtimeID := strings.TrimSpace(os.Getenv(originruntime.EnvID)); runtimeID != "" {
			switch runtimeKind := strings.TrimSpace(os.Getenv(originruntime.EnvKind)); runtimeKind {
			case string(originruntime.KindNative), string(originruntime.KindWSL), string(originruntime.KindDocker), string(originruntime.KindKubernetes), string(originruntime.KindVM):
				features = append(features, "origin.runtime.v1", "origin.runtime."+runtimeKind+".v1", "origin.runtime.path-map.v1")
			}
		}
		if containsString(localServices, "fs") {
			features = append(features, "fs.atomic-replace.v1")
			if config.Local != nil {
				description := config.Local.FileBackendDescription()
				if description.Backend != "" {
					features = append(features, "fs.backend-api.v1", "fs.qid-core.v1")
					if strings.HasPrefix(description.Backend, "compose:") {
						features = append(features, "fs.compose.v1", "fs.union.v1", "fs.branch-priority.v1", "fs.copy-on-write.v1", "fs.transaction-plugins.v1", "fs.data-policy.v1")
					}
					if description.Hooks {
						features = append(features, "fs.hooks.v1")
					}
					if description.Core.Store != "" {
						features = append(features, "fs.core."+description.Core.Store+".v1")
					}
				}
			}
		}
		if containsString(localServices, "tcp") {
			features = append(features, "grpc.mqtt-framing.v1", "grpc.mqtt-stream-dialer.v1", "grpc.mqtt-loopback-proxy.v1")
		}
		if containsString(localServices, "udp") {
			features = append(features, "udp.rfc1928.v1", "socks5.udp-associate.v1")
		}
		if config.Local != nil && config.Local.TCPProofEnabled() {
			features = append(features, "tcp.client-proof.v1", "socks5.auth.private-0x80.v1", "grpc.mqtt-framing.proof.v1")
			if config.Local.TCPProofRequired() {
				features = append(features, "tcp.client-proof.required.v1")
			}
		}
		if config.Local != nil && config.Local.MapReduceEnabled() {
			features = append(features, "compute.mapreduce.v1", "compute.mapreduce.rules.v1", "compute.mapreduce.plugins.v1")
		}
		if config.Local != nil && config.Local.ExecEnabled() {
			features = append(features, "exec.command.v1", "exec.policy.v1", "exec.provenance.v1")
		}
		if config.Local != nil && config.Local.EventsEnabled() {
			features = append(features, "events.routed.v1", "events.policy.v1", "events.provenance.v1")
		}
		if config.Router != nil {
			features = append(features, "route.forward.linear.v1")
		}
		if hopDepth > 0 {
			features = append(features, "recursive.hop.v1")
		}
		if config.Extensions != nil && !config.Extensions.Empty() {
			features = append(features, "extensions.hooks.v1")
			if config.Extensions.HasRuntime(extension.EBPFRuntimeKind) {
				features = append(features, "extensions.ebpf.v1")
			}
		}
		return sessionapi.Snapshot{Binding: strings.TrimSpace(config.Binding), CurrentNode: ctx.CurrentNode, CurrentIndex: currentIndex, Topology: append([]string(nil), ctx.Nodes...), Nodes: nodes, LocalServices: localServices, Features: features, PreviousNode: previousNode, HopDepth: hopDepth, HopChainSHA256: sessionapi.HopChainDigest(encodedHop)}, nil
	}}
	if config.Router != nil {
		server.PrepareRoute = func(_ context.Context, params sessionapi.RoutePrepareParams) (sessionapi.RoutePlan, error) {
			plan, err := config.Router.Prepare(params.Node)
			if err != nil {
				return sessionapi.RoutePlan{}, err
			}
			return sessionapi.RoutePlan{TargetNode: plan.TargetNode, TargetIndex: plan.TargetIndex, Direction: plan.Direction, NextHop: plan.NextHop, NextBinding: plan.NextBinding, Service: strings.TrimSpace(params.Service), Available: plan.Available, UsesCurrent: plan.UsesCurrent}, nil
		}
	}
	return server
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
