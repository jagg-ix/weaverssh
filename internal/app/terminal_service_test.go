package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/containerstream"
	"weaverssh/internal/p9client"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/terminalsession"
)

type configuredTerminalTestProvider struct{}

func (configuredTerminalTestProvider) Name() string { return "fake" }
func (configuredTerminalTestProvider) OpenContainerStream(context.Context, containerstream.Request) (io.ReadCloser, error) {
	return nil, containerstream.ErrExecutionUnsupported
}

func TestConfiguredTerminalServiceLoadsPolicyAndRecording(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "policy.json")
	recordingPath := filepath.Join(directory, "recording.ndjson")
	policy := terminalsession.Policy{
		Version: terminalsession.PolicyVersion,
		Default: "deny",
		Actions: []terminalsession.ActionPolicy{{
			Name: "status", Executable: "/usr/bin/status",
			Principals: []string{"*"}, Sources: []string{"laptop"},
			Endpoints: []string{"node-a"}, Targets: []string{"pod-a"}, Providers: []string{"fake"},
			Recording: terminalsession.RecordingRequired,
		}},
	}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := containerstream.NewRegistry()
	if err := registry.Register(configuredTerminalTestProvider{}); err != nil {
		t.Fatal(err)
	}
	router, err := containerstream.NewRouter(registry, containerstream.Discoverer{}, containerstream.RouterConfig{Provider: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewConfiguredTerminalService(context.Background(), TerminalServiceConfig{
		PolicyPath: policyPath, RecordingPath: recordingPath, Router: router,
		ResolvePrincipal: func(terminalsession.OpenMetadata) (string, error) { return "alice@example.test", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.Server == nil || service.Manager == nil || service.Router == nil || service.Server.Manager != service.Manager || service.Server.ResolvePrincipal == nil {
		t.Fatalf("incomplete configured service: %+v", service)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(recordingPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recording mode=%o want=600", info.Mode().Perm())
	}
}

func TestConfiguredTerminalServiceRequiresPolicy(t *testing.T) {
	if _, err := NewConfiguredTerminalService(context.Background(), TerminalServiceConfig{}); err == nil {
		t.Fatal("terminal service started without default-deny policy")
	}
}

func TestConfiguredContainerExecServiceSharesManagerWithProcessFS(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "process-policy.json")
	policy := terminalsession.Policy{
		Version: terminalsession.PolicyVersion,
		Default: "deny",
		Actions: []terminalsession.ActionPolicy{{
			Name: "status", Executable: "/usr/bin/status",
			Principals: []string{"*"}, Sources: []string{"laptop"},
			Endpoints: []string{"node-a"}, Targets: []string{"pod-a"}, Providers: []string{"fake"},
		}},
	}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := containerstream.NewRegistry()
	registry.MustRegister(configuredTerminalTestProvider{})
	router, err := containerstream.NewRouter(registry, containerstream.Discoverer{}, containerstream.RouterConfig{Provider: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewConfiguredContainerExecService(context.Background(), ContainerExecServiceConfig{PolicyPath: policyPath, Router: router})
	if err != nil {
		t.Fatal(err)
	}
	if service.Server == nil || service.Manager == nil || service.ProcessFS == nil || service.Server.Manager != service.Manager || service.Server.ProcessFS != service.ProcessFS {
		t.Fatalf("incomplete configured container exec service: %+v", service)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID: "processfs-test", Audience: authproof.AudienceNodeContext,
		ChainID: "processfs-chain", ChainSHA256: authproof.ChainBindingSHA256("node-a"),
		Nodes: []string{"node-a"}, CurrentNode: "node-a", OriginNode: "node-a", EndpointNode: "node-a",
		Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh, authproof.CapabilityContainerExec},
		Nonce:        "processfs-nonce", IssuedAtUnix: now.Add(-time.Second).Unix(), ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := NewLocalServices(LocalServiceConfig{
		SignedContext: signed, PublicKey: publicKey, ContainerExecServer: service.Server,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !routed.ContainerExecEnabled() || !routed.ProcessFSEnabled() || !containsService(routed.Services(), sessionmux.ServiceFS) {
		t.Fatalf("services=%v exec=%t processfs=%t", routed.Services(), routed.ContainerExecEnabled(), routed.ProcessFSEnabled())
	}
	routedSnapshot, err := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: routed.Context, Local: routed}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(routedSnapshot.Features, " "), "container.processfs.p9.v1") {
		t.Fatalf("features=%v", routedSnapshot.Features)
	}
	processMetadata, err := containerstream.NewProcessFSOpenMetadata("node-a", "vfs://container/node-a/pod-a/.wv/processes?provider=fake")
	if err != nil {
		t.Fatal(err)
	}
	processTransport, err := OpenBrokerTarget(context.Background(), routed, &sessionroute.Router{}, "binding-a", routed.Context, sessionbroker.OpenRequest{
		Node: "node-a", Service: sessionmux.ServiceFS, Data: processMetadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	processClient, err := p9client.Attach(processTransport)
	if err != nil {
		t.Fatal(err)
	}
	processEntries, err := processClient.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(processEntries) != 5 {
		t.Fatalf("ProcessFS entries=%v", processEntries)
	}
	if err := processClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := routed.Close(); err != nil {
		t.Fatal(err)
	}
	execOnlyContext := signed.Context
	execOnlyContext.Capabilities = []string{authproof.CapabilityNodeContext, authproof.CapabilityContainerExec}
	execOnlyContext.Nonce = "processfs-exec-only-nonce"
	execOnly, err := authproof.SignNodeContext(execOnlyContext, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	execOnlyLocal, err := NewLocalServices(LocalServiceConfig{
		SignedContext: execOnly, PublicKey: publicKey, ContainerExecServer: service.Server,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !execOnlyLocal.ContainerExecEnabled() || execOnlyLocal.ProcessFSEnabled() || containsService(execOnlyLocal.Services(), sessionmux.ServiceFS) {
		t.Fatalf("exec-only services=%v exec=%t processfs=%t", execOnlyLocal.Services(), execOnlyLocal.ContainerExecEnabled(), execOnlyLocal.ProcessFSEnabled())
	}
	if err := execOnlyLocal.Close(); err != nil {
		t.Fatal(err)
	}
	local := &LocalServices{
		Context:  authproof.NodeContext{Nodes: []string{"node-a"}, CurrentNode: "node-a", OriginNode: "node-a", EndpointNode: "node-a"},
		services: []sessionmux.ServiceID{sessionmux.ServiceExec}, containerExec: service.Server,
	}
	snapshot, err := NewSessionAPIServer(SessionAPIConfig{Binding: "binding-a", Context: local.Context, Local: local}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(snapshot.Features, " "), "container.process-manager.v1") {
		t.Fatalf("features=%v", snapshot.Features)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func containsService(services []sessionmux.ServiceID, want sessionmux.ServiceID) bool {
	for _, service := range services {
		if service == want {
			return true
		}
	}
	return false
}

func TestConfiguredContainerExecServiceRequiresPolicy(t *testing.T) {
	if _, err := NewConfiguredContainerExecService(context.Background(), ContainerExecServiceConfig{}); err == nil {
		t.Fatal("container exec service started without default-deny policy")
	}
}
