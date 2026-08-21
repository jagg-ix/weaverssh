package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	ProviderKubernetes = "kubernetes"
	ProviderRancher    = "rancher"
	ProviderCRI        = "cri"
	ProviderDocker     = "docker"
	ProviderPodman     = "podman"
	ProviderNomad      = "nomad"
)

type cliFlavor uint8

const (
	flavorKubernetes cliFlavor = iota + 1
	flavorRancher
	flavorCRI
	flavorDocker
	flavorPodman
	flavorNomad
)

type cliProvider struct {
	name   string
	binary string
	flavor cliFlavor
	runner CommandRunner
}

func NewKubernetesProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderKubernetes, binary, "kubectl", flavorKubernetes, runner)
}

func NewRancherProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderRancher, binary, "k3s", flavorRancher, runner)
}

func NewCRIProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderCRI, binary, "crictl", flavorCRI, runner)
}

func NewDockerProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderDocker, binary, "docker", flavorDocker, runner)
}

func NewPodmanProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderPodman, binary, "podman", flavorPodman, runner)
}

func NewNomadProvider(runner CommandRunner, binary string) Provider {
	return newCLIProvider(ProviderNomad, binary, "nomad", flavorNomad, runner)
}

func newCLIProvider(name, binary, fallback string, flavor cliFlavor, runner CommandRunner) Provider {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = fallback
	}
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &cliProvider{name: name, binary: binary, flavor: flavor, runner: runner}
}

// NewDefaultRegistry returns all built-in adapters. Kubernetes, Rancher,
// Docker, Podman, and Nomad combine a native API fast path with the argv-only
// CLI safe path. CRI remains CLI-only until it has a faithful streaming API
// transport independent of kubelet's CRI streaming server.
func NewDefaultRegistry(runner CommandRunner) *Registry {
	registry := NewRegistry()
	registry.MustRegister(mustHybridProvider(ProviderKubernetes, newKubernetesAPIProvider(ProviderKubernetes), NewKubernetesProvider(runner, "")), "k8s")
	registry.MustRegister(mustHybridProvider(ProviderRancher, newKubernetesAPIProvider(ProviderRancher), NewRancherProvider(runner, "")), "k3s", "rke")
	registry.MustRegister(NewCRIProvider(runner, ""), "containerd", "cri-o")
	registry.MustRegister(mustHybridProvider(ProviderDocker, newDefaultEngineAPIProvider(ProviderDocker), NewDockerProvider(runner, "")), "oci")
	registry.MustRegister(mustHybridProvider(ProviderPodman, newDefaultEngineAPIProvider(ProviderPodman), NewPodmanProvider(runner, "")))
	registry.MustRegister(mustHybridProvider(ProviderNomad, newDefaultNomadAPIProvider(), NewNomadProvider(runner, "")))
	return registry
}

func mustHybridProvider(name string, fast, safe Provider) Provider {
	provider, err := NewHybridProvider(name, fast, safe)
	if err != nil {
		panic(err)
	}
	return provider
}

func (p *cliProvider) Name() string { return p.name }

func (p *cliProvider) OpenContainerStream(ctx context.Context, request Request) (io.ReadCloser, error) {
	if p == nil || p.runner == nil {
		return nil, errors.New("containerstream: unavailable provider")
	}
	if _, err := safeAdapterToken("target", request.TargetID); err != nil {
		return nil, err
	}
	if request.FilePath == "" || !strings.HasPrefix(request.FilePath, "/") || strings.ContainsAny(request.FilePath, "\x00\r\n") {
		return nil, errors.New("containerstream: provider requires an absolute file path")
	}
	args, err := p.command(request)
	if err != nil {
		return nil, err
	}
	return p.runner.Open(ctx, Command{Args: args, InheritHostEnv: true})
}

func (p *cliProvider) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	if p == nil || p.runner == nil {
		return nil, errors.New("containerstream: unavailable provider")
	}
	duplex, ok := p.runner.(DuplexCommandRunner)
	if !ok {
		return nil, fmt.Errorf("%w: %s command runner", ErrExecutionUnsupported, p.name)
	}
	if _, err := safeAdapterToken("target", request.TargetID); err != nil {
		return nil, err
	}
	if err := validateProcessSpec(spec); err != nil {
		return nil, err
	}
	if spec.TTY {
		return nil, fmt.Errorf("%w: %s CLI fallback cannot expose a remote TTY", ErrControlUnsupported, p.name)
	}
	args, err := p.processCommand(request, spec)
	if err != nil {
		return nil, err
	}
	process, err := duplex.Start(ctx, Command{Args: args, InheritHostEnv: true})
	if err != nil {
		return nil, err
	}
	if process == nil {
		return nil, errors.New("containerstream: command runner returned a nil process")
	}
	capabilities := process.Capabilities()
	capabilities.TTY = false
	capabilities.Signals = false
	capabilities.Resize = false
	capabilities.Terminate = false
	return &providerProcess{name: p.name, Process: process, capabilities: &capabilities}, nil
}

type providerProcess struct {
	name         string
	capabilities *ProcessCapabilities
	Process
}

func (p *providerProcess) ProviderName() string { return p.name }
func (p *providerProcess) Capabilities() ProcessCapabilities {
	if p.capabilities != nil {
		return *p.capabilities
	}
	return p.Process.Capabilities()
}

func (p *cliProvider) command(request Request) ([]string, error) {
	if err := p.validateOptions(request); err != nil {
		return nil, err
	}
	option := func(name string) (string, error) {
		value := strings.TrimSpace(request.Options[name])
		if value == "" {
			return "", nil
		}
		return safeAdapterToken(name, value)
	}

	switch p.flavor {
	case flavorKubernetes, flavorRancher:
		args := []string{p.binary}
		if p.flavor == flavorRancher {
			args = append(args, "kubectl")
		}
		contextName, err := option("context")
		if err != nil {
			return nil, err
		}
		if contextName != "" {
			args = append(args, "--context", contextName)
		}
		namespace, err := option("namespace")
		if err != nil {
			return nil, err
		}
		if namespace != "" {
			args = append(args, "--namespace", namespace)
		}
		args = append(args, "exec", request.TargetID)
		container, err := option("container")
		if err != nil {
			return nil, err
		}
		if container != "" {
			args = append(args, "--container", container)
		}
		return append(args, "--", "cat", "--", request.FilePath), nil
	case flavorCRI:
		args := []string{p.binary}
		endpoint := strings.TrimSpace(request.Options["runtime-endpoint"])
		if endpoint != "" {
			if len(endpoint) > 1024 || strings.ContainsAny(endpoint, "\x00\r\n") {
				return nil, errors.New("containerstream: invalid CRI runtime endpoint")
			}
			args = append(args, "--runtime-endpoint="+endpoint)
		}
		return append(args, "exec", request.TargetID, "cat", "--", request.FilePath), nil
	case flavorDocker:
		args := []string{p.binary}
		contextName, err := option("context")
		if err != nil {
			return nil, err
		}
		if contextName != "" {
			args = append(args, "--context", contextName)
		}
		return append(args, "exec", request.TargetID, "cat", "--", request.FilePath), nil
	case flavorPodman:
		args := []string{p.binary}
		connection, err := option("connection")
		if err != nil {
			return nil, err
		}
		if connection != "" {
			args = append(args, "--connection", connection)
		}
		return append(args, "exec", request.TargetID, "cat", "--", request.FilePath), nil
	case flavorNomad:
		args := []string{p.binary, "alloc", "exec", "-i=false", "-t=false"}
		namespace, err := option("namespace")
		if err != nil {
			return nil, err
		}
		if namespace != "" {
			args = append(args, "-namespace="+namespace)
		}
		task, err := option("task")
		if err != nil {
			return nil, err
		}
		if task != "" {
			args = append(args, "-task="+task)
		}
		return append(args, request.TargetID, "cat", "--", request.FilePath), nil
	default:
		return nil, fmt.Errorf("containerstream: unsupported CLI provider %q", p.name)
	}
}

func (p *cliProvider) processCommand(request Request, spec ProcessSpec) ([]string, error) {
	if err := p.validateOptions(request); err != nil {
		return nil, err
	}
	option := func(name string) (string, error) {
		value := strings.TrimSpace(request.Options[name])
		if value == "" {
			return "", nil
		}
		return safeAdapterToken(name, value)
	}
	remote := remoteArgv(spec)
	switch p.flavor {
	case flavorKubernetes, flavorRancher:
		args := []string{p.binary}
		if p.flavor == flavorRancher {
			args = append(args, "kubectl")
		}
		contextName, err := option("context")
		if err != nil {
			return nil, err
		}
		if contextName != "" {
			args = append(args, "--context", contextName)
		}
		namespace, err := option("namespace")
		if err != nil {
			return nil, err
		}
		if namespace != "" {
			args = append(args, "--namespace", namespace)
		}
		args = append(args, "exec", "--stdin", request.TargetID)
		container, err := option("container")
		if err != nil {
			return nil, err
		}
		if container != "" {
			args = append(args, "--container", container)
		}
		return append(append(args, "--"), remote...), nil
	case flavorCRI:
		args := []string{p.binary}
		endpoint := strings.TrimSpace(request.Options["runtime-endpoint"])
		if endpoint != "" {
			if len(endpoint) > 1024 || strings.ContainsAny(endpoint, "\x00\r\n") {
				return nil, errors.New("containerstream: invalid CRI runtime endpoint")
			}
			args = append(args, "--runtime-endpoint="+endpoint)
		}
		return append(append(args, "exec", "-i", request.TargetID), remote...), nil
	case flavorDocker:
		args := []string{p.binary}
		contextName, err := option("context")
		if err != nil {
			return nil, err
		}
		if contextName != "" {
			args = append(args, "--context", contextName)
		}
		return append(append(args, "exec", "--interactive", request.TargetID), remote...), nil
	case flavorPodman:
		args := []string{p.binary}
		connection, err := option("connection")
		if err != nil {
			return nil, err
		}
		if connection != "" {
			args = append(args, "--connection", connection)
		}
		return append(append(args, "exec", "--interactive", request.TargetID), remote...), nil
	case flavorNomad:
		args := []string{p.binary, "alloc", "exec", "-i=true", "-t=false"}
		namespace, err := option("namespace")
		if err != nil {
			return nil, err
		}
		if namespace != "" {
			args = append(args, "-namespace="+namespace)
		}
		task, err := option("task")
		if err != nil {
			return nil, err
		}
		if task != "" {
			args = append(args, "-task="+task)
		}
		return append(append(args, request.TargetID), remote...), nil
	default:
		return nil, fmt.Errorf("containerstream: unsupported CLI provider %q", p.name)
	}
}

func (p *cliProvider) validateOptions(request Request) error {
	allowedOptions := map[cliFlavor]map[string]bool{
		flavorKubernetes: {"context": true, "namespace": true, "container": true},
		flavorRancher:    {"context": true, "namespace": true, "container": true},
		flavorCRI:        {"runtime-endpoint": true},
		flavorDocker:     {"context": true},
		flavorPodman:     {"connection": true},
		flavorNomad:      {"namespace": true, "task": true},
	}
	for name := range request.Options {
		if !allowedOptions[p.flavor][name] {
			return fmt.Errorf("containerstream: provider %s does not support option %q", p.name, name)
		}
	}
	return nil
}
