package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// ErrFastPathUnavailable lets a socket/API provider request the portable CLI
// fallback without masking authorization, protocol, or target errors.
var ErrFastPathUnavailable = errors.New("containerstream: provider fast path unavailable")

type hybridProvider struct {
	name string
	fast Provider
	safe Provider
}

// NewHybridProvider composes an API/socket fast path with a portable safe path.
// Fallback occurs only for ErrFastPathUnavailable; all other fast-path errors
// are returned unchanged so authorization failures never downgrade silently.
func NewHybridProvider(name string, fast, safe Provider) (Provider, error) {
	name = normalizeProviderName(name)
	if !providerNamePattern.MatchString(name) || fast == nil || safe == nil {
		return nil, errors.New("containerstream: invalid hybrid provider")
	}
	return &hybridProvider{name: name, fast: fast, safe: safe}, nil
}

func (p *hybridProvider) Name() string { return p.name }

// Discover merges transport evidence without probing either endpoint. A
// socket makes the fast path usable, while an executable CLI makes the safe
// path usable; a host with both receives the combined deterministic score.
func (p *hybridProvider) Discover(probe Probe) Candidate {
	if probe == nil {
		probe = OSProbe{}
	}
	candidate := Candidate{Provider: p.name}
	merge := func(next Candidate) {
		candidate.Available = candidate.Available || next.Available
		candidate.Score += next.Score
		candidate.Artifacts = append(candidate.Artifacts, next.Artifacts...)
	}
	if discoverable, ok := p.fast.(DiscoverableProvider); ok {
		merge(discoverable.Discover(probe))
	}
	if discoverable, ok := p.safe.(DiscoverableProvider); ok {
		merge(discoverable.Discover(probe))
	} else if cli, ok := p.safe.(*cliProvider); ok {
		if resolved, err := probe.LookPath(cli.binary); err == nil && strings.TrimSpace(resolved) != "" {
			const cliWeight = 55
			merge(Candidate{
				Available: true,
				Score:     cliWeight,
				Artifacts: []Artifact{{Kind: "binary", Value: resolved, Weight: cliWeight}},
			})
		}
	}
	return normalizeCandidate(p.name, candidate)
}

func (p *hybridProvider) OpenContainerStream(ctx context.Context, request Request) (io.ReadCloser, error) {
	stream, err := p.fast.OpenContainerStream(ctx, request)
	if err == nil || !errors.Is(err, ErrFastPathUnavailable) {
		return stream, err
	}
	return p.safe.OpenContainerStream(ctx, request)
}

func (p *hybridProvider) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	fast, ok := p.fast.(ExecutionProvider)
	if ok {
		process, err := fast.StartContainerProcess(ctx, request, spec)
		if err == nil || !errors.Is(err, ErrFastPathUnavailable) {
			if process != nil {
				process = &providerProcess{name: p.name, Process: process}
			}
			return process, err
		}
	}
	safe, ok := p.safe.(ExecutionProvider)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrExecutionUnsupported, p.name)
	}
	process, err := safe.StartContainerProcess(ctx, request, spec)
	if process != nil {
		process = &providerProcess{name: p.name, Process: process}
	}
	return process, err
}

type DiscoveryMode string

const (
	// ModeLocked discovers once and keeps the provider stable for the lifetime
	// of the router. This is the default for a long-running wv-agent.
	ModeLocked DiscoveryMode = "locked"
	// ModePerRequest re-runs discovery before every request.
	ModePerRequest DiscoveryMode = "per-request"
)

type RouterConfig struct {
	Mode     DiscoveryMode
	Provider string
}

type Router struct {
	registry   *Registry
	discoverer Discoverer
	mode       DiscoveryMode
	configured string

	mu        sync.Mutex
	selected  string
	discovery Discovery
}

func NewRouter(registry *Registry, discoverer Discoverer, config RouterConfig) (*Router, error) {
	if registry == nil {
		registry = NewDefaultRegistry(nil)
	}
	discoverer.Registry = registry
	mode := DiscoveryMode(strings.ToLower(strings.TrimSpace(string(config.Mode))))
	if mode == "" {
		mode = ModeLocked
	}
	if mode != ModeLocked && mode != ModePerRequest {
		return nil, fmt.Errorf("containerstream: unsupported discovery mode %q", mode)
	}
	configured := normalizeProviderName(config.Provider)
	if configured != "" {
		if _, ok := registry.Provider(configured); !ok {
			return nil, fmt.Errorf("containerstream: configured provider %q is not registered", configured)
		}
	}
	return &Router{registry: registry, discoverer: discoverer, mode: mode, configured: configured}, nil
}

func NewEnvironmentRouter() (*Router, error) {
	registry := NewDefaultRegistry(nil)
	return NewRouter(registry, Discoverer{Probe: OSProbe{}, Registry: registry}, RouterConfig{
		Mode:     DiscoveryMode(strings.TrimSpace(getenv(EnvDiscoveryMode))),
		Provider: strings.TrimSpace(getenv(EnvProvider)),
	})
}

var getenv = func(name string) string {
	value, _ := OSProbe{}.LookupEnv(name)
	return value
}

// Open routes one parsed request. An explicit URI provider hint has request
// scope and does not mutate the locked provider.
func (r *Router) Open(ctx context.Context, request Request) (io.ReadCloser, error) {
	_, provider, err := r.providerFor(request)
	if err != nil {
		return nil, err
	}
	return provider.OpenContainerStream(ctx, request)
}

// StartContainerProcess routes an authorized process spec through the same
// provider selection used by read-only streams.
func (r *Router) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	if err := validateProcessSpec(spec); err != nil {
		return nil, err
	}
	name, provider, err := r.providerFor(request)
	if err != nil {
		return nil, err
	}
	execution, ok := provider.(ExecutionProvider)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrExecutionUnsupported, name)
	}
	process, err := execution.StartContainerProcess(ctx, request, spec)
	if err == nil && process == nil {
		return nil, fmt.Errorf("containerstream: provider %q returned a nil process", name)
	}
	return process, err
}

func (r *Router) providerFor(request Request) (string, Provider, error) {
	if r == nil || r.registry == nil {
		return "", nil, errors.New("containerstream: router unavailable")
	}
	name := normalizeProviderName(request.ProviderHint)
	if name == "" {
		var err error
		name, err = r.selectProvider()
		if err != nil {
			return "", nil, err
		}
	}
	provider, ok := r.registry.Provider(name)
	if !ok {
		return "", nil, fmt.Errorf("containerstream: provider %q is not registered", name)
	}
	return name, provider, nil
}

// Refresh explicitly re-runs discovery and replaces a locked selection. It is
// intended for controlled agent reloads, not implicit mid-stream switching.
func (r *Router) Refresh() (Discovery, error) {
	if r == nil {
		return Discovery{}, errors.New("containerstream: router unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refreshLocked()
}

func (r *Router) Status() Discovery {
	if r == nil {
		return Discovery{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.discovery.Candidates == nil {
		_, _ = r.refreshLocked()
	}
	return cloneDiscovery(r.discovery)
}

func (r *Router) selectProvider() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.configured != "" {
		return r.configured, nil
	}
	if r.mode == ModeLocked && r.selected != "" {
		return r.selected, nil
	}
	discovery, err := r.refreshLocked()
	if err != nil {
		return "", err
	}
	return discovery.Selected, nil
}

func (r *Router) refreshLocked() (Discovery, error) {
	discovery := r.discoverer.Discover()
	if r.configured != "" {
		discovery.Selected = r.configured
	}
	r.discovery = cloneDiscovery(discovery)
	r.selected = discovery.Selected
	if discovery.Selected == "" {
		return cloneDiscovery(discovery), ErrNoProvider
	}
	return cloneDiscovery(discovery), nil
}

func cloneDiscovery(discovery Discovery) Discovery {
	out := Discovery{Selected: discovery.Selected, Candidates: make([]Candidate, len(discovery.Candidates))}
	for index, candidate := range discovery.Candidates {
		out.Candidates[index] = candidate
		out.Candidates[index].Artifacts = append([]Artifact(nil), candidate.Artifacts...)
	}
	return out
}
