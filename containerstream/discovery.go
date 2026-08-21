package containerstream

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	EnvProvider      = "WEAVERSSH_CONTAINER_PROVIDER"
	EnvDiscoveryMode = "WEAVERSSH_CONTAINER_DISCOVERY_MODE"
)

// Artifact records one bounded signal used to score a provider.
type Artifact struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Weight int    `json:"weight"`
}

// Candidate is a deterministic discovery result. Available means the current
// implementation has an executable transport, not merely a matching socket.
type Candidate struct {
	Provider  string     `json:"provider"`
	Score     int        `json:"score"`
	Available bool       `json:"available"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

type Discovery struct {
	Selected   string      `json:"selected,omitempty"`
	Candidates []Candidate `json:"candidates"`
}

// Probe isolates environment, socket, and PATH inspection for deterministic
// tests and embedded agents with a restricted host view.
type Probe interface {
	LookupEnv(string) (string, bool)
	LookPath(string) (string, error)
	Socket(string) bool
}

type OSProbe struct{}

func (OSProbe) LookupEnv(name string) (string, bool) { return os.LookupEnv(name) }
func (OSProbe) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (OSProbe) RegularFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}
func (OSProbe) Socket(name string) bool {
	info, err := os.Lstat(name)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode()&os.ModeSocket != 0
}

// DiscoverableProvider lets a plugin supply its own bounded availability
// probe. The discoverer overwrites Candidate.Provider with Provider.Name and
// validates the returned score and artifact count.
type DiscoverableProvider interface {
	Provider
	Discover(Probe) Candidate
}

type Discoverer struct {
	Probe    Probe
	Registry *Registry
}

func (d Discoverer) Discover() Discovery {
	probe := d.Probe
	if probe == nil {
		probe = OSProbe{}
	}
	registry := d.Registry
	if registry == nil {
		registry = NewDefaultRegistry(nil)
	}

	type candidateSpec struct {
		name     string
		binaries []weightedValue
		env      []weightedValue
		sockets  []weightedValue
	}
	specs := []candidateSpec{
		{name: ProviderRancher, binaries: []weightedValue{{"k3s", 70}}, env: []weightedValue{{"K3S_URL", 25}, {"K3S_TOKEN", 10}}, sockets: []weightedValue{{"/run/k3s/containerd/containerd.sock", 25}}},
		{name: ProviderPodman, binaries: []weightedValue{{"podman", 55}}, env: []weightedValue{{"CONTAINER_HOST", 20}}, sockets: []weightedValue{{podmanSocket(probe), 45}, {"/run/podman/podman.sock", 20}}},
		{name: ProviderKubernetes, binaries: []weightedValue{{"kubectl", 55}}, env: []weightedValue{{"KUBECONFIG", 30}, {"KUBERNETES_SERVICE_HOST", 25}}, sockets: []weightedValue{{"/run/containerd/containerd.sock", 10}, {"/var/run/crio/crio.sock", 10}}},
		{name: ProviderCRI, binaries: []weightedValue{{"crictl", 55}}, env: []weightedValue{{"CONTAINER_RUNTIME_ENDPOINT", 35}}, sockets: []weightedValue{{"/run/containerd/containerd.sock", 25}, {"/var/run/crio/crio.sock", 25}}},
		{name: ProviderDocker, binaries: []weightedValue{{"docker", 55}}, env: []weightedValue{{"DOCKER_HOST", 30}}, sockets: []weightedValue{{"/var/run/docker.sock", 35}}},
		{name: ProviderNomad, binaries: []weightedValue{{"nomad", 55}}, env: []weightedValue{{"NOMAD_ADDR", 35}, {"NOMAD_TOKEN", 5}}},
	}

	discovery := Discovery{}
	seen := map[string]bool{}
	for _, spec := range specs {
		provider, registered := registry.Provider(spec.name)
		if !registered {
			continue
		}
		seen[spec.name] = true
		if discoverable, ok := provider.(DiscoverableProvider); ok {
			discovery.Candidates = append(discovery.Candidates, normalizeCandidate(spec.name, discoverable.Discover(probe)))
			continue
		}
		candidate := Candidate{Provider: spec.name}
		for _, item := range spec.binaries {
			if resolved, err := probe.LookPath(item.value); err == nil && strings.TrimSpace(resolved) != "" {
				candidate.Available = true
				candidate.Score += item.weight
				candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "binary", Value: resolved, Weight: item.weight})
			}
		}
		for _, item := range spec.env {
			if value, ok := probe.LookupEnv(item.value); ok && strings.TrimSpace(value) != "" {
				candidate.Score += item.weight
				candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "environment", Value: item.value, Weight: item.weight})
			}
		}
		for _, item := range spec.sockets {
			if item.value != "" && probe.Socket(item.value) {
				candidate.Score += item.weight
				candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "socket", Value: item.value, Weight: item.weight})
			}
		}
		discovery.Candidates = append(discovery.Candidates, candidate)
	}
	for _, name := range registry.Names() {
		if seen[name] {
			continue
		}
		provider, _ := registry.Provider(name)
		candidate := Candidate{Provider: name}
		if discoverable, ok := provider.(DiscoverableProvider); ok {
			candidate = normalizeCandidate(name, discoverable.Discover(probe))
		}
		discovery.Candidates = append(discovery.Candidates, candidate)
	}
	sort.SliceStable(discovery.Candidates, func(i, j int) bool {
		left, right := discovery.Candidates[i], discovery.Candidates[j]
		if left.Available != right.Available {
			return left.Available
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		return left.Provider < right.Provider
	})
	for _, candidate := range discovery.Candidates {
		if candidate.Available {
			discovery.Selected = candidate.Provider
			break
		}
	}
	return discovery
}

func normalizeCandidate(name string, candidate Candidate) Candidate {
	candidate.Provider = name
	if candidate.Score < 0 {
		candidate.Score = 0
	}
	if candidate.Score > 10_000 {
		candidate.Score = 10_000
	}
	if len(candidate.Artifacts) > 64 {
		candidate.Artifacts = append([]Artifact(nil), candidate.Artifacts[:64]...)
	}
	for index := range candidate.Artifacts {
		artifact := &candidate.Artifacts[index]
		artifact.Kind = strings.TrimSpace(artifact.Kind)
		artifact.Value = strings.TrimSpace(artifact.Value)
		if len(artifact.Kind) > 64 {
			artifact.Kind = artifact.Kind[:64]
		}
		if len(artifact.Value) > 1024 {
			artifact.Value = artifact.Value[:1024]
		}
		artifact.Kind = strings.NewReplacer("\n", "", "\r", "", "\x00", "").Replace(artifact.Kind)
		artifact.Value = strings.NewReplacer("\n", "", "\r", "", "\x00", "").Replace(artifact.Value)
	}
	return candidate
}

type weightedValue struct {
	value  string
	weight int
}

func podmanSocket(probe Probe) string {
	value, ok := probe.LookupEnv("XDG_RUNTIME_DIR")
	value = strings.TrimSpace(value)
	if !ok || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Join(filepath.Clean(value), "podman", "podman.sock")
}

var ErrNoProvider = errors.New("containerstream: no usable orchestration provider discovered")
