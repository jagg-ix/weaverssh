package containerstream

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type errorProvider struct {
	name string
	err  error
}

type discoverableStaticProvider struct {
	staticProvider
	candidate Candidate
}

func (p discoverableStaticProvider) Discover(Probe) Candidate { return p.candidate }

func (p errorProvider) Name() string { return p.name }
func (p errorProvider) OpenContainerStream(context.Context, Request) (io.ReadCloser, error) {
	return nil, p.err
}

type fakeProbe struct {
	env     map[string]string
	binary  map[string]string
	sockets map[string]bool
}

func (p *fakeProbe) LookupEnv(name string) (string, bool) { value, ok := p.env[name]; return value, ok }
func (p *fakeProbe) LookPath(name string) (string, error) {
	if value := p.binary[name]; value != "" {
		return value, nil
	}
	return "", errors.New("missing")
}
func (p *fakeProbe) Socket(name string) bool { return p.sockets[name] }

type fakeFileProbe struct {
	*fakeProbe
	files map[string]bool
}

func (p *fakeFileProbe) RegularFile(name string) bool { return p.files[name] }

func TestKubernetesNativeConfigIsExecutableDiscoveryEvidence(t *testing.T) {
	probe := &fakeFileProbe{
		fakeProbe: &fakeProbe{env: map[string]string{"HOME": "/home/agent"}, binary: map[string]string{}, sockets: map[string]bool{}},
		files:     map[string]bool{"/home/agent/.kube/config": true},
	}
	discovery := (Discoverer{Probe: probe, Registry: NewDefaultRegistry(nil)}).Discover()
	if discovery.Selected != ProviderKubernetes {
		t.Fatalf("selected=%q candidates=%+v", discovery.Selected, discovery.Candidates)
	}
	for _, candidate := range discovery.Candidates {
		if candidate.Provider == ProviderKubernetes {
			if !candidate.Available || candidate.Score != 20 {
				t.Fatalf("kubernetes candidate=%+v", candidate)
			}
			return
		}
	}
	t.Fatal("kubernetes candidate missing")
}

func TestDiscoveryPrefersRootlessPodmanEvidence(t *testing.T) {
	probe := &fakeProbe{
		env:     map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"},
		binary:  map[string]string{"podman": "/usr/bin/podman", "docker": "/usr/bin/docker"},
		sockets: map[string]bool{"/run/user/1000/podman/podman.sock": true, "/var/run/docker.sock": true},
	}
	discovery := (Discoverer{Probe: probe, Registry: NewDefaultRegistry(nil)}).Discover()
	if discovery.Selected != ProviderPodman {
		t.Fatalf("selected=%q candidates=%+v", discovery.Selected, discovery.Candidates)
	}
}

func TestDockerSocketWithoutExecutableSelectsEngineFastPath(t *testing.T) {
	probe := &fakeProbe{env: map[string]string{}, binary: map[string]string{}, sockets: map[string]bool{"/var/run/docker.sock": true}}
	discovery := (Discoverer{Probe: probe, Registry: NewDefaultRegistry(nil)}).Discover()
	if discovery.Selected != ProviderDocker {
		t.Fatalf("selected=%q", discovery.Selected)
	}
	for _, candidate := range discovery.Candidates {
		if candidate.Provider == ProviderDocker && (!candidate.Available || candidate.Score != 35) {
			t.Fatalf("docker candidate=%+v", candidate)
		}
	}
}

func TestHybridDiscoveryCombinesSocketAndCLIEvidence(t *testing.T) {
	probe := &fakeProbe{
		env:     map[string]string{},
		binary:  map[string]string{"docker": "/usr/bin/docker"},
		sockets: map[string]bool{"/var/run/docker.sock": true},
	}
	discovery := (Discoverer{Probe: probe, Registry: NewDefaultRegistry(nil)}).Discover()
	for _, candidate := range discovery.Candidates {
		if candidate.Provider == ProviderDocker {
			if !candidate.Available || candidate.Score != 90 || len(candidate.Artifacts) != 2 {
				t.Fatalf("docker candidate=%+v", candidate)
			}
			return
		}
	}
	t.Fatal("docker candidate missing")
}

func TestPluginCanProvideDiscoveryProbe(t *testing.T) {
	registry := NewRegistry()
	registry.MustRegister(discoverableStaticProvider{
		staticProvider: staticProvider{name: "custom-stack", payload: "custom"},
		candidate:      Candidate{Score: 125, Available: true, Artifacts: []Artifact{{Kind: "socket", Value: "/run/custom.sock", Weight: 125}}},
	})
	discovery := (Discoverer{Probe: &fakeProbe{env: map[string]string{}, binary: map[string]string{}, sockets: map[string]bool{}}, Registry: registry}).Discover()
	if discovery.Selected != "custom-stack" || len(discovery.Candidates) != 1 {
		t.Fatalf("discovery=%+v", discovery)
	}
}

func TestRouterLockedAndPerRequestModes(t *testing.T) {
	registry := NewRegistry()
	registry.MustRegister(staticProvider{name: ProviderDocker, payload: "docker"})
	registry.MustRegister(staticProvider{name: ProviderPodman, payload: "podman"})
	probe := &fakeProbe{env: map[string]string{}, binary: map[string]string{"docker": "/bin/docker"}, sockets: map[string]bool{}}
	locked, err := NewRouter(registry, Discoverer{Probe: probe}, RouterConfig{Mode: ModeLocked})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TargetID: "workload", FilePath: "/data"}
	first, err := locked.Open(nil, request)
	if err != nil {
		t.Fatal(err)
	}
	firstPayload, _ := io.ReadAll(first)
	probe.binary = map[string]string{"podman": "/bin/podman"}
	second, err := locked.Open(nil, request)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, _ := io.ReadAll(second)
	if string(firstPayload) != "docker" || string(secondPayload) != "docker" {
		t.Fatalf("locked payloads=%q %q", firstPayload, secondPayload)
	}

	dynamic, err := NewRouter(registry, Discoverer{Probe: probe}, RouterConfig{Mode: ModePerRequest})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := dynamic.Open(nil, request)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(stream)
	if strings.TrimSpace(string(payload)) != "podman" {
		t.Fatalf("dynamic payload=%q", payload)
	}
}

func TestHybridProviderFallsBackOnlyWhenFastPathUnavailable(t *testing.T) {
	hybrid, err := NewHybridProvider("docker", errorProvider{name: "fast", err: ErrFastPathUnavailable}, staticProvider{name: "safe", payload: "fallback"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := hybrid.OpenContainerStream(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(stream)
	if string(payload) != "fallback" {
		t.Fatalf("payload=%q", payload)
	}

	denied := errors.New("permission denied")
	hybrid, err = NewHybridProvider("docker", errorProvider{name: "fast", err: denied}, staticProvider{name: "safe", payload: "unsafe fallback"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hybrid.OpenContainerStream(context.Background(), Request{}); !errors.Is(err, denied) {
		t.Fatalf("err=%v", err)
	}
}
