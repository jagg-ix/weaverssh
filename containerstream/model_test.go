package containerstream

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestParseURIProviderNeutralTarget(t *testing.T) {
	request, err := ParseURI("vfs://container/rancher-node/pod-abc/data/archive.bin?provider=k3s&namespace=jobs&container=worker")
	if err != nil {
		t.Fatal(err)
	}
	if request.Endpoint != "rancher-node" || request.TargetID != "pod-abc" || request.FilePath != "/data/archive.bin" {
		t.Fatalf("request=%+v", request)
	}
	if request.ProviderHint != "k3s" || request.Options["namespace"] != "jobs" || request.Options["container"] != "worker" {
		t.Fatalf("provider/options=%q %#v", request.ProviderHint, request.Options)
	}
}

func TestParseURIRejectsTraversalAndOptionInjection(t *testing.T) {
	for _, raw := range []string{
		"vfs://container/node/pod/../secret",
		"vfs://container/node/%2dexec/data",
		"vfs://container/node/pod/data?namespace=-all",
		"vfs://other/node/pod/data",
	} {
		request, err := ParseURI(raw)
		if err == nil {
			if _, optionErr := safeAdapterToken("namespace", request.Options["namespace"]); optionErr == nil {
				t.Fatalf("ParseURI(%q) unexpectedly accepted: %+v", raw, request)
			}
		}
	}
}

type staticProvider struct{ name, payload string }

func (p staticProvider) Name() string { return p.name }
func (p staticProvider) OpenContainerStream(context.Context, Request) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(p.payload)), nil
}

func TestRegistryAliases(t *testing.T) {
	registry := NewRegistry()
	registry.MustRegister(staticProvider{name: "kubernetes", payload: "ok"}, "k8s")
	provider, ok := registry.Provider("K8S")
	if !ok || provider.Name() != "kubernetes" {
		t.Fatalf("provider=%v ok=%t", provider, ok)
	}
	if err := registry.Register(staticProvider{name: "other"}, "k8s"); err == nil {
		t.Fatal("expected duplicate alias rejection")
	}
	if err := registry.Replace(staticProvider{name: "kubernetes", payload: "replacement"}); err != nil {
		t.Fatal(err)
	}
	provider, ok = registry.Provider("k8s")
	if !ok {
		t.Fatal("replacement alias missing")
	}
	stream, _ := provider.OpenContainerStream(context.Background(), Request{})
	payload, _ := io.ReadAll(stream)
	if string(payload) != "replacement" {
		t.Fatalf("replacement payload=%q", payload)
	}
}
