package originruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubernetesConfigRequiresPodOrSelector(t *testing.T) {
	for _, kubernetes := range []*KubernetesConfig{
		{Namespace: "jobs"},
		{Namespace: "jobs", Pod: "processor-0", Selector: "app=processor"},
	} {
		config := Config{Version: ConfigVersion, Name: "invalid-k8s", Kind: KindKubernetes, GuestRoot: "/workspace", Kubernetes: kubernetes}
		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("config=%+v err=%v", kubernetes, err)
		}
	}
}

func TestKubernetesHostPathDiscoveryRequiresExpectedNode(t *testing.T) {
	config := Config{
		Version: ConfigVersion, Name: "unsafe-hostpath", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", AllowHostPathDiscovery: true},
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "expected_node") {
		t.Fatalf("err=%v", err)
	}
}

func TestKubernetesConfigFileResolvesRelativeKubeconfig(t *testing.T) {
	root := t.TempDir()
	kubeconfig := filepath.Join(root, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "runtime.json")
	payload := `{
  "version": "weaverssh.origin-runtime.v1",
  "name": "k8s-relative",
  "kind": "kubernetes",
  "guest_root": "/workspace",
  "kubernetes": {
    "kubeconfig": "kubeconfig",
    "namespace": "jobs",
    "pod": "processor-0"
  }
}`
	if err := os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	config, _, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Kubernetes.Kubeconfig != kubeconfig {
		t.Fatalf("kubeconfig=%q", config.Kubernetes.Kubeconfig)
	}
}
