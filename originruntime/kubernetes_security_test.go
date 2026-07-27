package originruntime

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestKubernetesExecutionOnlyRejectsUnusedPathMappings(t *testing.T) {
	pod := runningKubernetesPod("uid-mapping")
	payload, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "unmapped", Kind: KindKubernetes, GuestRoot: "/workspace",
		PathMappings: []PathMapping{{Host: t.TempDir(), Guest: "/outputs"}},
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker"},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: payload}})
	if err == nil || !strings.Contains(err.Error(), "execution-only runtime cannot include path_mappings") {
		t.Fatalf("err=%v", err)
	}
}

func TestKubernetesHostPathRejectsBackslashSubPath(t *testing.T) {
	hostPath := t.TempDir()
	pod := runningKubernetesPod("uid-subpath")
	pod.Spec.Containers[0].VolumeMounts = []kubernetesVolumeMount{{
		Name: "workspace", MountPath: "/workspace", SubPath: `..\escape`,
	}}
	volume := kubernetesVolume{Name: "workspace"}
	volume.HostPath = &struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}{Path: hostPath, Type: "Directory"}
	pod.Spec.Volumes = []kubernetesVolume{volume}
	payload, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "ambiguous-subpath", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{
			Namespace: "jobs", Pod: "processor-0", Container: "worker",
			ExpectedNode: "origin-node", AllowHostPathDiscovery: true,
		},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: payload}})
	if err == nil || !strings.Contains(err.Error(), "backslash ambiguity") {
		t.Fatalf("err=%v", err)
	}
	_ = os.RemoveAll(hostPath)
}
