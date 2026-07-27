package originruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func runningKubernetesPod(uid string) kubernetesPod {
	var pod kubernetesPod
	pod.Metadata.Name = "processor-0"
	pod.Metadata.Namespace = "jobs"
	pod.Metadata.UID = uid
	pod.Spec.NodeName = "origin-node"
	pod.Spec.Containers = []kubernetesContainer{{Name: "worker"}}
	pod.Status.Phase = "Running"
	pod.Status.Conditions = []kubernetesPodCondition{{Type: "Ready", Status: "True"}}
	status := kubernetesContainerStatus{Name: "worker", Ready: true}
	status.State.Running = &struct {
		StartedAt string `json:"startedAt"`
	}{StartedAt: "2026-07-25T00:00:00Z"}
	pod.Status.ContainerStatuses = []kubernetesContainerStatus{status}
	return pod
}

func marshalKubernetes(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestKubernetesExecutionOnlyRuntimeUsesDirectKubectlExec(t *testing.T) {
	pod := runningKubernetesPod("uid-a")
	payload := marshalKubernetes(t, pod)
	runner := &fakeRunner{results: []RunResult{{Stdout: payload}, {Stdout: payload}, {Stdout: []byte("done")}}}
	config := Config{
		Version: ConfigVersion, Name: "k8s-job", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Context: "development", Namespace: "jobs", Pod: "processor-0", Container: "worker", RequireRunning: true, RequireReady: true},
	}
	runtime, err := Resolve(context.Background(), config, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := runtime.Descriptor()
	if !HasCapability(descriptor, CapabilityExec) || HasCapability(descriptor, CapabilityFilesystem) || descriptor.HostRoot != "" || len(descriptor.PathMappings) != 0 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	if descriptor.Attributes["kubernetes.pod_uid"] != "uid-a" || descriptor.Attributes["kubernetes.container"] != "worker" {
		t.Fatalf("attributes=%v", descriptor.Attributes)
	}
	result, err := runtime.Exec(context.Background(), ExecRequest{Command: []string{"processor", "input.dat"}, Environment: map[string]string{"MODE": "safe"}})
	if err != nil || string(result.Stdout) != "done" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"kubectl", "--context", "development", "--namespace", "jobs", "exec", "processor-0", "--container", "worker", "--", "/usr/bin/env", "--", "MODE=safe", "processor", "input.dat"}
	if !reflect.DeepEqual(runner.requests[2].Args, want) {
		t.Fatalf("args=%q", runner.requests[2].Args)
	}
}

func TestKubernetesSelectorRequiresExactlyOnePod(t *testing.T) {
	list := kubernetesPodList{Items: []kubernetesPod{runningKubernetesPod("a"), runningKubernetesPod("b")}}
	_, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "selector", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Selector: "app=processor"},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: marshalKubernetes(t, list)}})
	if err == nil || !strings.Contains(err.Error(), "exactly one pod") {
		t.Fatalf("err=%v", err)
	}
}

func TestKubernetesUsesDefaultContainerAnnotation(t *testing.T) {
	pod := runningKubernetesPod("uid-default")
	pod.Metadata.Annotations = map[string]string{kubernetesDefaultContainerAnnotation: "worker"}
	payload := marshalKubernetes(t, kubernetesPodList{Items: []kubernetesPod{pod}})
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "selector-default", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Selector: "app=processor"},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: payload}})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Descriptor().Attributes["kubernetes.container"] != "worker" {
		t.Fatalf("descriptor=%+v", runtime.Descriptor())
	}
}

func TestKubernetesExecutionPreflightRejectsPodReplacement(t *testing.T) {
	first := marshalKubernetes(t, runningKubernetesPod("uid-original"))
	replacement := marshalKubernetes(t, runningKubernetesPod("uid-replacement"))
	runner := &fakeRunner{results: []RunResult{{Stdout: first}, {Stdout: replacement}}}
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "uid-bound", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker"},
	}, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Exec(context.Background(), ExecRequest{Command: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("err=%v", err)
	}
	if len(runner.requests) != 2 {
		t.Fatalf("requests=%d", len(runner.requests))
	}
}

func TestKubernetesExplicitHostRootSupportsSharedStorage(t *testing.T) {
	hostRoot := t.TempDir()
	pod := runningKubernetesPod("uid-pvc")
	pod.Spec.Containers[0].VolumeMounts = []kubernetesVolumeMount{{Name: "workspace", MountPath: "/workspace"}}
	pod.Spec.Volumes = []kubernetesVolume{{Name: "workspace"}}
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "pvc-origin", Kind: KindKubernetes,
		GuestRoot: "/workspace", HostRoot: hostRoot,
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker", ExpectedNode: "origin-node"},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: marshalKubernetes(t, pod)}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := runtime.Descriptor()
	if descriptor.HostRoot != hostRoot || !HasCapability(descriptor, CapabilityFilesystem) || !HasCapability(descriptor, CapabilityExec) {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestKubernetesHostPathDiscoveryIsNodeBoundAndReadOnly(t *testing.T) {
	hostPath := t.TempDir()
	project := filepath.Join(hostPath, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	pod := runningKubernetesPod("uid-hostpath")
	pod.Spec.Containers[0].VolumeMounts = []kubernetesVolumeMount{{Name: "workspace", MountPath: "/workspace", ReadOnly: true}}
	volume := kubernetesVolume{Name: "workspace"}
	volume.HostPath = &struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}{Path: hostPath, Type: "Directory"}
	pod.Spec.Volumes = []kubernetesVolume{volume}
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "hostpath-origin", Kind: KindKubernetes, GuestRoot: "/workspace/project",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker", ExpectedNode: "origin-node", AllowHostPathDiscovery: true},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: marshalKubernetes(t, pod)}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := runtime.Descriptor()
	if descriptor.HostRoot != project || !descriptor.ReadOnly || !HasCapability(descriptor, CapabilityPathMap) {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestKubernetesRequireReadyRejectsUnreadyContainer(t *testing.T) {
	pod := runningKubernetesPod("uid-unready")
	pod.Status.ContainerStatuses[0].Ready = false
	_, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "unready", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker", RequireReady: true},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: marshalKubernetes(t, pod)}})
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("err=%v", err)
	}
}

func TestKubernetesRejectsWorkingDirectoryWithoutShell(t *testing.T) {
	pod := runningKubernetesPod("uid-dir")
	runner := &fakeRunner{results: []RunResult{{Stdout: marshalKubernetes(t, pod)}, {Stdout: marshalKubernetes(t, pod)}}}
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "no-cd", Kind: KindKubernetes, GuestRoot: "/workspace",
		Kubernetes: &KubernetesConfig{Namespace: "jobs", Pod: "processor-0", Container: "worker"},
	}, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Exec(context.Background(), ExecRequest{Command: []string{"true"}, Directory: "/workspace"})
	if err == nil || !strings.Contains(err.Error(), "does not support changing") {
		t.Fatalf("err=%v", err)
	}
}
