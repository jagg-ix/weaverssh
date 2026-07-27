package originruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const kubernetesDefaultContainerAnnotation = "kubectl.kubernetes.io/default-container"

type kubernetesResolver struct{}

func (kubernetesResolver) Kind() Kind { return KindKubernetes }

type kubernetesPod struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		DeletionTimestamp string            `json:"deletionTimestamp"`
		Annotations       map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		NodeName   string                `json:"nodeName"`
		Containers []kubernetesContainer `json:"containers"`
		Volumes    []kubernetesVolume    `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Phase             string                      `json:"phase"`
		Conditions        []kubernetesPodCondition    `json:"conditions"`
		ContainerStatuses []kubernetesContainerStatus `json:"containerStatuses"`
	} `json:"status"`
}

type kubernetesPodList struct {
	Items []kubernetesPod `json:"items"`
}

type kubernetesContainer struct {
	Name         string                  `json:"name"`
	VolumeMounts []kubernetesVolumeMount `json:"volumeMounts"`
}

type kubernetesVolumeMount struct {
	Name        string `json:"name"`
	MountPath   string `json:"mountPath"`
	ReadOnly    bool   `json:"readOnly"`
	SubPath     string `json:"subPath"`
	SubPathExpr string `json:"subPathExpr"`
}

type kubernetesVolume struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"hostPath,omitempty"`
}

type kubernetesPodCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type kubernetesContainerStatus struct {
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
	State struct {
		Running *struct {
			StartedAt string `json:"startedAt"`
		} `json:"running,omitempty"`
	} `json:"state"`
}

func (kubernetesResolver) Resolve(ctx context.Context, config Config, digest string, runner Runner) (Descriptor, error) {
	if err := validateKubeconfig(config.Kubernetes.Kubeconfig); err != nil {
		return Descriptor{}, err
	}
	if config.HostRoot == "" && !config.Kubernetes.AllowHostPathDiscovery && len(config.PathMappings) != 0 {
		return Descriptor{}, errors.New("originruntime: Kubernetes execution-only runtime cannot include path_mappings without host_root or hostPath discovery")
	}
	pod, err := resolveKubernetesPod(ctx, config, runner)
	if err != nil {
		return Descriptor{}, err
	}
	container, status, err := selectKubernetesContainer(pod, config.Kubernetes.Container)
	if err != nil {
		return Descriptor{}, err
	}
	if expected := config.Kubernetes.ExpectedNode; expected != "" && strings.TrimSpace(pod.Spec.NodeName) != expected {
		return Descriptor{}, fmt.Errorf("originruntime: Kubernetes pod is scheduled on node %q, expected %q", pod.Spec.NodeName, expected)
	}
	running := kubernetesContainerRunning(pod, status)
	ready := running && status.Ready && kubernetesPodReady(pod)
	if config.Kubernetes.RequireRunning && !running {
		return Descriptor{}, errors.New("originruntime: Kubernetes pod container is not running")
	}
	if config.Kubernetes.RequireReady && !ready {
		return Descriptor{}, errors.New("originruntime: Kubernetes pod container is not ready")
	}

	guestRoot := normalizeGuestPath(config.GuestRoot)
	capabilities := make([]Capability, 0, 3)
	if running {
		capabilities = append(capabilities, CapabilityExec)
	}
	hostRoot := ""
	var mappings []PathMapping
	readOnly := config.ReadOnly
	mount, volume, mounted := selectKubernetesVolume(pod, container, guestRoot)
	if config.HostRoot != "" {
		if !mounted {
			return Descriptor{}, errors.New("originruntime: Kubernetes guest_root is not mounted in the selected container")
		}
		hostRoot, err = canonicalHostDirectory(config.HostRoot)
		if err != nil {
			return Descriptor{}, fmt.Errorf("originruntime: Kubernetes explicit host root: %w", err)
		}
		mappings, err = canonicalMappings(hostRoot, guestRoot, config.PathMappings)
		if err != nil {
			return Descriptor{}, err
		}
		readOnly = readOnly || mount.ReadOnly
		capabilities = append(capabilities, CapabilityFilesystem, CapabilityPathMap)
	} else if config.Kubernetes.AllowHostPathDiscovery {
		if !mounted || volume.HostPath == nil || strings.TrimSpace(volume.HostPath.Path) == "" {
			return Descriptor{}, errors.New("originruntime: Kubernetes guest_root is not backed by a discoverable hostPath volume")
		}
		if strings.TrimSpace(pod.Spec.NodeName) != config.Kubernetes.ExpectedNode {
			return Descriptor{}, errors.New("originruntime: Kubernetes hostPath discovery requires the selected pod on expected_node")
		}
		if mount.SubPathExpr != "" {
			return Descriptor{}, errors.New("originruntime: Kubernetes subPathExpr cannot be resolved safely for hostPath discovery")
		}
		hostBase := strings.TrimSpace(volume.HostPath.Path)
		if !filepath.IsAbs(hostBase) || strings.ContainsAny(hostBase, "\x00\r\n") {
			return Descriptor{}, errors.New("originruntime: Kubernetes hostPath must be an absolute host-visible path")
		}
		if mount.SubPath != "" {
			rawSubPath := strings.TrimSpace(mount.SubPath)
			if strings.Contains(rawSubPath, "\\") {
				return Descriptor{}, errors.New("originruntime: Kubernetes volume subPath contains backslash ambiguity")
			}
			cleanSubPath := path.Clean(rawSubPath)
			if cleanSubPath == "." || cleanSubPath == ".." || strings.HasPrefix(cleanSubPath, "../") || path.IsAbs(cleanSubPath) {
				return Descriptor{}, errors.New("originruntime: invalid Kubernetes volume subPath")
			}
			hostBase = filepath.Join(hostBase, filepath.FromSlash(cleanSubPath))
		}
		relative, ok := guestRelative(mount.MountPath, guestRoot)
		if !ok {
			return Descriptor{}, errors.New("originruntime: Kubernetes mount does not contain guest_root")
		}
		if relative != "." {
			hostBase = filepath.Join(hostBase, filepath.FromSlash(relative))
		}
		hostRoot, err = canonicalHostDirectory(hostBase)
		if err != nil {
			return Descriptor{}, fmt.Errorf("originruntime: Kubernetes hostPath root: %w", err)
		}
		mappings, err = canonicalMappings(hostRoot, guestRoot, config.PathMappings)
		if err != nil {
			return Descriptor{}, err
		}
		readOnly = readOnly || mount.ReadOnly
		capabilities = append(capabilities, CapabilityFilesystem, CapabilityPathMap)
	}
	if len(capabilities) == 0 {
		return Descriptor{}, errors.New("originruntime: Kubernetes pod provides neither executable nor origin-visible filesystem capabilities")
	}
	attributes := map[string]string{
		"kubernetes.namespace": strings.TrimSpace(pod.Metadata.Namespace),
		"kubernetes.pod":       strings.TrimSpace(pod.Metadata.Name),
		"kubernetes.pod_uid":   strings.TrimSpace(pod.Metadata.UID),
		"kubernetes.container": strings.TrimSpace(container.Name),
		"kubernetes.node":      strings.TrimSpace(pod.Spec.NodeName),
		"kubernetes.phase":     strings.TrimSpace(pod.Status.Phase),
		"kubernetes.ready":     fmt.Sprintf("%t", ready),
	}
	return Descriptor{
		Version: DescriptorVersion, Name: config.Name, Kind: config.Kind,
		RuntimeID: runtimeID(config.Kind, pod.Metadata.UID+"\x00"+container.Name),
		GuestRoot: guestRoot, HostRoot: hostRoot, ReadOnly: readOnly,
		Capabilities: capabilities, PathMappings: mappings, Attributes: attributes,
		ConfigSHA256: digest,
	}, nil
}

func (kubernetesResolver) Preflight(ctx context.Context, config Config, descriptor Descriptor, runner Runner) error {
	podName := descriptor.Attributes["kubernetes.pod"]
	podUID := descriptor.Attributes["kubernetes.pod_uid"]
	containerName := descriptor.Attributes["kubernetes.container"]
	if podName == "" || podUID == "" || containerName == "" {
		return errors.New("originruntime: Kubernetes descriptor lacks pod identity")
	}
	copyConfig := cloneConfig(config)
	copyConfig.Kubernetes.Pod = podName
	copyConfig.Kubernetes.Selector = ""
	copyConfig.Kubernetes.Container = containerName
	pod, err := resolveKubernetesPod(ctx, copyConfig, runner)
	if err != nil {
		return fmt.Errorf("originruntime: Kubernetes execution preflight: %w", err)
	}
	if strings.TrimSpace(pod.Metadata.UID) != podUID {
		return errors.New("originruntime: Kubernetes pod UID changed after runtime resolution")
	}
	_, status, err := selectKubernetesContainer(pod, containerName)
	if err != nil {
		return err
	}
	if !kubernetesContainerRunning(pod, status) {
		return errors.New("originruntime: Kubernetes pod container is no longer running")
	}
	if config.Kubernetes.RequireReady && !(status.Ready && kubernetesPodReady(pod)) {
		return errors.New("originruntime: Kubernetes pod container is no longer ready")
	}
	return nil
}

func (kubernetesResolver) PrepareExec(_ context.Context, config Config, descriptor Descriptor, request ExecRequest) (RunRequest, error) {
	if len(request.Command) == 0 {
		return RunRequest{}, errors.New("originruntime: command is required")
	}
	if strings.TrimSpace(request.Directory) != "" {
		return RunRequest{}, errors.New("originruntime: Kubernetes direct execution does not support changing the working directory")
	}
	assignments, err := validatedEnvironmentAssignments(effectiveEnvironment(request))
	if err != nil {
		return RunRequest{}, err
	}
	podName := descriptor.Attributes["kubernetes.pod"]
	containerName := descriptor.Attributes["kubernetes.container"]
	if podName == "" || containerName == "" {
		return RunRequest{}, errors.New("originruntime: Kubernetes descriptor lacks execution identity")
	}
	args := kubectlBaseArgs(config.Kubernetes)
	args = append(args, "exec", podName)
	if request.Stdin != nil {
		args = append(args, "--stdin")
	}
	args = append(args, "--container", containerName, "--", config.Kubernetes.EnvBinary, "--")
	args = append(args, assignments...)
	args = append(args, request.Command...)
	return RunRequest{Args: args, InheritHostEnv: true, Stdin: request.Stdin, MaxOutputBytes: request.MaxOutputBytes}, nil
}

func resolveKubernetesPod(ctx context.Context, config Config, runner Runner) (kubernetesPod, error) {
	args := kubectlBaseArgs(config.Kubernetes)
	if config.Kubernetes.Pod != "" {
		args = append(args, "get", "pod", config.Kubernetes.Pod, "--output", "json")
		result, err := runner.Run(ctx, RunRequest{Args: args, InheritHostEnv: true, MaxOutputBytes: 4 << 20})
		if err != nil {
			return kubernetesPod{}, fmt.Errorf("originruntime: kubectl get pod: %w: %s", err, strings.TrimSpace(string(result.Stderr)))
		}
		var pod kubernetesPod
		if err := json.Unmarshal(result.Stdout, &pod); err != nil {
			return kubernetesPod{}, fmt.Errorf("originruntime: decode Kubernetes pod: %w", err)
		}
		return validateKubernetesPod(pod, config.Kubernetes.Namespace)
	}
	args = append(args, "get", "pods", "--selector", config.Kubernetes.Selector, "--output", "json")
	result, err := runner.Run(ctx, RunRequest{Args: args, InheritHostEnv: true, MaxOutputBytes: 8 << 20})
	if err != nil {
		return kubernetesPod{}, fmt.Errorf("originruntime: kubectl select pods: %w: %s", err, strings.TrimSpace(string(result.Stderr)))
	}
	var list kubernetesPodList
	if err := json.Unmarshal(result.Stdout, &list); err != nil {
		return kubernetesPod{}, fmt.Errorf("originruntime: decode Kubernetes pod list: %w", err)
	}
	if len(list.Items) != 1 {
		return kubernetesPod{}, fmt.Errorf("originruntime: Kubernetes selector must resolve exactly one pod, found %d", len(list.Items))
	}
	return validateKubernetesPod(list.Items[0], config.Kubernetes.Namespace)
}

func validateKubernetesPod(pod kubernetesPod, namespace string) (kubernetesPod, error) {
	pod.Metadata.Name = strings.TrimSpace(pod.Metadata.Name)
	pod.Metadata.Namespace = strings.TrimSpace(pod.Metadata.Namespace)
	pod.Metadata.UID = strings.TrimSpace(pod.Metadata.UID)
	pod.Spec.NodeName = strings.TrimSpace(pod.Spec.NodeName)
	if pod.Metadata.Name == "" || pod.Metadata.UID == "" {
		return kubernetesPod{}, errors.New("originruntime: Kubernetes pod lacks name or UID")
	}
	if pod.Metadata.Namespace == "" {
		pod.Metadata.Namespace = namespace
	}
	if pod.Metadata.Namespace != namespace {
		return kubernetesPod{}, fmt.Errorf("originruntime: Kubernetes pod namespace %q does not match configured namespace %q", pod.Metadata.Namespace, namespace)
	}
	if len(pod.Spec.Containers) == 0 {
		return kubernetesPod{}, errors.New("originruntime: Kubernetes pod has no regular containers")
	}
	return pod, nil
}

func selectKubernetesContainer(pod kubernetesPod, configured string) (kubernetesContainer, kubernetesContainerStatus, error) {
	name := strings.TrimSpace(configured)
	if name == "" {
		name = strings.TrimSpace(pod.Metadata.Annotations[kubernetesDefaultContainerAnnotation])
	}
	if name == "" && len(pod.Spec.Containers) == 1 {
		name = pod.Spec.Containers[0].Name
	}
	if name == "" {
		return kubernetesContainer{}, kubernetesContainerStatus{}, errors.New("originruntime: Kubernetes pod has multiple containers; configure container explicitly")
	}
	var selected kubernetesContainer
	found := false
	for _, container := range pod.Spec.Containers {
		if strings.TrimSpace(container.Name) == name {
			selected = container
			selected.Name = name
			found = true
			break
		}
	}
	if !found {
		return kubernetesContainer{}, kubernetesContainerStatus{}, fmt.Errorf("originruntime: Kubernetes container %q not found", name)
	}
	var status kubernetesContainerStatus
	for _, candidate := range pod.Status.ContainerStatuses {
		if strings.TrimSpace(candidate.Name) == name {
			status = candidate
			break
		}
	}
	status.Name = name
	return selected, status, nil
}

func kubernetesContainerRunning(pod kubernetesPod, status kubernetesContainerStatus) bool {
	return strings.TrimSpace(pod.Metadata.DeletionTimestamp) == "" && strings.TrimSpace(pod.Status.Phase) == "Running" && status.State.Running != nil
}

func kubernetesPodReady(pod kubernetesPod) bool {
	for _, condition := range pod.Status.Conditions {
		if strings.TrimSpace(condition.Type) == "Ready" {
			return strings.EqualFold(strings.TrimSpace(condition.Status), "True")
		}
	}
	return false
}

func selectKubernetesVolume(pod kubernetesPod, container kubernetesContainer, guestRoot string) (kubernetesVolumeMount, kubernetesVolume, bool) {
	var selected kubernetesVolumeMount
	for _, mount := range container.VolumeMounts {
		mount.MountPath = normalizeGuestPath(mount.MountPath)
		if _, ok := guestRelative(mount.MountPath, guestRoot); !ok {
			continue
		}
		if len(mount.MountPath) > len(selected.MountPath) {
			selected = mount
		}
	}
	if selected.MountPath == "" {
		return kubernetesVolumeMount{}, kubernetesVolume{}, false
	}
	for _, volume := range pod.Spec.Volumes {
		if strings.TrimSpace(volume.Name) == strings.TrimSpace(selected.Name) {
			return selected, volume, true
		}
	}
	return kubernetesVolumeMount{}, kubernetesVolume{}, false
}

func kubectlBaseArgs(config *KubernetesConfig) []string {
	args := []string{config.Binary}
	if config.Kubeconfig != "" {
		args = append(args, "--kubeconfig", config.Kubeconfig)
	}
	if config.Context != "" {
		args = append(args, "--context", config.Context)
	}
	if config.Namespace != "" {
		args = append(args, "--namespace", config.Namespace)
	}
	return args
}

func validateKubeconfig(filePath string) error {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("originruntime: Kubernetes kubeconfig: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4<<20 {
		return errors.New("originruntime: Kubernetes kubeconfig must be a bounded regular non-symlink file")
	}
	return nil
}

var _ Resolver = kubernetesResolver{}
var _ PreflightResolver = kubernetesResolver{}
