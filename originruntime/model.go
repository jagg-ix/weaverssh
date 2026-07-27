// Package originruntime resolves origin-node filesystems and command execution
// across native hosts, WSL distributions, Docker containers, Kubernetes pods,
// and VM adapters.
package originruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ConfigVersion     = "weaverssh.origin-runtime.v1"
	DescriptorVersion = "weaverssh.origin-runtime-descriptor.v1"
	MaxConfigBytes    = 4 << 20
)

type Kind string

const (
	KindNative     Kind = "native"
	KindWSL        Kind = "wsl"
	KindDocker     Kind = "docker"
	KindKubernetes Kind = "kubernetes"
	KindVM         Kind = "vm"
)

type Capability string

const (
	CapabilityFilesystem Capability = "filesystem"
	CapabilityExec       Capability = "exec"
	CapabilityPathMap    Capability = "path-map"
)

type PathMapping struct {
	Host  string `json:"host"`
	Guest string `json:"guest"`
}

type WSLConfig struct {
	Distribution string `json:"distribution"`
	Binary       string `json:"binary,omitempty"`
	EnvBinary    string `json:"env_binary,omitempty"`
}

type DockerConfig struct {
	Container      string `json:"container"`
	Binary         string `json:"binary,omitempty"`
	User           string `json:"user,omitempty"`
	WorkingDir     string `json:"working_directory,omitempty"`
	RequireRunning bool   `json:"require_running,omitempty"`
}

type KubernetesConfig struct {
	Binary                 string `json:"binary,omitempty"`
	Kubeconfig             string `json:"kubeconfig,omitempty"`
	Context                string `json:"context,omitempty"`
	Namespace              string `json:"namespace,omitempty"`
	Pod                    string `json:"pod,omitempty"`
	Selector               string `json:"selector,omitempty"`
	Container              string `json:"container,omitempty"`
	ExpectedNode           string `json:"expected_node,omitempty"`
	EnvBinary              string `json:"env_binary,omitempty"`
	RequireRunning         bool   `json:"require_running,omitempty"`
	RequireReady           bool   `json:"require_ready,omitempty"`
	AllowHostPathDiscovery bool   `json:"allow_host_path_discovery,omitempty"`
}

type VMConfig struct {
	Driver string `json:"driver"`
	ID     string `json:"id"`
}

type Config struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	Kind         Kind              `json:"kind"`
	GuestRoot    string            `json:"guest_root"`
	HostRoot     string            `json:"host_root,omitempty"`
	ReadOnly     bool              `json:"read_only,omitempty"`
	PathMappings []PathMapping     `json:"path_mappings,omitempty"`
	WSL          *WSLConfig        `json:"wsl,omitempty"`
	Docker       *DockerConfig     `json:"docker,omitempty"`
	Kubernetes   *KubernetesConfig `json:"kubernetes,omitempty"`
	VM           *VMConfig         `json:"vm,omitempty"`
}

type Descriptor struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	Kind         Kind              `json:"kind"`
	RuntimeID    string            `json:"runtime_id"`
	GuestRoot    string            `json:"guest_root"`
	HostRoot     string            `json:"host_root,omitempty"`
	ReadOnly     bool              `json:"read_only,omitempty"`
	Capabilities []Capability      `json:"capabilities"`
	PathMappings []PathMapping     `json:"path_mappings,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	ConfigSHA256 string            `json:"config_sha256"`
}

func LoadConfigFile(filePath string) (Config, string, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return Config{}, "", errors.New("originruntime: config path is required")
	}
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return Config{}, "", err
	}
	payload, err := readConfigFile(absolute)
	if err != nil {
		return Config{}, "", err
	}
	config, err := decodeConfig(payload)
	if err != nil {
		return Config{}, "", err
	}
	base := filepath.Dir(absolute)
	if config.HostRoot != "" && !filepath.IsAbs(config.HostRoot) {
		config.HostRoot = filepath.Join(base, config.HostRoot)
	}
	for index := range config.PathMappings {
		if !filepath.IsAbs(config.PathMappings[index].Host) {
			config.PathMappings[index].Host = filepath.Join(base, config.PathMappings[index].Host)
		}
	}
	if config.Kubernetes != nil && config.Kubernetes.Kubeconfig != "" && !filepath.IsAbs(config.Kubernetes.Kubeconfig) {
		config.Kubernetes.Kubeconfig = filepath.Join(base, config.Kubernetes.Kubeconfig)
	}
	if err := config.Validate(); err != nil {
		return Config{}, "", err
	}
	digest := sha256.Sum256(payload)
	return config, hex.EncodeToString(digest[:]), nil
}

func readConfigFile(absolute string) ([]byte, error) {
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxConfigBytes {
		return nil, errors.New("originruntime: config must be a bounded regular non-symlink file")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxConfigBytes {
		return nil, errors.New("originruntime: config exceeds 4 MiB")
	}
	return payload, nil
}

func DecodeConfig(reader io.Reader) (Config, []byte, error) {
	if reader == nil {
		return Config{}, nil, errors.New("originruntime: nil config reader")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil {
		return Config{}, nil, err
	}
	if len(payload) > MaxConfigBytes {
		return Config{}, nil, errors.New("originruntime: config exceeds 4 MiB")
	}
	config, err := decodeConfig(payload)
	if err != nil {
		return Config{}, nil, err
	}
	if err := config.Validate(); err != nil {
		return Config{}, nil, err
	}
	return config, payload, nil
}

func decodeConfig(payload []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("originruntime: trailing config data")
	}
	return config, nil
}

func (config *Config) Validate() error {
	if config == nil {
		return errors.New("originruntime: nil config")
	}
	config.Version = strings.TrimSpace(config.Version)
	config.Name = strings.TrimSpace(config.Name)
	config.GuestRoot = path.Clean(filepath.ToSlash(strings.TrimSpace(config.GuestRoot)))
	config.HostRoot = strings.TrimSpace(config.HostRoot)
	if config.Version != ConfigVersion {
		return errors.New("originruntime: unsupported config version")
	}
	if !validToken(config.Name, 128) {
		return errors.New("originruntime: invalid runtime name")
	}
	if !config.Kind.valid() {
		return errors.New("originruntime: unsupported runtime kind")
	}
	if !path.IsAbs(config.GuestRoot) || len(config.GuestRoot) > 4096 || strings.ContainsAny(config.GuestRoot, "\x00\r\n") {
		return errors.New("originruntime: guest_root must be an absolute guest path")
	}
	if config.Kind == KindNative && config.HostRoot == "" {
		if filepath.IsAbs(filepath.FromSlash(config.GuestRoot)) {
			config.HostRoot = filepath.FromSlash(config.GuestRoot)
		} else {
			return errors.New("originruntime: native runtime requires host_root on this platform")
		}
	}
	if config.HostRoot != "" {
		if !filepath.IsAbs(config.HostRoot) || len(config.HostRoot) > 4096 || strings.ContainsAny(config.HostRoot, "\x00\r\n") {
			return errors.New("originruntime: host_root must be an absolute host path")
		}
		config.HostRoot = filepath.Clean(config.HostRoot)
	}
	if err := config.validateKindConfig(); err != nil {
		return err
	}
	if len(config.PathMappings) > 256 {
		return errors.New("originruntime: path_mappings exceeds 256 entries")
	}
	seenHost := map[string]struct{}{}
	seenGuest := map[string]struct{}{}
	for index := range config.PathMappings {
		mapping := &config.PathMappings[index]
		mapping.Host = filepath.Clean(strings.TrimSpace(mapping.Host))
		mapping.Guest = path.Clean(filepath.ToSlash(strings.TrimSpace(mapping.Guest)))
		if !filepath.IsAbs(mapping.Host) || !path.IsAbs(mapping.Guest) || strings.ContainsAny(mapping.Host+mapping.Guest, "\x00\r\n") {
			return fmt.Errorf("originruntime: invalid path mapping at index %d", index)
		}
		if _, exists := seenHost[mapping.Host]; exists {
			return fmt.Errorf("originruntime: duplicate host path mapping %s", mapping.Host)
		}
		if _, exists := seenGuest[mapping.Guest]; exists {
			return fmt.Errorf("originruntime: duplicate guest path mapping %s", mapping.Guest)
		}
		seenHost[mapping.Host] = struct{}{}
		seenGuest[mapping.Guest] = struct{}{}
	}
	sort.Slice(config.PathMappings, func(i, j int) bool {
		if config.PathMappings[i].Guest != config.PathMappings[j].Guest {
			return config.PathMappings[i].Guest < config.PathMappings[j].Guest
		}
		return config.PathMappings[i].Host < config.PathMappings[j].Host
	})
	return nil
}

func (config Config) validateKindConfig() error {
	count := 0
	if config.WSL != nil {
		count++
	}
	if config.Docker != nil {
		count++
	}
	if config.Kubernetes != nil {
		count++
	}
	if config.VM != nil {
		count++
	}
	switch config.Kind {
	case KindNative:
		if count != 0 {
			return errors.New("originruntime: native config cannot include wsl, docker, kubernetes, or vm blocks")
		}
	case KindWSL:
		if count != 1 || config.WSL == nil {
			return errors.New("originruntime: wsl config requires only the wsl block")
		}
		config.WSL.Distribution = strings.TrimSpace(config.WSL.Distribution)
		config.WSL.Binary = defaultBinary(config.WSL.Binary, "wsl.exe")
		config.WSL.EnvBinary = strings.TrimSpace(config.WSL.EnvBinary)
		if config.WSL.EnvBinary == "" {
			config.WSL.EnvBinary = "/usr/bin/env"
		}
		if !safeText(config.WSL.Distribution, 256) || !safeExecutable(config.WSL.Binary) || !safeText(config.WSL.EnvBinary, 4096) || !path.IsAbs(config.WSL.EnvBinary) {
			return errors.New("originruntime: invalid WSL configuration")
		}
	case KindDocker:
		if count != 1 || config.Docker == nil {
			return errors.New("originruntime: docker config requires only the docker block")
		}
		config.Docker.Container = strings.TrimSpace(config.Docker.Container)
		config.Docker.Binary = defaultBinary(config.Docker.Binary, "docker")
		config.Docker.User = strings.TrimSpace(config.Docker.User)
		config.Docker.WorkingDir = path.Clean(strings.TrimSpace(config.Docker.WorkingDir))
		if config.Docker.WorkingDir == "." {
			config.Docker.WorkingDir = ""
		}
		if !safeText(config.Docker.Container, 256) || !safeExecutable(config.Docker.Binary) || !safeOptionalText(config.Docker.User, 256) {
			return errors.New("originruntime: invalid Docker configuration")
		}
		if config.Docker.WorkingDir != "" && !path.IsAbs(config.Docker.WorkingDir) {
			return errors.New("originruntime: Docker working_directory must be absolute")
		}
	case KindKubernetes:
		if count != 1 || config.Kubernetes == nil {
			return errors.New("originruntime: kubernetes config requires only the kubernetes block")
		}
		kubernetes := config.Kubernetes
		kubernetes.Binary = defaultBinary(kubernetes.Binary, "kubectl")
		kubernetes.Kubeconfig = strings.TrimSpace(kubernetes.Kubeconfig)
		kubernetes.Context = strings.TrimSpace(kubernetes.Context)
		kubernetes.Namespace = strings.TrimSpace(kubernetes.Namespace)
		kubernetes.Pod = strings.TrimSpace(kubernetes.Pod)
		kubernetes.Selector = strings.TrimSpace(kubernetes.Selector)
		kubernetes.Container = strings.TrimSpace(kubernetes.Container)
		kubernetes.ExpectedNode = strings.TrimSpace(kubernetes.ExpectedNode)
		kubernetes.EnvBinary = strings.TrimSpace(kubernetes.EnvBinary)
		if kubernetes.Namespace == "" {
			kubernetes.Namespace = "default"
		}
		if kubernetes.EnvBinary == "" {
			kubernetes.EnvBinary = "/usr/bin/env"
		}
		if !safeExecutable(kubernetes.Binary) || !safeOptionalText(kubernetes.Context, 256) || !safeText(kubernetes.Namespace, 256) || !safeOptionalText(kubernetes.Pod, 256) || !safeOptionalText(kubernetes.Selector, 1024) || !safeOptionalText(kubernetes.Container, 256) || !safeOptionalText(kubernetes.ExpectedNode, 256) || !safeText(kubernetes.EnvBinary, 4096) || !path.IsAbs(kubernetes.EnvBinary) {
			return errors.New("originruntime: invalid Kubernetes configuration")
		}
		if (kubernetes.Pod == "") == (kubernetes.Selector == "") {
			return errors.New("originruntime: Kubernetes requires exactly one of pod or selector")
		}
		if kubernetes.Kubeconfig != "" {
			if !filepath.IsAbs(kubernetes.Kubeconfig) || len(kubernetes.Kubeconfig) > 4096 || strings.ContainsAny(kubernetes.Kubeconfig, "\x00\r\n") {
				return errors.New("originruntime: Kubernetes kubeconfig must be an absolute host path")
			}
			kubernetes.Kubeconfig = filepath.Clean(kubernetes.Kubeconfig)
		}
		if kubernetes.AllowHostPathDiscovery && config.HostRoot == "" && kubernetes.ExpectedNode == "" {
			return errors.New("originruntime: Kubernetes hostPath discovery requires expected_node")
		}
	case KindVM:
		if count != 1 || config.VM == nil {
			return errors.New("originruntime: vm config requires only the vm block")
		}
		config.VM.Driver = strings.TrimSpace(config.VM.Driver)
		config.VM.ID = strings.TrimSpace(config.VM.ID)
		if !validToken(config.VM.Driver, 128) || !safeText(config.VM.ID, 256) {
			return errors.New("originruntime: invalid VM configuration")
		}
		if config.VM.Driver == "shared-folder" && config.HostRoot == "" {
			return errors.New("originruntime: shared-folder VM requires host_root")
		}
	}
	return nil
}

func (kind Kind) valid() bool {
	switch kind {
	case KindNative, KindWSL, KindDocker, KindKubernetes, KindVM:
		return true
	default:
		return false
	}
}

func validToken(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char == '_' || char == '.' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func safeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func safeOptionalText(value string, maximum int) bool {
	return value == "" || safeText(value, maximum)
}

func safeExecutable(value string) bool {
	return safeText(value, 4096) && !strings.ContainsAny(value, "\t ")
}

func defaultBinary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
