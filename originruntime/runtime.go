package originruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const MaxCommandOutputBytes = 4 << 20

var ErrPathUnmapped = errors.New("originruntime: path is not mapped")
var ErrExecUnsupported = errors.New("originruntime: execution is not supported")

type RunRequest struct {
	Args           []string
	Environment    map[string]string
	Directory      string
	InheritHostEnv bool
	Stdin          io.Reader
	MaxOutputBytes int
}

type RunResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
}

type Runner interface {
	Run(context.Context, RunRequest) (RunResult, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(request.Args) == 0 || strings.TrimSpace(request.Args[0]) == "" {
		return RunResult{}, errors.New("originruntime: command is required")
	}
	maximum := request.MaxOutputBytes
	if maximum <= 0 {
		maximum = MaxCommandOutputBytes
	}
	if maximum > 64<<20 {
		return RunResult{}, errors.New("originruntime: command output limit exceeds 64 MiB")
	}
	command := exec.CommandContext(ctx, request.Args[0], request.Args[1:]...)
	if request.Directory != "" {
		command.Dir = request.Directory
	}
	environment := map[string]string{}
	if request.InheritHostEnv {
		for _, entry := range os.Environ() {
			name, value, ok := strings.Cut(entry, "=")
			if ok && validEnvironmentName(name) && !strings.ContainsAny(value, "\x00\r\n") {
				environment[name] = value
			}
		}
	}
	for name, value := range request.Environment {
		if !validEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			return RunResult{}, fmt.Errorf("originruntime: invalid environment entry %q", name)
		}
		environment[name] = value
	}
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	command.Env = make([]string, 0, len(names))
	totalEnvironment := 0
	for _, name := range names {
		entry := name + "=" + environment[name]
		totalEnvironment += len(entry)
		if totalEnvironment > 1<<20 {
			return RunResult{}, errors.New("originruntime: command environment exceeds 1 MiB")
		}
		command.Env = append(command.Env, entry)
	}
	command.Stdin = request.Stdin
	stdout := &boundedBuffer{maximum: maximum}
	stderr := &boundedBuffer{maximum: maximum}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	result := RunResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if stdout.truncated || stderr.truncated {
		return result, errors.New("originruntime: command output exceeded configured limit")
	}
	if runErr == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, fmt.Errorf("originruntime: command exited with status %d", result.ExitCode)
	}
	return result, runErr
}

type ExecRequest struct {
	Command        []string
	Environment    map[string]string
	Directory      string
	InheritHostEnv bool
	Stdin          io.Reader
	MaxOutputBytes int
}

type Resolver interface {
	Kind() Kind
	Resolve(context.Context, Config, string, Runner) (Descriptor, error)
	PrepareExec(context.Context, Config, Descriptor, ExecRequest) (RunRequest, error)
}

// PreflightResolver can revalidate an ephemeral runtime identity immediately
// before execution. It is intentionally optional so existing trusted resolvers
// remain source compatible.
type PreflightResolver interface {
	Preflight(context.Context, Config, Descriptor, Runner) error
}

type Registry struct {
	mu        sync.RWMutex
	resolvers map[Kind]Resolver
}

func NewRegistry() *Registry {
	registry := NewEmptyRegistry()
	registry.MustRegister(nativeResolver{})
	registry.MustRegister(wslResolver{})
	registry.MustRegister(dockerResolver{})
	registry.MustRegister(kubernetesResolver{})
	registry.MustRegister(vmResolver{})
	return registry
}

func NewEmptyRegistry() *Registry {
	return &Registry{resolvers: map[Kind]Resolver{}}
}

func (registry *Registry) Register(resolver Resolver) error {
	if registry == nil || resolver == nil || !resolver.Kind().valid() {
		return errors.New("originruntime: invalid resolver")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.resolvers[resolver.Kind()]; exists {
		return fmt.Errorf("originruntime: resolver already registered for %s", resolver.Kind())
	}
	registry.resolvers[resolver.Kind()] = resolver
	return nil
}

func (registry *Registry) MustRegister(resolver Resolver) {
	if err := registry.Register(resolver); err != nil {
		panic(err)
	}
}

func (registry *Registry) Replace(resolver Resolver) error {
	if registry == nil || resolver == nil || !resolver.Kind().valid() {
		return errors.New("originruntime: invalid replacement resolver")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.resolvers[resolver.Kind()] = resolver
	return nil
}

type Runtime struct {
	config     Config
	descriptor Descriptor
	resolver   Resolver
	runner     Runner
}

func OpenFile(ctx context.Context, configPath string, registry *Registry, runner Runner) (*Runtime, error) {
	config, digest, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	return Resolve(ctx, config, digest, registry, runner)
}

func Resolve(ctx context.Context, config Config, configSHA256 string, registry *Registry, runner Runner) (*Runtime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if configSHA256 == "" {
		payload, err := json.Marshal(config)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(payload)
		configSHA256 = hex.EncodeToString(digest[:])
	}
	if !validSHA256(configSHA256) {
		return nil, errors.New("originruntime: invalid configuration sha256")
	}
	if registry == nil {
		registry = NewRegistry()
	}
	if runner == nil {
		runner = OSRunner{}
	}
	registry.mu.RLock()
	resolver := registry.resolvers[config.Kind]
	registry.mu.RUnlock()
	if resolver == nil {
		return nil, fmt.Errorf("originruntime: no resolver for %s", config.Kind)
	}
	descriptor, err := resolver.Resolve(ctx, config, configSHA256, runner)
	if err != nil {
		return nil, err
	}
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}
	return &Runtime{config: cloneConfig(config), descriptor: cloneDescriptor(descriptor), resolver: resolver, runner: runner}, nil
}

func (runtime *Runtime) Descriptor() Descriptor {
	if runtime == nil {
		return Descriptor{}
	}
	return cloneDescriptor(runtime.descriptor)
}

func (runtime *Runtime) Config() Config {
	if runtime == nil {
		return Config{}
	}
	return cloneConfig(runtime.config)
}

func (runtime *Runtime) MapHostToGuest(hostPath string) (string, error) {
	if runtime == nil {
		return "", errors.New("originruntime: runtime unavailable")
	}
	hostPath = filepath.Clean(strings.TrimSpace(hostPath))
	if !filepath.IsAbs(hostPath) {
		return "", errors.New("originruntime: host path must be absolute")
	}
	mappings := append([]PathMapping(nil), runtime.descriptor.PathMappings...)
	sort.Slice(mappings, func(i, j int) bool { return len(mappings[i].Host) > len(mappings[j].Host) })
	for _, mapping := range mappings {
		relative, err := filepath.Rel(mapping.Host, hostPath)
		if err != nil || escapesHost(relative) {
			continue
		}
		if relative == "." {
			return mapping.Guest, nil
		}
		return path.Join(mapping.Guest, filepath.ToSlash(relative)), nil
	}
	return "", ErrPathUnmapped
}

func (runtime *Runtime) MapGuestToHost(guestPath string) (string, error) {
	if runtime == nil {
		return "", errors.New("originruntime: runtime unavailable")
	}
	guestPath = normalizeGuestAbsolute(guestPath)
	if !path.IsAbs(guestPath) {
		return "", errors.New("originruntime: guest path must be absolute")
	}
	mappings := append([]PathMapping(nil), runtime.descriptor.PathMappings...)
	sort.Slice(mappings, func(i, j int) bool { return len(mappings[i].Guest) > len(mappings[j].Guest) })
	for _, mapping := range mappings {
		relative, ok := guestRelative(mapping.Guest, guestPath)
		if !ok {
			continue
		}
		if relative == "." {
			return mapping.Host, nil
		}
		return filepath.Join(mapping.Host, filepath.FromSlash(relative)), nil
	}
	return "", ErrPathUnmapped
}

func (runtime *Runtime) Exec(ctx context.Context, request ExecRequest) (RunResult, error) {
	if runtime == nil || runtime.resolver == nil || runtime.runner == nil {
		return RunResult{}, errors.New("originruntime: runtime unavailable")
	}
	if !hasCapability(runtime.descriptor.Capabilities, CapabilityExec) {
		return RunResult{}, ErrExecUnsupported
	}
	if preflight, ok := runtime.resolver.(PreflightResolver); ok {
		if err := preflight.Preflight(ctx, runtime.config, runtime.descriptor, runtime.runner); err != nil {
			return RunResult{}, err
		}
	}
	prepared, err := runtime.resolver.PrepareExec(ctx, runtime.config, runtime.descriptor, request)
	if err != nil {
		return RunResult{}, err
	}
	return runtime.runner.Run(ctx, prepared)
}

func HasCapability(descriptor Descriptor, capability Capability) bool {
	return hasCapability(descriptor.Capabilities, capability)
}

func hasCapability(values []Capability, target Capability) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateDescriptor(descriptor Descriptor) error {
	if descriptor.Version != DescriptorVersion || !validToken(descriptor.Name, 128) || !descriptor.Kind.valid() || !validToken(descriptor.RuntimeID, 128) {
		return errors.New("originruntime: invalid descriptor metadata")
	}
	if descriptor.GuestRoot == "" || !path.IsAbs(descriptor.GuestRoot) {
		return errors.New("originruntime: invalid descriptor guest root")
	}
	if !validSHA256(descriptor.ConfigSHA256) {
		return errors.New("originruntime: invalid descriptor configuration sha256")
	}
	if len(descriptor.Capabilities) == 0 || len(descriptor.Capabilities) > 16 || len(descriptor.PathMappings) > 256 || len(descriptor.Attributes) > 64 {
		return errors.New("originruntime: invalid descriptor capabilities, mappings, or attributes")
	}
	seenCapabilities := map[Capability]struct{}{}
	for _, capability := range descriptor.Capabilities {
		switch capability {
		case CapabilityFilesystem, CapabilityExec, CapabilityPathMap:
		default:
			return fmt.Errorf("originruntime: unsupported capability %q", capability)
		}
		if _, exists := seenCapabilities[capability]; exists {
			return fmt.Errorf("originruntime: duplicate capability %q", capability)
		}
		seenCapabilities[capability] = struct{}{}
	}
	for key, value := range descriptor.Attributes {
		if !validToken(key, 128) || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("originruntime: invalid descriptor attribute %q", key)
		}
	}
	filesystem := hasCapability(descriptor.Capabilities, CapabilityFilesystem)
	pathMap := hasCapability(descriptor.Capabilities, CapabilityPathMap)
	if filesystem != pathMap {
		return errors.New("originruntime: filesystem and path-map capabilities must be paired")
	}
	if !filesystem {
		if descriptor.HostRoot != "" || len(descriptor.PathMappings) != 0 {
			return errors.New("originruntime: execution-only descriptor cannot publish host paths")
		}
		return nil
	}
	if descriptor.HostRoot == "" || !filepath.IsAbs(descriptor.HostRoot) || len(descriptor.PathMappings) == 0 {
		return errors.New("originruntime: filesystem descriptor requires an absolute host root and mappings")
	}
	seenHosts := map[string]struct{}{}
	seenGuests := map[string]struct{}{}
	rootMapping := false
	for _, mapping := range descriptor.PathMappings {
		if !filepath.IsAbs(mapping.Host) || !path.IsAbs(mapping.Guest) || strings.ContainsAny(mapping.Host+mapping.Guest, "\x00\r\n") {
			return errors.New("originruntime: invalid descriptor path mapping")
		}
		if _, exists := seenHosts[mapping.Host]; exists {
			return fmt.Errorf("originruntime: duplicate descriptor host mapping %s", mapping.Host)
		}
		if _, exists := seenGuests[mapping.Guest]; exists {
			return fmt.Errorf("originruntime: duplicate descriptor guest mapping %s", mapping.Guest)
		}
		seenHosts[mapping.Host] = struct{}{}
		seenGuests[mapping.Guest] = struct{}{}
		if filepath.Clean(mapping.Host) == filepath.Clean(descriptor.HostRoot) && path.Clean(mapping.Guest) == path.Clean(descriptor.GuestRoot) {
			rootMapping = true
		}
	}
	if !rootMapping {
		return errors.New("originruntime: descriptor lacks its root path mapping")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneConfig(config Config) Config {
	config.PathMappings = append([]PathMapping(nil), config.PathMappings...)
	if config.WSL != nil {
		value := *config.WSL
		config.WSL = &value
	}
	if config.Docker != nil {
		value := *config.Docker
		config.Docker = &value
	}
	if config.Kubernetes != nil {
		value := *config.Kubernetes
		config.Kubernetes = &value
	}
	if config.VM != nil {
		value := *config.VM
		config.VM = &value
	}
	return config
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	descriptor.Capabilities = append([]Capability(nil), descriptor.Capabilities...)
	descriptor.PathMappings = append([]PathMapping(nil), descriptor.PathMappings...)
	if descriptor.Attributes != nil {
		attributes := make(map[string]string, len(descriptor.Attributes))
		for key, value := range descriptor.Attributes {
			attributes[key] = value
		}
		descriptor.Attributes = attributes
	}
	return descriptor
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, "=") {
		return false
	}
	for index, char := range value {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || index > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func escapesHost(relative string) bool {
	return relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative)
}

func normalizeGuestAbsolute(value string) string {
	return path.Clean(filepath.ToSlash(strings.TrimSpace(value)))
}

func guestRelative(base, target string) (string, bool) {
	base = normalizeGuestAbsolute(base)
	target = normalizeGuestAbsolute(target)
	if !path.IsAbs(base) || !path.IsAbs(target) {
		return "", false
	}
	if base == target {
		return ".", true
	}
	if base == "/" {
		return strings.TrimPrefix(target, "/"), true
	}
	prefix := strings.TrimSuffix(base, "/") + "/"
	if !strings.HasPrefix(target, prefix) {
		return "", false
	}
	return strings.TrimPrefix(target, prefix), true
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	maximum   int
	truncated bool
}

func (buffer *boundedBuffer) Write(payload []byte) (int, error) {
	if buffer.maximum <= 0 {
		return len(payload), nil
	}
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.truncated = true
		return len(payload), nil
	}
	write := payload
	if len(write) > remaining {
		write = write[:remaining]
		buffer.truncated = true
	}
	_, _ = buffer.buffer.Write(write)
	return len(payload), nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.buffer.Bytes()...)
}
