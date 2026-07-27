package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	ConfigVersion    = "weaverssh.extensions.v1"
	maxConfigBytes   = 1 << 20
	maxCommandOutput = 32 << 10
)

// FileConfig describes command and eBPF extensions loaded from one strict file.
type FileConfig struct {
	Version    string                   `json:"version"`
	Extensions []CommandExtensionConfig `json:"extensions"`
}

// CommandExtensionConfig defines one named extension. The historical type name
// is retained for source compatibility; an extension may contain command hooks,
// eBPF hooks, or both.
type CommandExtensionConfig struct {
	Name        string              `json:"name"`
	Version     string              `json:"extension_version"`
	Description string              `json:"description,omitempty"`
	Hooks       []CommandHookConfig `json:"hooks,omitempty"`
	EBPFHooks   []EBPFHookConfig    `json:"ebpf_hooks,omitempty"`
}

// CommandHookConfig configures one bounded process invocation.
type CommandHookConfig struct {
	Point            Point             `json:"point"`
	Command          []string          `json:"command"`
	Mode             Mode              `json:"mode,omitempty"`
	Priority         int               `json:"priority,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
	MaxParallel      int               `json:"max_parallel,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
}

// LoadFile reads a strict, user-controlled extension configuration and returns
// a registry containing all configured command and eBPF hooks.
func LoadFile(path string, reporter Reporter) (*Registry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("extension: configuration path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("extension: configuration must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxConfigBytes {
		return nil, errors.New("extension: invalid configuration size")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("extension: configuration must not be group- or world-writable")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxConfigBytes {
		return nil, errors.New("extension: invalid configuration size")
	}
	var config FileConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("extension: trailing configuration data")
	}
	if config.Version == "" {
		config.Version = ConfigVersion
	}
	if config.Version != ConfigVersion || len(config.Extensions) == 0 {
		return nil, errors.New("extension: invalid configuration")
	}

	registry := NewRegistry(reporter)
	for _, configured := range config.Extensions {
		descriptor := Descriptor{Name: configured.Name, Version: configured.Version, Description: configured.Description}
		hookCount := len(configured.Hooks) + len(configured.EBPFHooks)
		if hookCount == 0 {
			return nil, fmt.Errorf("extension %s has no hooks", strings.TrimSpace(configured.Name))
		}
		hooks := make([]Hook, 0, hookCount)
		for _, raw := range configured.Hooks {
			hook, err := commandHook(descriptor.Name, raw)
			if err != nil {
				return nil, fmt.Errorf("extension %s: %w", strings.TrimSpace(configured.Name), err)
			}
			hooks = append(hooks, hook)
		}
		for _, raw := range configured.EBPFHooks {
			hook, err := configuredEBPFHook(raw)
			if err != nil {
				return nil, fmt.Errorf("extension %s: %w", strings.TrimSpace(configured.Name), err)
			}
			hooks = append(hooks, hook)
		}
		definition := Definition{Descriptor: descriptor, Hooks: hooks}
		if len(configured.EBPFHooks) > 0 {
			if err := registry.RegisterEBPF(definition); err != nil {
				return nil, err
			}
		} else if err := registry.Register(definition); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func configuredEBPFHook(raw EBPFHookConfig) (Hook, error) {
	runtimeName := strings.ToLower(strings.TrimSpace(raw.Runtime))
	if runtimeName == "" {
		runtimeName = EBPFRuntimePinned
	}
	if runtimeName != EBPFRuntimePinned {
		return Hook{}, fmt.Errorf("extension: unsupported configured eBPF runtime %q", runtimeName)
	}
	if !NativePinnedEBPFAvailable() {
		return Hook{}, ErrEBPFUnsupported
	}
	program, err := normalizeEBPFProgramRef(raw.Program)
	if err != nil {
		return Hook{}, err
	}
	if err := validateNativePinnedEBPF(program); err != nil {
		return Hook{}, err
	}
	raw.Program = program
	raw.Runtime = EBPFRuntimePinned
	return NewEBPFHook(PinnedRuntime{}, raw)
}

func commandHook(extensionName string, raw CommandHookConfig) (Hook, error) {
	if len(raw.Command) == 0 || strings.TrimSpace(raw.Command[0]) == "" {
		return Hook{}, errors.New("command hook requires an executable")
	}
	command := append([]string(nil), raw.Command...)
	command[0] = filepath.Clean(strings.TrimSpace(command[0]))
	if !filepath.IsAbs(command[0]) {
		return Hook{}, errors.New("command hook executable must be an absolute path")
	}
	for _, argument := range command {
		if strings.IndexByte(argument, 0) >= 0 {
			return Hook{}, errors.New("command hook argument contains NUL")
		}
	}
	executableInfo, err := os.Stat(command[0])
	if err != nil {
		return Hook{}, fmt.Errorf("command hook executable: %w", err)
	}
	if !executableInfo.Mode().IsRegular() {
		return Hook{}, errors.New("command hook executable must be a regular file")
	}
	if runtime.GOOS != "windows" && executableInfo.Mode().Perm()&0o111 == 0 {
		return Hook{}, errors.New("command hook file is not executable")
	}
	workingDirectory := strings.TrimSpace(raw.WorkingDirectory)
	if workingDirectory == "" {
		workingDirectory = filepath.Dir(command[0])
	}
	if !filepath.IsAbs(workingDirectory) {
		return Hook{}, errors.New("command hook working_directory must be absolute")
	}
	workingInfo, err := os.Stat(workingDirectory)
	if err != nil {
		return Hook{}, fmt.Errorf("command hook working_directory: %w", err)
	}
	if !workingInfo.IsDir() {
		return Hook{}, errors.New("command hook working_directory must be a directory")
	}
	environment, err := normalizeEnvironment(raw.Environment)
	if err != nil {
		return Hook{}, err
	}
	timeout, err := parseHookTimeout(raw.Timeout)
	if err != nil {
		return Hook{}, err
	}
	handler := commandHandler{
		extensionName:    strings.TrimSpace(extensionName),
		point:            raw.Point,
		command:          command,
		environment:      environment,
		workingDirectory: filepath.Clean(workingDirectory),
	}
	return Hook{
		Point:       raw.Point,
		Priority:    raw.Priority,
		Mode:        raw.Mode,
		Timeout:     timeout,
		MaxParallel: raw.MaxParallel,
		Handler:     handler.run,
	}, nil
}

func parseHookTimeout(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || duration <= 0 {
		return 0, errors.New("extension: hook timeout must be positive")
	}
	return duration, nil
}

type commandHandler struct {
	extensionName    string
	point            Point
	command          []string
	environment      []string
	workingDirectory string
}

func (h commandHandler) run(ctx context.Context, event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	command := exec.CommandContext(ctx, h.command[0], h.command[1:]...)
	command.Dir = h.workingDirectory
	command.Env = append([]string{
		"WEAVERSSH_EXTENSION=1",
		"WEAVERSSH_EXTENSION_NAME=" + h.extensionName,
		"WEAVERSSH_HOOK_POINT=" + string(h.point),
		"WEAVERSSH_EVENT_VERSION=" + EventVersion,
	}, h.environment...)
	command.Stdin = bytes.NewReader(payload)
	stdout := &limitedBuffer{maximum: maxCommandOutput}
	stderr := &limitedBuffer{maximum: maxCommandOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("command failed: %w; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	return nil
}

func normalizeEnvironment(raw map[string]string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	normalized := make(map[string]string, len(raw))
	for originalKey, value := range raw {
		key := strings.TrimSpace(originalKey)
		if !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("extension: invalid command environment")
		}
		if strings.HasPrefix(key, "WEAVERSSH_EXTENSION") || key == "WEAVERSSH_HOOK_POINT" || key == "WEAVERSSH_EVENT_VERSION" {
			return nil, fmt.Errorf("extension: reserved environment variable %q", key)
		}
		if _, exists := normalized[key]; exists {
			return nil, fmt.Errorf("extension: duplicate environment variable %q", key)
		}
		normalized[key] = value
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+normalized[key])
	}
	return out, nil
}

func validEnvironmentKey(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if r == '_' || unicode.IsUpper(r) || (index > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

type limitedBuffer struct {
	buffer  bytes.Buffer
	maximum int
}

func (b *limitedBuffer) Write(payload []byte) (int, error) {
	original := len(payload)
	remaining := b.maximum - b.buffer.Len()
	if remaining > 0 {
		if len(payload) > remaining {
			payload = payload[:remaining]
		}
		_, _ = b.buffer.Write(payload)
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}
