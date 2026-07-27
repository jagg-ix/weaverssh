package filebackend

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
	HookConfigVersion  = "weaverssh.file-backend-hooks.v1"
	maxHookConfigBytes = 1 << 20
	maxCommandOutput   = 32 << 10
)

type HookFileConfig struct {
	Version string              `json:"version"`
	Hooks   []CommandHookConfig `json:"hooks"`
}

type CommandHookConfig struct {
	Operation        Operation         `json:"operation"`
	Phase            Phase             `json:"phase,omitempty"`
	Command          []string          `json:"command"`
	Mode             Mode              `json:"mode,omitempty"`
	Priority         int               `json:"priority,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
	MaxParallel      int               `json:"max_parallel,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
}

// LoadHooksFile loads strict, bounded command hooks. Commands execute directly
// without a shell or ambient environment and receive one Event JSON object on
// standard input.
func LoadHooksFile(path string, reporter Reporter) (*Registry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("filebackend: hook configuration path is required")
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
		return nil, errors.New("filebackend: hook configuration must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxHookConfigBytes {
		return nil, errors.New("filebackend: invalid hook configuration size")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("filebackend: hook configuration must not be group- or world-writable")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxHookConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxHookConfigBytes {
		return nil, errors.New("filebackend: invalid hook configuration size")
	}
	var config HookFileConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("filebackend: trailing hook configuration data")
	}
	if config.Version == "" {
		config.Version = HookConfigVersion
	}
	if config.Version != HookConfigVersion || len(config.Hooks) == 0 || len(config.Hooks) > maxHooks {
		return nil, errors.New("filebackend: invalid hook configuration")
	}
	registry := NewRegistry(reporter)
	for index, raw := range config.Hooks {
		hook, err := configuredCommandHook(raw)
		if err != nil {
			return nil, fmt.Errorf("filebackend: hook %d: %w", index, err)
		}
		if err := registry.Register(hook); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func configuredCommandHook(raw CommandHookConfig) (Hook, error) {
	if raw.Phase == "" {
		raw.Phase = PhaseBefore
	}
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
	executable, err := os.Stat(command[0])
	if err != nil {
		return Hook{}, fmt.Errorf("command hook executable: %w", err)
	}
	if !executable.Mode().IsRegular() {
		return Hook{}, errors.New("command hook executable must be a regular file")
	}
	if runtime.GOOS != "windows" && executable.Mode().Perm()&0o111 == 0 {
		return Hook{}, errors.New("command hook file is not executable")
	}
	workingDirectory := strings.TrimSpace(raw.WorkingDirectory)
	if workingDirectory == "" {
		workingDirectory = filepath.Dir(command[0])
	}
	if !filepath.IsAbs(workingDirectory) {
		return Hook{}, errors.New("command hook working_directory must be absolute")
	}
	working, err := os.Stat(workingDirectory)
	if err != nil {
		return Hook{}, fmt.Errorf("command hook working_directory: %w", err)
	}
	if !working.IsDir() {
		return Hook{}, errors.New("command hook working_directory must be a directory")
	}
	environment, err := normalizeCommandEnvironment(raw.Environment)
	if err != nil {
		return Hook{}, err
	}
	timeout, err := parseCommandTimeout(raw.Timeout)
	if err != nil {
		return Hook{}, err
	}
	handler := commandHandler{
		operation: raw.Operation, phase: raw.Phase,
		command: command, environment: environment,
		workingDirectory: filepath.Clean(workingDirectory),
	}
	return Hook{
		Operation: raw.Operation, Phase: raw.Phase, Priority: raw.Priority,
		Mode: raw.Mode, Timeout: timeout, MaxParallel: raw.MaxParallel,
		Handler: handler.run,
	}, nil
}

type commandHandler struct {
	operation        Operation
	phase            Phase
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
		"WEAVERSSH_FILE_HOOK=1",
		"WEAVERSSH_FILE_OPERATION=" + string(h.operation),
		"WEAVERSSH_FILE_PHASE=" + string(h.phase),
		"WEAVERSSH_FILE_EVENT_VERSION=" + EventVersion,
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

func parseCommandTimeout(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || duration <= 0 {
		return 0, errors.New("filebackend: hook timeout must be positive")
	}
	return duration, nil
}

func normalizeCommandEnvironment(raw map[string]string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	normalized := make(map[string]string, len(raw))
	for original, value := range raw {
		key := strings.TrimSpace(original)
		if !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("filebackend: invalid command environment")
		}
		if strings.HasPrefix(key, "WEAVERSSH_FILE_") {
			return nil, fmt.Errorf("filebackend: reserved environment variable %q", key)
		}
		if _, exists := normalized[key]; exists {
			return nil, fmt.Errorf("filebackend: duplicate environment variable %q", key)
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

func (b *limitedBuffer) String() string { return b.buffer.String() }
