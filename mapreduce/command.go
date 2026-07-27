package mapreduce

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
	maxPluginConfigBytes      = 1 << 20
	maxCommandDiagnosticBytes = 32 << 10
)

type PluginFileConfig struct {
	Version string                `json:"version"`
	Plugins []CommandPluginConfig `json:"plugins"`
}

type CommandPluginConfig struct {
	Name             string            `json:"name"`
	Version          string            `json:"plugin_version"`
	Description      string            `json:"description,omitempty"`
	MapCommand       []string          `json:"map_command,omitempty"`
	ReduceCommand    []string          `json:"reduce_command,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
	MaxParallel      int               `json:"max_parallel,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
}

func LoadPluginFile(path string) (*Registry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("mapreduce: plugin configuration path is required")
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
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPluginConfigBytes {
		return nil, errors.New("mapreduce: invalid plugin configuration file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("mapreduce: plugin configuration must not be group- or world-writable")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxPluginConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxPluginConfigBytes {
		return nil, errors.New("mapreduce: invalid plugin configuration size")
	}
	var config PluginFileConfig
	if err := decodeStrict(payload, &config); err != nil {
		return nil, err
	}
	if config.Version == "" {
		config.Version = PluginConfigVersion
	}
	if config.Version != PluginConfigVersion || len(config.Plugins) == 0 || len(config.Plugins) > maxPlugins {
		return nil, errors.New("mapreduce: invalid plugin configuration")
	}
	registry := NewRegistry()
	for index, raw := range config.Plugins {
		plugin, err := newCommandPlugin(raw)
		if err != nil {
			return nil, fmt.Errorf("mapreduce: plugin %d: %w", index, err)
		}
		if err := registry.RegisterPlugin(plugin); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

type commandStage struct {
	plugin           string
	stage            string
	command          []string
	environment      []string
	workingDirectory string
	timeout          time.Duration
	semaphore        chan struct{}
}

func newCommandPlugin(raw CommandPluginConfig) (Plugin, error) {
	descriptor := Descriptor{Name: strings.TrimSpace(raw.Name), Version: strings.TrimSpace(raw.Version), Description: strings.TrimSpace(raw.Description)}
	if !validName(descriptor.Name) || descriptor.Version == "" || len(descriptor.Version) > 64 {
		return Plugin{}, errors.New("invalid plugin descriptor")
	}
	timeout := 2 * time.Second
	if strings.TrimSpace(raw.Timeout) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(raw.Timeout))
		if err != nil || parsed <= 0 || parsed > 10*time.Minute {
			return Plugin{}, errors.New("invalid plugin timeout")
		}
		timeout = parsed
	}
	parallel := raw.MaxParallel
	if parallel <= 0 {
		parallel = 1
	}
	if parallel > 64 {
		return Plugin{}, errors.New("plugin max_parallel exceeds 64")
	}
	environment, err := normalizeCommandEnvironment(raw.Environment)
	if err != nil {
		return Plugin{}, err
	}
	working := strings.TrimSpace(raw.WorkingDirectory)

	plugin := Plugin{Descriptor: descriptor}
	if len(raw.MapCommand) > 0 {
		stage, err := prepareCommandStage(descriptor.Name, "map", raw.MapCommand, working, environment, timeout, parallel)
		if err != nil {
			return Plugin{}, err
		}
		plugin.Map = stage.mapCall
	}
	if len(raw.ReduceCommand) > 0 {
		stage, err := prepareCommandStage(descriptor.Name, "reduce", raw.ReduceCommand, working, environment, timeout, parallel)
		if err != nil {
			return Plugin{}, err
		}
		plugin.Reduce = stage.reduceCall
	}
	if plugin.Map == nil && plugin.Reduce == nil {
		return Plugin{}, errors.New("command plugin requires map_command or reduce_command")
	}
	return plugin, nil
}

func prepareCommandStage(plugin, stage string, rawCommand []string, rawWorking string, environment []string, timeout time.Duration, parallel int) (*commandStage, error) {
	if len(rawCommand) == 0 || strings.TrimSpace(rawCommand[0]) == "" {
		return nil, errors.New("command stage requires executable")
	}
	command := append([]string(nil), rawCommand...)
	command[0] = filepath.Clean(strings.TrimSpace(command[0]))
	if !filepath.IsAbs(command[0]) {
		return nil, errors.New("command executable must be absolute")
	}
	for _, argument := range command {
		if strings.IndexByte(argument, 0) >= 0 {
			return nil, errors.New("command argument contains NUL")
		}
	}
	info, err := os.Stat(command[0])
	if err != nil {
		return nil, fmt.Errorf("command executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("command executable must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("command executable is not executable")
	}
	working := strings.TrimSpace(rawWorking)
	if working == "" {
		working = filepath.Dir(command[0])
	}
	if !filepath.IsAbs(working) {
		return nil, errors.New("working_directory must be absolute")
	}
	workingInfo, err := os.Stat(working)
	if err != nil {
		return nil, fmt.Errorf("working_directory: %w", err)
	}
	if !workingInfo.IsDir() {
		return nil, errors.New("working_directory must be a directory")
	}
	return &commandStage{plugin: plugin, stage: stage, command: command, environment: append([]string(nil), environment...), workingDirectory: filepath.Clean(working), timeout: timeout, semaphore: make(chan struct{}, parallel)}, nil
}

func (s *commandStage) mapCall(ctx context.Context, input MapInput) ([]Record, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var output struct {
		Records []Record `json:"records"`
	}
	if err := s.call(ctx, payload, &output); err != nil {
		return nil, err
	}
	if len(output.Records) > MaxRecords {
		return nil, ErrLimitExceeded
	}
	return output.Records, nil
}

func (s *commandStage) reduceCall(ctx context.Context, input ReduceInput) (Record, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return Record{}, err
	}
	var output struct {
		Record Record `json:"record"`
	}
	if err := s.call(ctx, payload, &output); err != nil {
		return Record{}, err
	}
	return output.Record, nil
}

func (s *commandStage) call(parent context.Context, payload []byte, target any) error {
	if len(payload) > MaxMessageBytes {
		return ErrLimitExceeded
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}
	command := exec.CommandContext(ctx, s.command[0], s.command[1:]...)
	command.Dir = s.workingDirectory
	command.Env = append([]string{
		"WEAVERSSH_MAPREDUCE_PLUGIN=" + s.plugin,
		"WEAVERSSH_MAPREDUCE_STAGE=" + s.stage,
		"WEAVERSSH_MAPREDUCE_PROTOCOL=" + ProtocolVersion,
	}, s.environment...)
	command.Stdin = bytes.NewReader(append(payload, '\n'))
	stdout := &limitedBuffer{maximum: MaxMessageBytes}
	stderr := &limitedBuffer{maximum: maxCommandDiagnosticBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("command failed: %w; stderr=%q", err, stderr.String())
	}
	if stdout.overflow {
		return errors.New("mapreduce: command output exceeds limit")
	}
	if err := decodeStrict(bytes.TrimSpace(stdout.Bytes()), target); err != nil {
		return fmt.Errorf("mapreduce: decode command output: %w", err)
	}
	return nil
}

func normalizeCommandEnvironment(raw map[string]string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	normalized := make(map[string]string, len(raw))
	for original, value := range raw {
		key := strings.TrimSpace(original)
		if !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("mapreduce: invalid command environment")
		}
		if strings.HasPrefix(key, "WEAVERSSH_MAPREDUCE_") {
			return nil, fmt.Errorf("mapreduce: reserved environment variable %q", key)
		}
		if _, exists := normalized[key]; exists {
			return nil, fmt.Errorf("mapreduce: duplicate environment variable %q", key)
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
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (b *limitedBuffer) Write(payload []byte) (int, error) {
	original := len(payload)
	remaining := b.maximum - b.buffer.Len()
	if remaining > 0 {
		if len(payload) > remaining {
			payload = payload[:remaining]
			b.overflow = true
		}
		_, _ = b.buffer.Write(payload)
	} else if original > 0 {
		b.overflow = true
	}
	return original, nil
}
func (b *limitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedBuffer) String() string { return b.buffer.String() }
