package originruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type nativeResolver struct{}

func (nativeResolver) Kind() Kind { return KindNative }
func (nativeResolver) Resolve(_ context.Context, config Config, digest string, _ Runner) (Descriptor, error) {
	hostRoot, err := canonicalHostDirectory(config.HostRoot)
	if err != nil {
		return Descriptor{}, fmt.Errorf("originruntime: native root: %w", err)
	}
	guestRoot := normalizeGuestPath(config.GuestRoot)
	mappings, err := canonicalMappings(hostRoot, guestRoot, config.PathMappings)
	if err != nil {
		return Descriptor{}, err
	}
	return Descriptor{
		Version: DescriptorVersion, Name: config.Name, Kind: config.Kind,
		RuntimeID: runtimeID(config.Kind, config.Name+"\x00"+hostRoot), GuestRoot: guestRoot,
		HostRoot: hostRoot, ReadOnly: config.ReadOnly,
		Capabilities: []Capability{CapabilityExec, CapabilityFilesystem, CapabilityPathMap},
		PathMappings: mappings, ConfigSHA256: digest,
	}, nil
}
func (nativeResolver) PrepareExec(_ context.Context, _ Config, descriptor Descriptor, request ExecRequest) (RunRequest, error) {
	if len(request.Command) == 0 {
		return RunRequest{}, errors.New("originruntime: command is required")
	}
	if err := validateExecutionEnvironment(request.Environment); err != nil {
		return RunRequest{}, err
	}
	command := append([]string(nil), request.Command...)
	if path.IsAbs(filepath.ToSlash(command[0])) {
		if mapped, err := mapGuestToHost(descriptor.PathMappings, command[0]); err == nil {
			command[0] = mapped
		} else if !errors.Is(err, ErrPathUnmapped) {
			return RunRequest{}, fmt.Errorf("originruntime: map native command: %w", err)
		}
	}
	directory := strings.TrimSpace(request.Directory)
	if directory != "" && path.IsAbs(filepath.ToSlash(directory)) {
		if mapped, err := mapGuestToHost(descriptor.PathMappings, directory); err == nil {
			directory = mapped
		} else if !errors.Is(err, ErrPathUnmapped) {
			return RunRequest{}, fmt.Errorf("originruntime: map native working directory: %w", err)
		}
	}
	return RunRequest{Args: command, Environment: cloneEnvironment(request.Environment), Directory: directory, InheritHostEnv: request.InheritHostEnv, Stdin: request.Stdin, MaxOutputBytes: request.MaxOutputBytes}, nil
}

type wslResolver struct{}

func (wslResolver) Kind() Kind { return KindWSL }
func (wslResolver) Resolve(ctx context.Context, config Config, digest string, runner Runner) (Descriptor, error) {
	hostRoot := config.HostRoot
	if hostRoot == "" {
		result, err := runner.Run(ctx, RunRequest{
			Args: []string{config.WSL.Binary, "--distribution", config.WSL.Distribution, "--exec", "wslpath", "-w", config.GuestRoot},
			InheritHostEnv: true, MaxOutputBytes: 64 << 10,
		})
		if err != nil {
			return Descriptor{}, fmt.Errorf("originruntime: resolve WSL root: %w: %s", err, strings.TrimSpace(string(result.Stderr)))
		}
		hostRoot = strings.TrimSpace(string(result.Stdout))
	}
	canonical, err := canonicalHostDirectory(hostRoot)
	if err != nil {
		return Descriptor{}, fmt.Errorf("originruntime: WSL host root: %w", err)
	}
	guestRoot := normalizeGuestPath(config.GuestRoot)
	mappings, err := canonicalMappings(canonical, guestRoot, config.PathMappings)
	if err != nil {
		return Descriptor{}, err
	}
	return Descriptor{
		Version: DescriptorVersion, Name: config.Name, Kind: config.Kind,
		RuntimeID: runtimeID(config.Kind, config.WSL.Distribution), GuestRoot: guestRoot,
		HostRoot: canonical, ReadOnly: config.ReadOnly,
		Capabilities: []Capability{CapabilityExec, CapabilityFilesystem, CapabilityPathMap},
		PathMappings: mappings, ConfigSHA256: digest,
	}, nil
}
func (wslResolver) PrepareExec(_ context.Context, config Config, _ Descriptor, request ExecRequest) (RunRequest, error) {
	if len(request.Command) == 0 {
		return RunRequest{}, errors.New("originruntime: command is required")
	}
	environment := effectiveEnvironment(request)
	assignments, err := validatedEnvironmentAssignments(environment)
	if err != nil {
		return RunRequest{}, err
	}
	args := []string{config.WSL.Binary, "--distribution", config.WSL.Distribution}
	if directory := normalizeOptionalGuestPath(request.Directory); directory != "" {
		if !path.IsAbs(directory) {
			return RunRequest{}, errors.New("originruntime: WSL working directory must be absolute")
		}
		args = append(args, "--cd", directory)
	}
	args = append(args, "--exec", config.WSL.EnvBinary, "--")
	args = append(args, assignments...)
	args = append(args, request.Command...)
	return RunRequest{Args: args, InheritHostEnv: true, Stdin: request.Stdin, MaxOutputBytes: request.MaxOutputBytes}, nil
}

type dockerResolver struct{}

type dockerState struct {
	Running bool `json:"Running"`
	Paused  bool `json:"Paused"`
}

type dockerMount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type dockerInspection struct {
	ID     string        `json:"Id"`
	State  dockerState   `json:"State"`
	Mounts []dockerMount `json:"Mounts"`
}

func (dockerResolver) Kind() Kind { return KindDocker }
func (dockerResolver) Resolve(ctx context.Context, config Config, digest string, runner Runner) (Descriptor, error) {
	result, err := runner.Run(ctx, RunRequest{
		Args: []string{config.Docker.Binary, "inspect", "--type", "container", config.Docker.Container},
		InheritHostEnv: true, MaxOutputBytes: 2 << 20,
	})
	if err != nil {
		return Descriptor{}, fmt.Errorf("originruntime: docker inspect: %w: %s", err, strings.TrimSpace(string(result.Stderr)))
	}
	var inspections []dockerInspection
	if err := json.Unmarshal(result.Stdout, &inspections); err != nil || len(inspections) != 1 {
		return Descriptor{}, errors.New("originruntime: docker inspect returned an invalid container description")
	}
	inspection := inspections[0]
	if config.Docker.RequireRunning && (!inspection.State.Running || inspection.State.Paused) {
		return Descriptor{}, errors.New("originruntime: Docker container is not running and executable")
	}
	guestRoot := normalizeGuestPath(config.GuestRoot)
	var selected dockerMount
	for _, mount := range inspection.Mounts {
		destination := normalizeGuestPath(mount.Destination)
		source := strings.TrimSpace(mount.Source)
		if source == "" || !guestContains(destination, guestRoot) {
			continue
		}
		if len(destination) > len(selected.Destination) {
			selected = mount
			selected.Source = source
			selected.Destination = destination
		}
	}
	hostRoot := config.HostRoot
	if hostRoot == "" {
		if selected.Source == "" {
			return Descriptor{}, errors.New("originruntime: Docker guest_root is not backed by a discoverable host mount; configure host_root or a bind mount")
		}
		relative, ok := guestRelative(selected.Destination, guestRoot)
		if !ok {
			return Descriptor{}, errors.New("originruntime: Docker mount does not contain guest_root")
		}
		hostRoot = selected.Source
		if relative != "." {
			hostRoot = filepath.Join(hostRoot, filepath.FromSlash(relative))
		}
	}
	canonical, err := canonicalHostDirectory(hostRoot)
	if err != nil {
		return Descriptor{}, fmt.Errorf("originruntime: Docker host root: %w", err)
	}
	mappings, err := canonicalMappings(canonical, guestRoot, config.PathMappings)
	if err != nil {
		return Descriptor{}, err
	}
	identity := strings.TrimSpace(inspection.ID)
	if identity == "" {
		identity = config.Docker.Container
	}
	capabilities := []Capability{CapabilityFilesystem, CapabilityPathMap}
	if inspection.State.Running && !inspection.State.Paused {
		capabilities = append(capabilities, CapabilityExec)
	}
	readOnly := config.ReadOnly
	if selected.Destination != "" && !selected.RW {
		readOnly = true
	}
	return Descriptor{
		Version: DescriptorVersion, Name: config.Name, Kind: config.Kind,
		RuntimeID: runtimeID(config.Kind, identity), GuestRoot: guestRoot,
		HostRoot: canonical, ReadOnly: readOnly,
		Capabilities: capabilities, PathMappings: mappings, ConfigSHA256: digest,
	}, nil
}
func (dockerResolver) PrepareExec(_ context.Context, config Config, _ Descriptor, request ExecRequest) (RunRequest, error) {
	if len(request.Command) == 0 {
		return RunRequest{}, errors.New("originruntime: command is required")
	}
	environment := effectiveEnvironment(request)
	assignments, err := validatedEnvironmentAssignments(environment)
	if err != nil {
		return RunRequest{}, err
	}
	args := []string{config.Docker.Binary, "exec"}
	if request.Stdin != nil {
		args = append(args, "--interactive")
	}
	if config.Docker.User != "" {
		args = append(args, "--user", config.Docker.User)
	}
	directory := normalizeOptionalGuestPath(request.Directory)
	if directory == "" {
		directory = config.Docker.WorkingDir
	}
	if directory != "" {
		if !path.IsAbs(directory) {
			return RunRequest{}, errors.New("originruntime: Docker working directory must be absolute")
		}
		args = append(args, "--workdir", directory)
	}
	for _, assignment := range assignments {
		args = append(args, "--env", assignment)
	}
	args = append(args, config.Docker.Container)
	args = append(args, request.Command...)
	return RunRequest{Args: args, InheritHostEnv: true, Stdin: request.Stdin, MaxOutputBytes: request.MaxOutputBytes}, nil
}

type vmResolver struct{}

func (vmResolver) Kind() Kind { return KindVM }
func (vmResolver) Resolve(_ context.Context, config Config, digest string, _ Runner) (Descriptor, error) {
	if config.VM.Driver != "shared-folder" {
		return Descriptor{}, fmt.Errorf("originruntime: VM driver %q requires a trusted custom resolver", config.VM.Driver)
	}
	hostRoot, err := canonicalHostDirectory(config.HostRoot)
	if err != nil {
		return Descriptor{}, fmt.Errorf("originruntime: VM shared folder: %w", err)
	}
	guestRoot := normalizeGuestPath(config.GuestRoot)
	mappings, err := canonicalMappings(hostRoot, guestRoot, config.PathMappings)
	if err != nil {
		return Descriptor{}, err
	}
	return Descriptor{
		Version: DescriptorVersion, Name: config.Name, Kind: config.Kind,
		RuntimeID: runtimeID(config.Kind, config.VM.Driver+"\x00"+config.VM.ID), GuestRoot: guestRoot,
		HostRoot: hostRoot, ReadOnly: config.ReadOnly,
		Capabilities: []Capability{CapabilityFilesystem, CapabilityPathMap},
		PathMappings: mappings, ConfigSHA256: digest,
	}, nil
}
func (vmResolver) PrepareExec(context.Context, Config, Descriptor, ExecRequest) (RunRequest, error) {
	return RunRequest{}, ErrExecUnsupported
}

func canonicalHostDirectory(value string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a real directory")
	}
	return filepath.Clean(resolved), nil
}

func canonicalMappings(hostRoot, guestRoot string, configured []PathMapping) ([]PathMapping, error) {
	mappings := []PathMapping{{Host: hostRoot, Guest: guestRoot}}
	for _, mapping := range configured {
		host, err := canonicalHostDirectory(mapping.Host)
		if err != nil {
			return nil, fmt.Errorf("originruntime: path mapping %s: %w", mapping.Host, err)
		}
		mappings = append(mappings, PathMapping{Host: host, Guest: normalizeGuestPath(mapping.Guest)})
	}
	seenHost := map[string]string{}
	seenGuest := map[string]string{}
	out := make([]PathMapping, 0, len(mappings))
	for _, mapping := range mappings {
		if previousGuest, exists := seenHost[mapping.Host]; exists {
			if previousGuest == mapping.Guest {
				continue
			}
			return nil, fmt.Errorf("originruntime: host path %s maps to multiple guest paths", mapping.Host)
		}
		if previousHost, exists := seenGuest[mapping.Guest]; exists {
			if previousHost == mapping.Host {
				continue
			}
			return nil, fmt.Errorf("originruntime: guest path %s maps to multiple host paths", mapping.Guest)
		}
		seenHost[mapping.Host] = mapping.Guest
		seenGuest[mapping.Guest] = mapping.Host
		out = append(out, mapping)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Guest < out[j].Guest })
	return out, nil
}

func mapGuestToHost(mappings []PathMapping, guestPath string) (string, error) {
	guestPath = normalizeGuestPath(guestPath)
	sorted := append([]PathMapping(nil), mappings...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Guest) > len(sorted[j].Guest) })
	for _, mapping := range sorted {
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

func normalizeGuestPath(value string) string {
	return normalizeGuestAbsolute(value)
}

func normalizeOptionalGuestPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return normalizeGuestPath(value)
}

func guestContains(base, target string) bool {
	_, ok := guestRelative(base, target)
	return ok
}

func runtimeID(kind Kind, identity string) string {
	digest := sha256.Sum256([]byte(string(kind) + "\x00" + identity))
	return string(kind) + "-" + hex.EncodeToString(digest[:12])
}

func effectiveEnvironment(request ExecRequest) map[string]string {
	values := map[string]string{}
	if request.InheritHostEnv {
		for _, entry := range os.Environ() {
			name, value, ok := strings.Cut(entry, "=")
			if ok && validEnvironmentName(name) && !strings.ContainsAny(value, "\x00\r\n") {
				values[name] = value
			}
		}
	}
	for name, value := range request.Environment {
		values[name] = value
	}
	return values
}

func validatedEnvironmentAssignments(values map[string]string) ([]string, error) {
	names := make([]string, 0, len(values))
	for name, value := range values {
		if !validEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("originruntime: invalid guest environment entry %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+"="+values[name])
	}
	return out, nil
}

func validateExecutionEnvironment(values map[string]string) error {
	_, err := validatedEnvironmentAssignments(values)
	return err
}

func cloneEnvironment(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for name, value := range values {
		out[name] = value
	}
	return out
}
