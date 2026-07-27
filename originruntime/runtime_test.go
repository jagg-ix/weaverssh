package originruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	requests []RunRequest
	result   RunResult
	err      error
	results  []RunResult
	errors   []error
}

func (runner *fakeRunner) Run(_ context.Context, request RunRequest) (RunResult, error) {
	runner.requests = append(runner.requests, request)
	index := len(runner.requests) - 1
	if index < len(runner.results) {
		var err error
		if index < len(runner.errors) {
			err = runner.errors[index]
		}
		return runner.results[index], err
	}
	return runner.result, runner.err
}

func TestNativeRuntimeMapsHostAndGuestPaths(t *testing.T) {
	root := t.TempDir()
	extra := t.TempDir()
	config := Config{
		Version: ConfigVersion, Name: "native-origin", Kind: KindNative,
		GuestRoot: "/workspace", HostRoot: root,
		PathMappings: []PathMapping{{Host: extra, Guest: "/artifacts"}},
	}
	runtime, err := Resolve(context.Background(), config, strings.Repeat("a", 64), nil, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := runtime.Descriptor()
	if descriptor.Kind != KindNative || !HasCapability(descriptor, CapabilityFilesystem) || !HasCapability(descriptor, CapabilityExec) {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	hostPath := filepath.Join(root, "nested", "file.txt")
	guestPath, err := runtime.MapHostToGuest(hostPath)
	if err != nil || guestPath != "/workspace/nested/file.txt" {
		t.Fatalf("guest=%q err=%v", guestPath, err)
	}
	mappedBack, err := runtime.MapGuestToHost("/artifacts/report.json")
	if err != nil || mappedBack != filepath.Join(extra, "report.json") {
		t.Fatalf("host=%q err=%v", mappedBack, err)
	}
}

func TestWSLRuntimeDiscoversRootAndBuildsDirectCommand(t *testing.T) {
	hostRoot := t.TempDir()
	runner := &fakeRunner{results: []RunResult{{Stdout: []byte(hostRoot + "\r\n")}, {Stdout: []byte("ok")}}}
	config := Config{
		Version: ConfigVersion, Name: "ubuntu-origin", Kind: KindWSL, GuestRoot: "/home/user/project",
		WSL: &WSLConfig{Distribution: "Ubuntu-24.04", Binary: "wsl.exe", EnvBinary: "/usr/bin/env"},
	}
	runtime, err := Resolve(context.Background(), config, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Descriptor().HostRoot != hostRoot {
		t.Fatalf("descriptor=%+v", runtime.Descriptor())
	}
	result, err := runtime.Exec(context.Background(), ExecRequest{
		Command: []string{"/usr/local/bin/process", "--fast"}, Directory: "/home/user/project/work",
		Environment: map[string]string{"TENANT": "alpha"},
	})
	if err != nil || string(result.Stdout) != "ok" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(runner.requests) != 2 {
		t.Fatalf("requests=%d", len(runner.requests))
	}
	want := []string{"wsl.exe", "--distribution", "Ubuntu-24.04", "--cd", "/home/user/project/work", "--exec", "/usr/bin/env", "--", "TENANT=alpha", "/usr/local/bin/process", "--fast"}
	if !reflect.DeepEqual(runner.requests[1].Args, want) {
		t.Fatalf("args=%q", runner.requests[1].Args)
	}
}

func TestWSLRuntimeRejectsInvalidGuestEnvironment(t *testing.T) {
	hostRoot := t.TempDir()
	runner := &fakeRunner{result: RunResult{Stdout: []byte(hostRoot)}}
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "wsl-env", Kind: KindWSL, GuestRoot: "/workspace",
		WSL: &WSLConfig{Distribution: "Ubuntu"},
	}, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Exec(context.Background(), ExecRequest{Command: []string{"true"}, Environment: map[string]string{"-bad": "value"}})
	if err == nil || !strings.Contains(err.Error(), "invalid guest environment") {
		t.Fatalf("err=%v", err)
	}
}

func TestDockerRuntimeUsesLongestMountAndBuildsExec(t *testing.T) {
	mountRoot := t.TempDir()
	projectRoot := filepath.Join(mountRoot, "project")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	inspection := []dockerInspection{{ID: "0123456789abcdef", State: dockerState{Running: true}}}
	inspection[0].Mounts = append(inspection[0].Mounts, dockerMount{Source: mountRoot, Destination: "/workspace", RW: true})
	payload, _ := json.Marshal(inspection)
	runner := &fakeRunner{results: []RunResult{{Stdout: payload}, {Stdout: []byte("done")}}}
	config := Config{
		Version: ConfigVersion, Name: "container-origin", Kind: KindDocker,
		GuestRoot: "/workspace/project",
		Docker: &DockerConfig{Container: "worker", Binary: "docker", User: "1000:1000", WorkingDir: "/workspace/project", RequireRunning: true},
	}
	runtime, err := Resolve(context.Background(), config, "", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Descriptor().HostRoot != projectRoot || runtime.Descriptor().ReadOnly {
		t.Fatalf("descriptor=%+v", runtime.Descriptor())
	}
	_, err = runtime.Exec(context.Background(), ExecRequest{Command: []string{"processor", "input.dat"}, Environment: map[string]string{"MODE": "safe"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "exec", "--user", "1000:1000", "--workdir", "/workspace/project", "--env", "MODE=safe", "worker", "processor", "input.dat"}
	if !reflect.DeepEqual(runner.requests[1].Args, want) {
		t.Fatalf("args=%q", runner.requests[1].Args)
	}
}

func TestDockerRuntimeRejectsStoppedRequiredContainer(t *testing.T) {
	root := t.TempDir()
	inspection := []dockerInspection{{ID: "stopped", Mounts: []dockerMount{{Source: root, Destination: "/data", RW: true}}}}
	payload, _ := json.Marshal(inspection)
	_, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "stopped", Kind: KindDocker, GuestRoot: "/data",
		Docker: &DockerConfig{Container: "stopped", RequireRunning: true},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: payload}})
	if err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("err=%v", err)
	}
}

func TestDockerStoppedContainerCanExposeReadOnlyFilesystemWithoutExec(t *testing.T) {
	root := t.TempDir()
	inspection := []dockerInspection{{ID: "stopped", Mounts: []dockerMount{{Source: root, Destination: "/data", RW: false}}}}
	payload, _ := json.Marshal(inspection)
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "stopped-fs", Kind: KindDocker, GuestRoot: "/data",
		Docker: &DockerConfig{Container: "stopped"},
	}, "", nil, &fakeRunner{result: RunResult{Stdout: payload}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := runtime.Descriptor()
	if !descriptor.ReadOnly || HasCapability(descriptor, CapabilityExec) || !HasCapability(descriptor, CapabilityFilesystem) {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestVMSharedFolderIsFilesystemOnly(t *testing.T) {
	root := t.TempDir()
	runtime, err := Resolve(context.Background(), Config{
		Version: ConfigVersion, Name: "vm-origin", Kind: KindVM,
		GuestRoot: "/mnt/shared", HostRoot: root,
		VM: &VMConfig{Driver: "shared-folder", ID: "build-vm"},
	}, "", nil, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if HasCapability(runtime.Descriptor(), CapabilityExec) {
		t.Fatal("shared-folder VM unexpectedly advertises execution")
	}
	if _, err := runtime.Exec(context.Background(), ExecRequest{Command: []string{"true"}}); !errors.Is(err, ErrExecUnsupported) {
		t.Fatalf("err=%v", err)
	}
}

type replacementVMResolver struct{}

func (replacementVMResolver) Kind() Kind { return KindVM }
func (replacementVMResolver) Resolve(_ context.Context, config Config, digest string, _ Runner) (Descriptor, error) {
	return Descriptor{Version: DescriptorVersion, Name: config.Name, Kind: KindVM, RuntimeID: "vm-custom", GuestRoot: "/guest", HostRoot: config.HostRoot, Capabilities: []Capability{CapabilityExec, CapabilityFilesystem, CapabilityPathMap}, PathMappings: []PathMapping{{Host: config.HostRoot, Guest: "/guest"}}, ConfigSHA256: digest}, nil
}
func (replacementVMResolver) PrepareExec(_ context.Context, _ Config, _ Descriptor, request ExecRequest) (RunRequest, error) {
	return RunRequest{Args: append([]string{"vmctl", "exec", "--"}, request.Command...)}, nil
}

func TestTrustedResolverCanReplaceVMBaseline(t *testing.T) {
	root := t.TempDir()
	registry := NewRegistry()
	if err := registry.Replace(replacementVMResolver{}); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{result: RunResult{Stdout: []byte("custom")}}
	runtime, err := Resolve(context.Background(), Config{Version: ConfigVersion, Name: "custom-vm", Kind: KindVM, GuestRoot: "/guest", HostRoot: root, VM: &VMConfig{Driver: "libvirt-agent", ID: "vm-a"}}, "", registry, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Exec(context.Background(), ExecRequest{Command: []string{"uname", "-a"}})
	if err != nil || string(result.Stdout) != "custom" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(runner.requests[0].Args, []string{"vmctl", "exec", "--", "uname", "-a"}) {
		t.Fatalf("args=%q", runner.requests[0].Args)
	}
}

func TestDecodeConfigRejectsUnknownFields(t *testing.T) {
	_, _, err := DecodeConfig(strings.NewReader(`{"version":"weaverssh.origin-runtime.v1","name":"x","kind":"native","guest_root":"/x","host_root":"/x","unknown":true}`))
	if err == nil {
		t.Fatal("unknown config field was accepted")
	}
}
