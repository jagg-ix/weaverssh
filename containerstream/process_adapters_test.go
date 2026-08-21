package containerstream

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
)

type duplexTestRunner struct {
	process Process
}

func (r duplexTestRunner) Open(context.Context, Command) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (r duplexTestRunner) Start(context.Context, Command) (Process, error) { return r.process, nil }

func TestBuiltInProcessCommands(t *testing.T) {
	request := Request{
		TargetID: "workload-a",
		Options:  map[string]string{"context": "dev", "namespace": "jobs", "container": "worker", "connection": "rootless", "task": "api"},
	}
	spec := ProcessSpec{Argv: []string{"/usr/bin/printf", "%s", "hello"}, Environment: map[string]string{"B": "2", "A": "1"}}
	remote := []string{"env", "--", "A=1", "B=2", "/usr/bin/printf", "%s", "hello"}
	tests := []struct {
		name     string
		provider Provider
		options  map[string]string
		prefix   []string
	}{
		{"kubernetes", NewKubernetesProvider(nil, "kubectl-x"), map[string]string{"context": "dev", "namespace": "jobs", "container": "worker"}, []string{"kubectl-x", "--context", "dev", "--namespace", "jobs", "exec", "--stdin", "workload-a", "--container", "worker", "--"}},
		{"rancher", NewRancherProvider(nil, "k3s-x"), map[string]string{"context": "dev", "namespace": "jobs", "container": "worker"}, []string{"k3s-x", "kubectl", "--context", "dev", "--namespace", "jobs", "exec", "--stdin", "workload-a", "--container", "worker", "--"}},
		{"cri", NewCRIProvider(nil, "crictl-x"), nil, []string{"crictl-x", "exec", "-i", "workload-a"}},
		{"docker", NewDockerProvider(nil, "docker-x"), map[string]string{"context": "dev"}, []string{"docker-x", "--context", "dev", "exec", "--interactive", "workload-a"}},
		{"podman", NewPodmanProvider(nil, "podman-x"), map[string]string{"connection": "rootless"}, []string{"podman-x", "--connection", "rootless", "exec", "--interactive", "workload-a"}},
		{"nomad", NewNomadProvider(nil, "nomad-x"), map[string]string{"namespace": "jobs", "task": "api"}, []string{"nomad-x", "alloc", "exec", "-i=true", "-t=false", "-namespace=jobs", "-task=api", "workload-a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request.Options = test.options
			provider := test.provider.(*cliProvider)
			got, err := provider.processCommand(request, spec)
			if err != nil {
				t.Fatal(err)
			}
			want := append(append([]string(nil), test.prefix...), remote...)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("command=%#v want=%#v", got, want)
			}
		})
	}
}

func TestCLIFallbackRejectsTTY(t *testing.T) {
	provider := NewDockerProvider(nil, "docker").(ExecutionProvider)
	_, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a"}, ProcessSpec{Argv: []string{"/bin/true"}, TTY: true})
	if err == nil {
		t.Fatal("CLI fallback accepted a remote TTY")
	}
}

func TestCLIFallbackDoesNotAdvertiseRemoteControl(t *testing.T) {
	active := newScriptedProcess()
	provider := NewDockerProvider(duplexTestRunner{process: active}, "docker").(ExecutionProvider)
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a"}, ProcessSpec{Argv: []string{"/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := process.Capabilities()
	if !capabilities.Stdin || !capabilities.Stdout || !capabilities.Stderr || capabilities.TTY || capabilities.Signals || capabilities.Resize || capabilities.Terminate {
		t.Fatalf("CLI capabilities=%+v", capabilities)
	}
	_ = process.Close()
}
