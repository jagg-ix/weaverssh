package containerstream

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
)

type captureRunner struct {
	commands []Command
	payload  string
}

func (r *captureRunner) Open(_ context.Context, command Command) (io.ReadCloser, error) {
	r.commands = append(r.commands, command)
	return io.NopCloser(strings.NewReader(r.payload)), nil
}

func TestBuiltInAdapterCommands(t *testing.T) {
	request := Request{
		Endpoint: "node-a", TargetID: "workload-a", FilePath: "/var/data.bin",
		Options: map[string]string{"context": "dev", "namespace": "jobs", "container": "worker", "connection": "rootless", "task": "api"},
	}
	tests := []struct {
		name     string
		provider Provider
		options  map[string]string
		want     []string
	}{
		{"kubernetes", NewKubernetesProvider(nil, "kubectl-x"), map[string]string{"context": "dev", "namespace": "jobs", "container": "worker"}, []string{"kubectl-x", "--context", "dev", "--namespace", "jobs", "exec", "workload-a", "--container", "worker", "--", "cat", "--", "/var/data.bin"}},
		{"rancher", NewRancherProvider(nil, "k3s-x"), map[string]string{"context": "dev", "namespace": "jobs", "container": "worker"}, []string{"k3s-x", "kubectl", "--context", "dev", "--namespace", "jobs", "exec", "workload-a", "--container", "worker", "--", "cat", "--", "/var/data.bin"}},
		{"cri", NewCRIProvider(nil, "crictl-x"), nil, []string{"crictl-x", "exec", "workload-a", "cat", "--", "/var/data.bin"}},
		{"docker", NewDockerProvider(nil, "docker-x"), map[string]string{"context": "dev"}, []string{"docker-x", "--context", "dev", "exec", "workload-a", "cat", "--", "/var/data.bin"}},
		{"podman", NewPodmanProvider(nil, "podman-x"), map[string]string{"connection": "rootless"}, []string{"podman-x", "--connection", "rootless", "exec", "workload-a", "cat", "--", "/var/data.bin"}},
		{"nomad", NewNomadProvider(nil, "nomad-x"), map[string]string{"namespace": "jobs", "task": "api"}, []string{"nomad-x", "alloc", "exec", "-i=false", "-t=false", "-namespace=jobs", "-task=api", "workload-a", "cat", "--", "/var/data.bin"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request.Options = test.options
			runner := &captureRunner{payload: "bytes"}
			provider := test.provider.(*cliProvider)
			provider.runner = runner
			stream, err := provider.OpenContainerStream(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := io.ReadAll(stream)
			_ = stream.Close()
			if string(payload) != "bytes" || len(runner.commands) != 1 || !reflect.DeepEqual(runner.commands[0].Args, test.want) {
				t.Fatalf("payload=%q command=%#v want=%#v", payload, runner.commands, test.want)
			}
		})
	}
}

func TestAdapterRejectsFlagShapedOption(t *testing.T) {
	provider := NewKubernetesProvider(&captureRunner{}, "kubectl")
	_, err := provider.OpenContainerStream(context.Background(), Request{
		TargetID: "pod-a", FilePath: "/data", Options: map[string]string{"namespace": "--all"},
	})
	if err == nil {
		t.Fatal("expected unsafe option rejection")
	}
}

func TestAdapterRejectsUnsupportedOption(t *testing.T) {
	provider := NewDockerProvider(&captureRunner{}, "docker")
	_, err := provider.OpenContainerStream(context.Background(), Request{
		TargetID: "container-a", FilePath: "/data", Options: map[string]string{"namespace": "jobs"},
	})
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("err=%v", err)
	}
}
