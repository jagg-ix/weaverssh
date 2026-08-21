package terminalsession

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"weaverssh/containerstream"
)

func validTerminalPolicy() Policy {
	return Policy{
		Version: PolicyVersion,
		Default: "deny",
		Actions: []ActionPolicy{{
			Name: "debug-shell", Executable: "/bin/bash", FixedArgs: []string{"--noprofile"},
			Environment: map[string]string{"LANG": "C"},
			Principals:  []string{"alice@example.test"}, Sources: []string{"laptop"},
			Endpoints: []string{"node-a"}, Targets: []string{"pod-a"}, Providers: []string{"podman"},
			Options: map[string][]string{"namespace": {"jobs"}, "container": {"worker"}},
			MaxArgs: 2, MaxStdinBytes: 4096, Timeout: "5m", DetachTTL: "30m",
			ReplayBytes: 8192, Recording: RecordingRequired,
		}},
	}
}

func TestPolicyAuthorizerMapsNamedActionWithoutShell(t *testing.T) {
	authorizer, err := NewPolicyAuthorizer(validTerminalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	request.Action = "debug-shell"
	request.TargetURI = "vfs://container/node-a/pod-a/dev/tty?provider=podman&namespace=jobs&container=worker"
	request.Args = []string{"-l"}
	grant, err := authorizer.AuthorizeOpen(context.Background(), testIdentity(), request)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/bin/bash", "--noprofile", "-l"}; !reflect.DeepEqual(grant.Process.Argv, want) {
		t.Fatalf("argv=%q want=%q", grant.Process.Argv, want)
	}
	if grant.Process.Environment["LANG"] != "C" || grant.Process.Environment["TERM"] != "xterm-256color" {
		t.Fatalf("environment=%v", grant.Process.Environment)
	}
	if !grant.Process.TTY || grant.Process.Timeout != 5*time.Minute || grant.Process.MaxStdinBytes != 4096 || grant.DetachTTL != 30*time.Minute || grant.RecordingMode != RecordingRequired {
		t.Fatalf("unexpected grant: %+v", grant)
	}
}

func TestPolicyAuthorizerMapsNonInteractiveProcessFromBrokerIdentity(t *testing.T) {
	authorizer, err := NewPolicyAuthorizer(validTerminalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	target, err := containerstream.ParseURI("vfs://container/node-a/pod-a/proc/exec?provider=podman&namespace=jobs&container=worker")
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	spec, err := authorizer.AuthorizeContainerProcess(context.Background(), containerstream.ProcessIdentity{
		Principal: identity.Principal, SourceNode: identity.SourceNode,
		SourceBinding: identity.SourceBinding, ChainSHA256: identity.ChainSHA256,
	}, target, containerstream.StartRequest{Action: "debug-shell", Args: []string{"-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if spec.TTY || spec.Environment["TERM"] != "" || !reflect.DeepEqual(spec.Argv, []string{"/bin/bash", "--noprofile", "-l"}) {
		t.Fatalf("unexpected non-interactive spec: %+v", spec)
	}
	if _, err := authorizer.AuthorizeContainerProcess(context.Background(), containerstream.ProcessIdentity{}, target, containerstream.StartRequest{Action: "debug-shell"}); !errors.Is(err, containerstream.ErrProcessPermission) {
		t.Fatalf("unbound identity error=%v", err)
	}
}

func TestPolicyAuthorizerDeniesUnlistedInputsAndRechecksReattach(t *testing.T) {
	authorizer, err := NewPolicyAuthorizer(validTerminalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	request.Action = "debug-shell"
	request.TargetURI = "vfs://container/node-a/pod-a/dev/tty?provider=podman&namespace=jobs&container=worker"

	tests := []struct {
		name   string
		mutate func(*OpenRequest, *Identity)
	}{
		{"unknown action", func(r *OpenRequest, _ *Identity) { r.Action = "arbitrary-command" }},
		{"client environment", func(r *OpenRequest, _ *Identity) {
			r.Environment = map[string]string{"SAFE": "still-not-client-controlled"}
		}},
		{"provider", func(r *OpenRequest, _ *Identity) {
			r.TargetURI = "vfs://container/node-a/pod-a/dev/tty?provider=docker&namespace=jobs&container=worker"
		}},
		{"option", func(r *OpenRequest, _ *Identity) {
			r.TargetURI = "vfs://container/node-a/pod-a/dev/tty?provider=podman&namespace=prod&container=worker"
		}},
		{"principal", func(_ *OpenRequest, i *Identity) { i.Principal = "mallory@example.test" }},
		{"arguments", func(r *OpenRequest, _ *Identity) { r.Args = []string{"1", "2", "3"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			identity := testIdentity()
			test.mutate(&candidate, &identity)
			if _, err := authorizer.AuthorizeOpen(context.Background(), identity, candidate); !errors.Is(err, ErrDenied) {
				t.Fatalf("error=%v want denied", err)
			}
		})
	}

	snapshot := Snapshot{Action: request.Action, TargetURI: request.TargetURI}
	if err := authorizer.AuthorizeReattach(context.Background(), testIdentity(), snapshot); err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	identity.SourceNode = "other-laptop"
	if err := authorizer.AuthorizeReattach(context.Background(), identity, snapshot); !errors.Is(err, ErrDenied) {
		t.Fatalf("reattach error=%v want denied", err)
	}
}

func TestPolicyRejectsCredentialEnvironmentAndNonAbsoluteExecutable(t *testing.T) {
	policy := validTerminalPolicy()
	policy.Actions[0].Environment["API_TOKEN"] = "secret"
	if _, err := NewPolicyAuthorizer(policy); err == nil {
		t.Fatal("credential-like environment accepted")
	}
	policy = validTerminalPolicy()
	policy.Actions[0].Executable = "bash"
	if _, err := NewPolicyAuthorizer(policy); err == nil {
		t.Fatal("relative executable accepted")
	}
}

func TestDocumentedTerminalPolicyExampleParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "examples", "terminal-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Actions) != 1 || policy.Actions[0].Name != "debug-shell" {
		t.Fatalf("policy=%+v", policy)
	}
}

func TestDocumentedProcessPolicyExampleParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "examples", "process-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Actions) != 1 || policy.Actions[0].Name != "inspect-build" {
		t.Fatalf("policy=%+v", policy)
	}
}
