package app

import (
	"strings"
	"testing"

	"weaverssh/originruntime"
)

func TestInjectOpenSSHEnvironmentIncludesOriginRuntimeMetadata(t *testing.T) {
	t.Setenv(originruntime.EnvKind, "docker")
	t.Setenv(originruntime.EnvID, "docker-0123456789abcdef")
	args, direct, err := injectOpenSSHEnvironment([]string{"ssh", "host"}, map[string]string{EnvWVOrigin: "workstation-42"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !direct {
		t.Fatal("direct SSH invocation was not recognized")
	}
	joined := strings.Join(args, " ")
	for _, expected := range []string{
		"WVORIGIN=workstation-42",
		"WVORIGIN_RUNTIME=docker",
		"WVORIGIN_RUNTIME_ID=docker-0123456789abcdef",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("args=%q missing %q", args, expected)
		}
	}
}

func TestInjectOpenSSHEnvironmentRejectsRuntimeConflict(t *testing.T) {
	t.Setenv(originruntime.EnvKind, "wsl")
	_, _, err := injectOpenSSHEnvironment(
		[]string{"ssh", "-o", "SetEnv=WVORIGIN_RUNTIME=docker", "host"},
		map[string]string{EnvWVOrigin: "workstation-42"},
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "conflicting OpenSSH SetEnv") {
		t.Fatalf("err=%v", err)
	}
}
