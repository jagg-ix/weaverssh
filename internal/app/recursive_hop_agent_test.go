package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"weaverssh/sshagent"
)

func TestRecursiveHopAgentEnvironment(t *testing.T) {
	t.Setenv("WEAVERSSH_SSH_ADD", "/usr/local/bin/ssh-add")
	t.Setenv("WEAVERSSH_HOP_AGENT_ADD", "/keys/hop")
	t.Setenv("WEAVERSSH_HOP_AGENT_LIFETIME", "7m")
	t.Setenv("WEAVERSSH_HOP_AGENT_CONFIRM", "yes")
	t.Setenv("WEAVERSSH_HOP_AGENT_TEST_SIGN", "1")
	got := recursiveHopAgentEnvironment(RecursiveHopConfig{})
	if got.SSHAddBinary != "/usr/local/bin/ssh-add" || got.AgentAddKeyFile != "/keys/hop" || got.AgentAddLifetime != "7m" || !got.AgentAddConfirm || !got.AgentTestSign {
		t.Fatalf("config=%+v", got)
	}
}

func TestPrepareRecursiveHopRejectsMissingAgentIdentityBeforeSigning(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("required-hop-key"))
	keyFile := filepath.Join(t.TempDir(), "hop.pub")
	if err := os.WriteFile(keyFile, []byte("ssh-ed25519 "+blob+" hop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &sshagent.Client{AuthSock: "/tmp/agent.sock", Run: func(_ context.Context, _ string, args []string, _ []string) ([]byte, []byte, error) {
		if !reflect.DeepEqual(args, []string{"-L"}) {
			t.Fatalf("args=%q", args)
		}
		return []byte{}, []byte("The agent has no identities."), errors.New("exit status 1")
	}}
	_, err := PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
		NodeContext:    recursiveHopContext([]string{"root", "child"}, "root"),
		SigningKeyFile: keyFile,
		Verifier:       appHopVerifier{public: nil},
		AgentClient:    fake,
	})
	if err == nil || !strings.Contains(err.Error(), "identity is not loaded") || !strings.Contains(err.Error(), "ssh-agent add") {
		t.Fatalf("error=%v", err)
	}
}
