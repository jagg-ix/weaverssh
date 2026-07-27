package sshagent

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testPublicKey(t *testing.T, comment string) (string, Identity) {
	t.Helper()
	blob := base64.StdEncoding.EncodeToString([]byte("test-public-key-blob"))
	line := "ssh-ed25519 " + blob + " " + comment
	identity, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	return line, identity
}

func TestListAndEnsureLoadedIgnoreComments(t *testing.T) {
	line, expected := testPublicKey(t, "configured-comment")
	keyFile := filepath.Join(t.TempDir(), "hop.pub")
	if err := os.WriteFile(keyFile, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{AuthSock: "/tmp/agent.sock", Run: func(_ context.Context, _ string, args []string, _ []string) ([]byte, []byte, error) {
		if !reflect.DeepEqual(args, []string{"-L"}) {
			t.Fatalf("args=%q", args)
		}
		return []byte(expected.KeyType + " " + expected.KeyBlob + " agent-comment\n"), nil, nil
	}}
	got, err := client.EnsureLoaded(context.Background(), keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.Canonical() != expected.Canonical() || got.Fingerprint != expected.Fingerprint {
		t.Fatalf("got=%+v expected=%+v", got, expected)
	}
}

func TestListTreatsNoIdentitiesAsEmpty(t *testing.T) {
	client := Client{AuthSock: "/tmp/agent.sock", Run: func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		return nil, []byte("The agent has no identities.\n"), errors.New("exit status 1")
	}}
	identities, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 0 {
		t.Fatalf("identities=%+v", identities)
	}
}

func TestUnavailableAgentIsClassified(t *testing.T) {
	client := Client{AuthSock: "/tmp/missing.sock", Run: func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		return nil, []byte("Could not open a connection to your authentication agent."), errors.New("exit status 2")
	}}
	_, err := client.List(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v", err)
	}
}

func TestAddBuildsLifetimeAndConfirmationArguments(t *testing.T) {
	var got []string
	client := Client{AuthSock: "/tmp/agent.sock", Run: func(_ context.Context, _ string, args []string, environment []string) ([]byte, []byte, error) {
		got = append([]string(nil), args...)
		found := false
		for _, entry := range environment {
			if entry == "SSH_AUTH_SOCK=/tmp/agent.sock" {
				found = true
			}
		}
		if !found {
			t.Fatal("explicit SSH_AUTH_SOCK was not passed")
		}
		return nil, nil, nil
	}}
	if err := client.Add(context.Background(), "/keys/hop", AddOptions{Lifetime: "5m", Confirm: true, Quiet: true}); err != nil {
		t.Fatal(err)
	}
	want := []string{"-q", "-c", "-t", "5m", "/keys/hop"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestEnsureLoadedReturnsActionableError(t *testing.T) {
	line, expected := testPublicKey(t, "expected")
	keyFile := filepath.Join(t.TempDir(), "hop.pub")
	if err := os.WriteFile(keyFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	otherBlob := base64.StdEncoding.EncodeToString([]byte("different-key"))
	client := Client{AuthSock: "/tmp/agent.sock", Run: func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		return []byte("ssh-ed25519 " + otherBlob + " other\n"), nil, nil
	}}
	_, err := client.EnsureLoaded(context.Background(), keyFile)
	if !errors.Is(err, ErrIdentityNotLoaded) || !strings.Contains(err.Error(), expected.Fingerprint) || !strings.Contains(err.Error(), "wv ssh-agent add") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadPublicKeyRejectsPrivateMaterial(t *testing.T) {
	file := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(file, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeyFile(file); err == nil || !strings.Contains(err.Error(), ".pub") {
		t.Fatalf("error=%v", err)
	}
}

func TestTestAndRemoveArguments(t *testing.T) {
	line, _ := testPublicKey(t, "key")
	file := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	client := Client{AuthSock: "/tmp/agent.sock", Run: func(_ context.Context, _ string, args []string, _ []string) ([]byte, []byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil, nil
	}}
	if err := client.Test(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"-T", file}, {"-d", file}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q want=%q", calls, want)
	}
}
