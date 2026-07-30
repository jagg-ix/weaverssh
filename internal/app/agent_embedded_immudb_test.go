package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"weaverssh/evidencebinding"
)

func TestAgentRuntimeWithEmbeddedImmuDBAnchorsAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-immudb")
	config := AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network: "tcp",
		X11Target: "127.0.0.1:6000",
	}
	runtime, err := NewAgentRuntimeWithEmbeddedImmuDB(config, "00112233445566778899aabbccddeeff", AgentEmbeddedImmuDBConfig{
		Path: path, ProviderName: "node-a-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	head := evidencebinding.Head{StreamID: "agent/node-a", Sequence: 1, StatementSHA256: agentSHA256('a')}
	receipt, err := runtime.AnchorEvidenceHead(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Provider != "node-a-local" {
		t.Fatalf("provider=%q", receipt.Provider)
	}
	if err := runtime.VerifyEvidenceReceipt(context.Background(), head, receipt); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}

	reopened, err := NewAgentRuntimeWithEmbeddedImmuDB(config, "00112233445566778899aabbccddeeff", AgentEmbeddedImmuDBConfig{
		Path: path, ProviderName: "node-a-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.VerifyEvidenceReceipt(context.Background(), head, receipt); err != nil {
		t.Fatalf("receipt did not survive agent restart: %v", err)
	}
}

func TestAgentEmbeddedImmuDBConfigFromEnvironment(t *testing.T) {
	values := map[string]string{
		AgentEmbeddedImmuDBPathEnv: "/var/lib/weaverssh/agent-evidence",
		AgentEmbeddedImmuDBProviderEnv: "node-local",
	}
	config := AgentEmbeddedImmuDBConfigFromEnv(func(name string) string { return values[name] })
	if config.Path != values[AgentEmbeddedImmuDBPathEnv] || config.ProviderName != "node-local" {
		t.Fatalf("config=%+v", config)
	}
	if err := (AgentEmbeddedImmuDBConfig{}).Validate(); err == nil {
		t.Fatal("empty embedded configuration was accepted")
	}
}

func TestClosedEmbeddedAgentRejectsAnchoring(t *testing.T) {
	config := AgentConfig{InterfaceMode: string(AgentInterfaceLibrary), X11Network: "tcp", X11Target: "127.0.0.1:6000"}
	runtime, err := NewAgentRuntimeWithEmbeddedImmuDB(config, "cookie", AgentEmbeddedImmuDBConfig{Path: filepath.Join(t.TempDir(), "db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	head := evidencebinding.Head{StreamID: "agent/node-a", Sequence: 1, StatementSHA256: agentSHA256('b')}
	_, err = runtime.AnchorEvidenceHead(context.Background(), head)
	if !errors.Is(err, evidencebinding.ErrInvalidAnchor) {
		t.Fatalf("closed runtime error=%v", err)
	}
}

func agentSHA256(value byte) string {
	buffer := make([]byte, 64)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}
