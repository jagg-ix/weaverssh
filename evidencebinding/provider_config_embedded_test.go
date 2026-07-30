package evidencebinding

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestProviderConfigurationBuildsEmbeddedImmuDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-store")
	config := AnchorProviderConfigFile{
		Version: AnchorProviderConfigVersion,
		Threshold: 1,
		Providers: []AnchorProviderConfig{{Name: "node-a-local", Type: EmbeddedImmuDBProviderName, Path: path}},
	}
	providers, policy, err := config.Build(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseAnchorProviders(providers)
	if len(providers) != 1 || providers[0].Name() != "node-a-local" {
		t.Fatalf("providers=%v", providers)
	}
	head := Head{StreamID: "agent/node-a", Sequence: 1, StatementSHA256: repeatSHA256('f')}
	receipts, err := policy.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Verify(context.Background(), head, receipts); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedProviderConfigurationRejectsRemoteFields(t *testing.T) {
	config := AnchorProviderConfigFile{
		Version: AnchorProviderConfigVersion,
		Threshold: 1,
		Providers: []AnchorProviderConfig{{
			Name: "local", Type: EmbeddedImmuDBProviderName, Path: "/tmp/db", BaseURL: "http://localhost", Token: "not-used",
		}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("embedded provider accepted remote fields")
	}
}

func TestEmbeddedProviderConfigStrictJSON(t *testing.T) {
	document := map[string]any{
		"version": AnchorProviderConfigVersion,
		"threshold": 1,
		"providers": []map[string]any{{"name": "local", "type": EmbeddedImmuDBProviderName, "path": filepath.Join(t.TempDir(), "db")}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeAnchorProviderConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if config.Providers[0].Path == "" {
		t.Fatal("embedded path was not decoded")
	}
}
