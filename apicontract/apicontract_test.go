package apicontract

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryBuildsPortableLock(t *testing.T) {
	root := t.TempDir()
	schemaDir := filepath.Join(root, "schema")
	if err := os.MkdirAll(schemaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(schemaDir, "request.json")
	schema := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:test:request","title":"Request","type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`
	if err := os.WriteFile(schemaPath, []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := Catalog{Version: CatalogVersion, Name: "test-api", Revision: "1.0.0", Contracts: []Contract{{ID: "request", Version: "1.0.0", Kind: KindJSONSchema, Path: schemaPath, Stability: StabilityStable, Compatibility: CompatibilityBackward}}}
	lock, err := NewRegistry().ValidateCatalog(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Contracts) != 1 || lock.Contracts[0].SHA256 == "" || lock.Contracts[0].Path != "request.json" {
		t.Fatalf("lock=%+v", lock)
	}
	if !contains(lock.Contracts[0].Symbols, "property:id") || !contains(lock.Contracts[0].Symbols, "schema:Request") {
		t.Fatalf("symbols=%v", lock.Contracts[0].Symbols)
	}
}

func TestCompareLocksEnforcesBackwardCompatibilityAndSemanticVersions(t *testing.T) {
	base := Lock{Version: LockVersion, CatalogName: "api", Revision: "1.0.0", CatalogSHA256: strings.Repeat("a", 64), Contracts: []LockedEntry{
		{ID: "session", Version: "2.0.0", Kind: KindOpenRPC, Path: "session-2.json", Stability: StabilityStable, Compatibility: CompatibilityBackward, SHA256: strings.Repeat("b", 64), Symbols: []string{"method:a", "method:b"}},
		{ID: "session", Version: "10.0.0", Kind: KindOpenRPC, Path: "session-10.json", Stability: StabilityStable, Compatibility: CompatibilityBackward, SHA256: strings.Repeat("c", 64), Symbols: []string{"method:a", "method:b", "method:c"}},
	}}
	current := Lock{Version: LockVersion, CatalogName: "api", Revision: "11.0.0", CatalogSHA256: strings.Repeat("d", 64), Contracts: []LockedEntry{{ID: "session", Version: "11.0.0", Kind: KindOpenRPC, Path: "session-11.json", Stability: StabilityStable, Compatibility: CompatibilityBackward, SHA256: strings.Repeat("e", 64), Symbols: []string{"method:a", "method:c"}}}}
	report, err := CompareLocks(base, current)
	if err != nil {
		t.Fatal(err)
	}
	if report.Compatible || len(report.Changes) != 1 || report.Changes[0].PreviousVersion != "10.0.0" || !contains(report.Changes[0].RemovedSymbols, "method:b") {
		t.Fatalf("report=%+v", report)
	}
}

func TestProtobufValidatorSupportsProto3AndEditions(t *testing.T) {
	for _, header := range []string{`syntax = "proto3";`, `edition = "2024";`} {
		payload := []byte(header + `
package weaverssh.control.v1;
message StatusRequest {}
message StatusResponse {}
service Control { rpc Status(StatusRequest) returns (StatusResponse); }
`)
		summary, err := (protobufSourceValidator{}).Validate(context.Background(), Contract{Kind: KindProtobuf}, payload)
		if err != nil {
			t.Fatal(err)
		}
		if !contains(summary.Symbols, "message:weaverssh.control.v1.StatusRequest") || !contains(summary.Symbols, "service:weaverssh.control.v1.Control") || !contains(summary.Symbols, "rpc:weaverssh.control.v1.Status") {
			t.Fatalf("symbols=%v", summary.Symbols)
		}
	}
}

func TestFileProviderDetectsContractReplacement(t *testing.T) {
	root := t.TempDir()
	schemaPath := filepath.Join(root, "schema.json")
	payload := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Value","type":"string"}`)
	if err := os.WriteFile(schemaPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(root, "catalog.json")
	catalog := Catalog{Version: CatalogVersion, Name: "provider-api", Revision: "1.0.0", Contracts: []Contract{{ID: "value", Version: "1.0.0", Kind: KindJSONSchema, Path: "schema.json", Stability: StabilityStable, Compatibility: CompatibilityBackward}}}
	catalogPayload, _ := json.Marshal(catalog)
	if err := os.WriteFile(catalogPath, catalogPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := OpenFileProvider(context.Background(), catalogPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	read, entry, err := provider.Read(context.Background(), "value", "")
	if err != nil || string(read) != string(payload) || entry.Version != "1.0.0" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	if err := os.WriteFile(schemaPath, []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Changed","type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Read(context.Background(), "value", "1.0.0"); err == nil {
		t.Fatal("provider accepted replaced contract bytes")
	}
}

type testGenerator struct{ files []GeneratedFile }

func (testGenerator) Name() string { return "test" }
func (testGenerator) Kind() Kind   { return KindJSONSchema }
func (generator testGenerator) Generate(context.Context, GenerationRequest) ([]GeneratedFile, error) { return generator.files, nil }

func TestGenerationRegistryConfinesOutput(t *testing.T) {
	registry := NewGenerationRegistry()
	if err := registry.Register(testGenerator{files: []GeneratedFile{{Path: "client/generated.go", Content: []byte("package client\n")}}}); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	written, err := registry.Generate(context.Background(), "test", GenerationRequest{Contract: Contract{Kind: KindJSONSchema}, OutputDir: output})
	if err != nil || len(written) != 1 {
		t.Fatalf("written=%v err=%v", written, err)
	}
	registry = NewGenerationRegistry()
	if err := registry.Register(testGenerator{files: []GeneratedFile{{Path: "../escape", Content: []byte("x")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Generate(context.Background(), "test", GenerationRequest{Contract: Contract{Kind: KindJSONSchema}, OutputDir: output}); err == nil {
		t.Fatal("generator escaped output directory")
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
