package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"weaverssh/apicontract"
)

func TestAPIContractLockValidateAndCompare(t *testing.T) {
	root := t.TempDir()
	schemaPath := filepath.Join(root, "value.schema.json")
	if err := os.WriteFile(schemaPath, []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Value","type":"object","properties":{"value":{"type":"string"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(root, "catalog.json")
	catalog := apicontract.Catalog{Version: apicontract.CatalogVersion, Name: "cli-api", Revision: "1.0.0", Contracts: []apicontract.Contract{{ID: "value", Version: "1.0.0", Kind: apicontract.KindJSONSchema, Path: "value.schema.json", Stability: apicontract.StabilityStable, Compatibility: apicontract.CompatibilityBackward}}}
	payload, _ := json.Marshal(catalog)
	if err := os.WriteFile(catalogPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "contracts.lock.json")
	if code := cmdAPIContractLock([]string{"--catalog", catalogPath, "--output", lockPath}); code != 0 {
		t.Fatalf("lock code=%d", code)
	}
	if code := cmdAPIContractValidate([]string{"--catalog", catalogPath, "--lock", lockPath}); code != 0 {
		t.Fatalf("validate code=%d", code)
	}
	if code := cmdAPIContractCompare([]string{"--previous", lockPath, "--current", lockPath}); code != 0 {
		t.Fatalf("compare code=%d", code)
	}
	if code := cmdAPIContractList([]string{"--catalog", catalogPath}); code != 0 {
		t.Fatalf("list code=%d", code)
	}
}

func TestAPIContractValidateRejectsModifiedLockedContract(t *testing.T) {
	root := t.TempDir()
	schemaPath := filepath.Join(root, "value.schema.json")
	initial := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Value","type":"string"}`)
	if err := os.WriteFile(schemaPath, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(root, "catalog.json")
	catalog := apicontract.Catalog{Version: apicontract.CatalogVersion, Name: "locked-api", Revision: "1.0.0", Contracts: []apicontract.Contract{{ID: "value", Version: "1.0.0", Kind: apicontract.KindJSONSchema, Path: "value.schema.json", Stability: apicontract.StabilityStable, Compatibility: apicontract.CompatibilityBackward}}}
	payload, _ := json.Marshal(catalog)
	if err := os.WriteFile(catalogPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "contracts.lock.json")
	if code := cmdAPIContractLock([]string{"--catalog", catalogPath, "--output", lockPath}); code != 0 {
		t.Fatalf("lock code=%d", code)
	}
	if err := os.WriteFile(schemaPath, []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Changed","type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdAPIContractValidate([]string{"--catalog", catalogPath, "--lock", lockPath}); code == 0 {
		t.Fatal("modified contract matched prior lock")
	}
}
