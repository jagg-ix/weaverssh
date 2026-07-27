package sessionapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"weaverssh/apicontract"
)

type contractProviderStub struct {
	payload []byte
}

func (provider contractProviderStub) Catalog(context.Context) (apicontract.Catalog, error) {
	return apicontract.Catalog{Version: apicontract.CatalogVersion, Name: "test-api", Revision: "1.0.0", Contracts: []apicontract.Contract{{ID: "session", Version: "1.0.0", Kind: apicontract.KindOpenRPC, Path: "session.json", Stability: apicontract.StabilityStable, Compatibility: apicontract.CompatibilityBackward}}}, nil
}
func (provider contractProviderStub) Lock(context.Context) (apicontract.Lock, error) {
	return apicontract.Lock{Version: apicontract.LockVersion, CatalogName: "test-api", Revision: "1.0.0", CatalogSHA256: strings.Repeat("a", 64), Contracts: []apicontract.LockedEntry{{ID: "session", Version: "1.0.0", Kind: apicontract.KindOpenRPC, Path: "session.json", Stability: apicontract.StabilityStable, Compatibility: apicontract.CompatibilityBackward, SHA256: strings.Repeat("b", 64), Symbols: []string{"method:session.describe"}}}}, nil
}
func (provider contractProviderStub) List(ctx context.Context) ([]apicontract.LockedEntry, error) {
	lock, _ := provider.Lock(ctx)
	return lock.Contracts, nil
}
func (provider contractProviderStub) Read(ctx context.Context, id, version string) ([]byte, apicontract.LockedEntry, error) {
	lock, _ := provider.Lock(ctx)
	return append([]byte(nil), provider.payload...), lock.Contracts[0], nil
}

func TestSessionAPIAdvertisesAndServesContracts(t *testing.T) {
	server := &Server{Snapshot: func(context.Context) (Snapshot, error) { return Snapshot{CurrentNode: "a", CurrentIndex: 0, Topology: []string{"a"}}, nil }, Contracts: contractProviderStub{payload: []byte(`{"openrpc":"1.4.0","info":{"title":"x","version":"1"},"methods":[]}`)}}
	capabilities, err := server.handle(context.Background(), Request{Protocol: ProtocolVersion, ID: "1", Method: MethodCapabilities})
	if err != nil {
		t.Fatal(err)
	}
	methods := capabilities.(Capabilities).Methods
	if !hasString(methods, MethodContractsList) || !hasString(methods, MethodContractGet) {
		t.Fatalf("methods=%v", methods)
	}
	params, _ := json.Marshal(ContractListParams{Limit: 1})
	listed, err := server.handle(context.Background(), Request{Protocol: ProtocolVersion, ID: "2", Method: MethodContractsList, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	result := listed.(ContractListResult)
	if result.Total != 1 || len(result.Contracts) != 1 || result.Contracts[0].ID != "session" {
		t.Fatalf("result=%+v", result)
	}
	params, _ = json.Marshal(ContractGetParams{ID: "session"})
	got, err := server.handle(context.Background(), Request{Protocol: ProtocolVersion, ID: "3", Method: MethodContractGet, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	document := got.(ContractDocument)
	if document.Encoding != "utf-8" || !strings.Contains(document.Data, `"openrpc"`) {
		t.Fatalf("document=%+v", document)
	}
}

func TestSessionAPIRejectsOversizedContract(t *testing.T) {
	server := &Server{Snapshot: func(context.Context) (Snapshot, error) { return Snapshot{}, nil }, Contracts: contractProviderStub{payload: []byte(strings.Repeat("x", MaxContractPayloadBytes+1))}}
	params, _ := json.Marshal(ContractGetParams{ID: "session"})
	_, err := server.handle(context.Background(), Request{Protocol: ProtocolVersion, ID: "1", Method: MethodContractGet, Params: params})
	if err == nil || !strings.Contains(err.Error(), ErrContractTooLarge.Error()) {
		t.Fatalf("err=%v", err)
	}
}

func hasString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
