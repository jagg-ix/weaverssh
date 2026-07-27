package apicontract

import (
	"context"
	"testing"
)

func TestCompatibilityRegistryDispatchesByKindAndName(t *testing.T) {
	registry := NewCompatibilityRegistry()
	if err := registry.Register(CompatibilityCheckerFunc{
		CheckerName: "strict",
		ContractKind: KindJSONSchema,
		CompareFunc: func(_ context.Context, previous, current Revision) (DeepCompatibilityResult, error) {
			return DeepCompatibilityResult{Compatible: string(previous.Payload) == string(current.Payload), Reasons: []string{"payloads must match"}}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	previous := Revision{Contract: Contract{Kind: KindJSONSchema}, Payload: []byte("a")}
	current := Revision{Contract: Contract{Kind: KindJSONSchema}, Payload: []byte("b")}
	result, err := registry.Compare(context.Background(), "strict", previous, current)
	if err != nil {
		t.Fatal(err)
	}
	if result.Compatible || len(result.Reasons) != 1 {
		t.Fatalf("result=%+v", result)
	}
}
