package evidencebinding

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAnchorProviderConfigBuildsIndependentInstances(t *testing.T) {
	config, err := DecodeAnchorProviderConfigBytes([]byte(`{
		"version":"weaverssh.evidence-provider-config.v1",
		"threshold":2,
		"providers":[
			{"name":"immudb-primary","type":"immudb","base_url":"https://immu-a.example","token_env":"IMMU_A_TOKEN"},
			{"name":"immudb-witness","type":"immudb","base_url":"https://immu-b.example","token":"inline-test-token"},
			{"name":"fabric-consortium","type":"fabric","base_url":"https://fabric.example","channel":"audit","chaincode":"evidence"}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	providers, _, err := config.Build(nil, func(name string) string {
		if name == "IMMU_A_TOKEN" {
			return "secret-a"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 3 {
		t.Fatalf("providers=%d", len(providers))
	}
	for index, want := range []string{"immudb-primary", "immudb-witness", "fabric-consortium"} {
		if providers[index].Name() != want {
			t.Fatalf("provider %d name=%q want=%q", index, providers[index].Name(), want)
		}
	}
}

func TestAnchorProviderConfigRejectsMissingSecretAndUnknownFields(t *testing.T) {
	config := AnchorProviderConfigFile{
		Version: AnchorProviderConfigVersion,
		Providers: []AnchorProviderConfig{{Name: "immu", Type: "immudb", BaseURL: "https://immu", TokenEnv: "MISSING_TOKEN"}},
	}
	if _, _, err := config.Build(nil, func(string) string { return "" }); err == nil {
		t.Fatal("missing token environment was accepted")
	}
	_, err := DecodeAnchorProviderConfigBytes([]byte(`{"version":"weaverssh.evidence-provider-config.v1","providers":[],"unexpected":true}`))
	if err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

func TestNamedAnchorProviderBindsAlias(t *testing.T) {
	head := Head{StreamID: "audit", Sequence: 1, StatementSHA256: strings.Repeat("a", 64)}
	inner := &configFakeProvider{name: "immudb"}
	provider := NamedAnchorProvider{ProviderName: "immudb-independent-a", Inner: inner}
	receipt, err := provider.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Provider != "immudb-independent-a" {
		t.Fatalf("provider=%s", receipt.Provider)
	}
	if err := provider.Verify(context.Background(), head, receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Provider = "immudb-independent-b"
	if err := provider.Verify(context.Background(), head, receipt); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("alias replay error=%v", err)
	}
}

type configFakeProvider struct{ name string }

func (p *configFakeProvider) Name() string { return p.name }
func (p *configFakeProvider) Anchor(_ context.Context, head Head) (AnchorReceipt, error) {
	statement, err := NewAnchorStatement(head)
	if err != nil {
		return AnchorReceipt{}, err
	}
	return AnchorReceipt{Version: AnchorVersion, Provider: p.name, Statement: statement, ExternalID: "record", ProofSHA256: strings.Repeat("b", 64), Committed: true}, nil
}
func (p *configFakeProvider) Verify(_ context.Context, head Head, receipt AnchorReceipt) error {
	return receipt.ValidateFor(p.name, head)
}
