package evidencebinding

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProviderIntegrationArtifactsRemainConnected(t *testing.T) {
	files := map[string][]string{
		"provider_config.go": {"AnchorProviderConfigVersion", "NamedAnchorProvider", "NewAnchorThresholdPolicy"},
		"../fabricbridge/server.go": {"--waitForEvent", "ReadEvidenceAnchor", "peer channel getinfo", "Authorization"},
		"../cmd/wv-evidence-anchor/main.go": {"anchor", "verify", "LoadAnchorProviderConfig"},
		"../cmd/wv-fabric-anchor-bridge/main.go": {"wv-fabric-anchor-bridge", "query-function"},
		"../deploy/fabric/evidence-chaincode/contract.go": {"AnchorEvidence", "ReadEvidenceAnchor", "GetTxID", "idempotency key already binds a different statement"},
		"../scripts/evidence/immudb-live-test.sh": {"immurestproxy/login", "TestLiveImmuDBAnchor"},
		"../scripts/evidence/fabric-live-test.sh": {"install-fabric.sh", "deployCC", "--wait-for-event", "TestLiveFabricAnchor"},
		"../.github/workflows/evidence-providers-live.yml": {"workflow_dispatch", "evidence-binding-immudb-live-test", "evidence-binding-fabric-live-test"},
	}
	for path, required := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		text := string(data)
		for _, phrase := range required {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s missing %q", path, phrase)
			}
		}
	}
}

func TestProviderConfigurationExampleIsValid(t *testing.T) {
	data, err := os.ReadFile("../docs/examples/evidence-binding/providers.local.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeAnchorProviderConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if config.Threshold != 2 || len(config.Providers) != 2 {
		t.Fatalf("config=%+v", config)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
}

func TestProviderOperationsDocumentationStatesProductionBoundary(t *testing.T) {
	data, err := os.ReadFile("../docs/architecture/evidence-provider-operations.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, phrase := range []string{
		"```mermaid", "independent name", "strictly decodes", "waitforevent",
		"not production deployment manifests", "independent immudb auditor state", "restricted fabric msp identities",
	} {
		if !strings.Contains(text, strings.ToLower(phrase)) {
			t.Errorf("operations documentation missing %q", phrase)
		}
	}
}
