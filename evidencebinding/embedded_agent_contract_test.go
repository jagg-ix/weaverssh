package evidencebinding

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedAgentEvidenceArtifactsRemainConnected(t *testing.T) {
	files := map[string][]string{
		"anchor_embedded_immudb.go": {
			"github.com/codenotary/immudb/embedded/store",
			"OpenEmbeddedImmuDBAnchor",
			"store.ReadWriteTx",
			"valueRef.Tx()",
			"valueRef.HC()",
			"embeddedImmuDBProofDomain",
		},
		"../internal/app/agent_embedded_immudb.go": {
			"AgentRuntimeWithEmbeddedImmuDB",
			"NewAgentRuntimeWithEmbeddedImmuDB",
			"WEAVERSSH_AGENT_IMMUDB_PATH",
			"AnchorEvidenceHead",
			"VerifyEvidenceReceipt",
		},
		"provider_config.go": {
			"EmbeddedImmuDBProviderName",
			"CloseAnchorProviders",
			"provider.Path",
		},
		"../docs/architecture/agent-embedded-immudb.md": {
			"```mermaid",
			"not an independent witness",
			"Business Source License 1.1",
			"AgentRuntimeWithEmbeddedImmuDB",
		},
		"../docs/examples/evidence-binding/providers.embedded.json": {
			"embedded-immudb",
			"independent-immudb",
			"WEAVERSSH_IMMUGW_TOKEN",
		},
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

func TestEmbeddedAgentDocumentationHasTwoMermaidViews(t *testing.T) {
	data, err := os.ReadFile("../docs/architecture/agent-embedded-immudb.md")
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(data), "```mermaid"); count != 2 {
		t.Fatalf("embedded agent Mermaid diagrams=%d want=2", count)
	}
}
