package evidencebinding

import (
	"os"
	"strings"
	"testing"
)

func TestAlgorithmDocumentationTracksImplementedSecurityBoundary(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read algorithm documentation: %v", err)
	}
	documentation := string(data)

	if got := strings.Count(documentation, "```mermaid"); got != 9 {
		t.Fatalf("expected 9 Mermaid algorithm diagrams, got %d", got)
	}

	required := []string{
		"## 1. Evidence commitment",
		"## 2. Merkle-root construction",
		"## 3. Merkle inclusion proof",
		"## 4. Signed checkpoint creation",
		"## 5. Trusted signature verification",
		"## 6. Append-only ledger verification",
		"## 7. Independently witnessed head",
		"## 8. Equivocation detection",
		"## 9. Detached receipt verification",
		"NewLeaf",
		"VerifyPayload",
		"BuildMerkleRoot",
		"BuildMerkleProof",
		"VerifyMerkleProof",
		"NewStatement",
		"SignStatement",
		"TrustPolicy.Verify",
		"VerifyLedger",
		"Witness.Observe",
		"DecodeSignedStatement",
		"Authentic prefix verified",
		"Completeness not bound",
		"independently retained witnessed head",
		"does not make ordinary local storage physically immutable",
	}
	for _, text := range required {
		if !strings.Contains(documentation, text) {
			t.Errorf("algorithm documentation is missing %q", text)
		}
	}
}

func TestMermaidDocumentationUsesBalancedFences(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read algorithm documentation: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	insideMermaid := false
	blocks := 0
	for lineNumber, line := range lines {
		switch strings.TrimSpace(line) {
		case "```mermaid":
			if insideMermaid {
				t.Fatalf("nested Mermaid fence at line %d", lineNumber+1)
			}
			insideMermaid = true
			blocks++
		case "```":
			if insideMermaid {
				insideMermaid = false
			}
		}
	}
	if insideMermaid {
		t.Fatal("unterminated Mermaid block")
	}
	if blocks != 9 {
		t.Fatalf("expected 9 balanced Mermaid blocks, got %d", blocks)
	}
}
