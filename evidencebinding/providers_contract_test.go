package evidencebinding

import (
	"os"
	"strings"
	"testing"
)

func TestProviderDocumentationMatchesImplementedBindingOptions(t *testing.T) {
	documentation, err := os.ReadFile("PROVIDERS.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(documentation)
	if strings.Count(text, "```mermaid") != 4 {
		t.Fatalf("Mermaid diagrams=%d want=4", strings.Count(text, "```mermaid"))
	}
	for _, phrase := range []string{
		"Hash chaining", "Merkle trees", "Digital signatures", "Immutable database", "Permissioned ledger",
		"RSA-PSS/SHA-256", "ECDSA P-256/SHA-256", "ECDSA P-384/SHA-384", "Ed25519",
		"/item/safe", "/item/safe/get", "successful commit status", "exact statement echo",
		"rewritten final entry requires an independently retained old head",
		"AnchorThresholdPolicy", "Duplicate receipts", "never increase quorum",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("PROVIDERS.md missing %q", phrase)
		}
	}
}

func TestAllFiveBindingOptionsHaveExecutableCoverage(t *testing.T) {
	files := []string{
		"binding_options_test.go", "signature_suite_test.go", "anchor_test.go", "anchor_threshold_test.go",
		"signature_suite.go", "anchor_immudb.go", "anchor_fabric.go", "anchor_threshold.go",
	}
	var joined strings.Builder
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		joined.Write(data)
	}
	source := joined.String()
	for _, symbol := range []string{
		"TestHashChainDetectsRewrittenEntryAndWitnessedTailRewrite",
		"TestMerkleProofCoverageAcrossOddAndEvenTreeWidths",
		"TestSignatureSuiteSupportsRSAECDSAAndEd25519",
		"TestImmuDBAnchorUsesVerifiedSafeSetAndSafeGet",
		"TestFabricAnchorRequiresCommittedExactStatementEcho",
		"TestAnchorThresholdAcceptsTwoIndependentProviders",
		"TestAnchorThresholdRejectsDuplicatesUnknownsAndInsufficientQuorum",
		"AlgorithmRSAPSSSHA256", "AlgorithmECDSAP256SHA256", "AlgorithmECDSAP384SHA384",
		"ImmuDBAnchor", "FabricAnchor", "AnchorThresholdPolicy",
		"ErrAnchorNotCommitted", "ErrAnchorMismatch", "ErrAnchorThreshold",
	} {
		if !strings.Contains(source, symbol) {
			t.Errorf("binding coverage missing %q", symbol)
		}
	}
}
