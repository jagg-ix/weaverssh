from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_domain_separated_merkle_and_statement_contracts() -> None:
    source = read("evidencebinding/nonrepudiation.go")
    assert 'leafDomain      = "weaverssh:evidence:leaf:v1\\x00"' in source
    assert 'nodeDomain      = "weaverssh:evidence:node:v1\\x00"' in source
    assert 'statementDomain = "weaverssh:evidence:statement:v1\\x00"' in source
    assert "payload[0] = 0" in source and "payload[0] = 1" in source
    for symbol in ("NewLeaf", "VerifyPayload", "BuildMerkleRoot", "BuildMerkleProof", "VerifyMerkleProof", "NewStatement", "PreviousSHA256"):
        assert symbol in source


def test_trusted_signatures_chain_and_witness_contracts() -> None:
    source = read("evidencebinding/nonrepudiation.go")
    for symbol in (
        "AlgorithmEd25519", "GenerateEd25519Signer", "KeyID", "SignStatement",
        "NewTrustPolicy", "ed25519.Verify", "VerifyLedger", "WitnessedHead",
        "NewWitness", "ErrEquivocation", "ErrHeadMismatch", "DecodeSignedStatement",
        "DisallowUnknownFields",
    ):
        assert symbol in source
    assert "trusted, ok := p.keys[signed.Statement.SignerKeyID]" in source
    assert "!bytes.Equal(trusted, encodedPublic)" in source


def test_multi_algorithm_signature_contracts() -> None:
    source = read("evidencebinding/signature_suite.go")
    tests = read("evidencebinding/signature_suite_test.go")
    for algorithm in ("rsa-pss-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384", "ed25519"):
        assert algorithm in source
    for symbol in (
        "SignatureTrustPolicy", "NewTrustedSigner", "GenerateRSAPSSSigner",
        "GenerateECDSASigner", "SignStatementWithKey", "VerifyLedgerWithSignaturePolicy",
        "rsa.SignPSS", "rsa.VerifyPSS", "ecdsa.SignASN1", "ecdsa.VerifyASN1",
        "ErrWeakSignatureKey", "ErrSignatureAlgorithmMismatch",
    ):
        assert symbol in source
    for test_name in (
        "TestSignatureSuiteSupportsRSAECDSAAndEd25519",
        "TestSignatureSuiteRejectsMutationSubstitutionAndAlgorithmConfusion",
        "TestSignatureSuiteRejectsWeakRSAAndWrongECDSACurve",
    ):
        assert f"func {test_name}" in tests


def test_adversarial_chain_and_merkle_coverage() -> None:
    tests = read("evidencebinding/binding_options_test.go")
    for test_name in (
        "TestHashChainDetectsRewrittenEntryAndWitnessedTailRewrite",
        "TestMerkleProofCoverageAcrossOddAndEvenTreeWidths",
        "TestMerkleRootCommitsLeafOrderWhileSortedInputIsDeterministic",
    ):
        assert f"func {test_name}" in tests
    assert "count <= 17" in tests
    assert "WitnessedHead: &original.Head" in tests


def test_external_anchor_provider_contracts() -> None:
    core = read("evidencebinding/anchor.go")
    immudb = read("evidencebinding/anchor_immudb.go")
    fabric = read("evidencebinding/anchor_fabric.go")
    tests = read("evidencebinding/anchor_test.go")
    threshold = read("evidencebinding/anchor_threshold.go")
    threshold_tests = read("evidencebinding/anchor_threshold_test.go")
    for symbol in ("AnchorStatement", "AnchorReceipt", "AnchorProvider", "ErrAnchorMismatch", "ErrAnchorNotCommitted"):
        assert symbol in core
    assert "/v1/immurestproxy/item/safe" in immudb
    assert "/v1/immurestproxy/item/safe/get" in immudb
    assert "Idempotency-Key" in immudb
    assert "bytes.Equal(decoded, expected)" in immudb
    for field in ("Channel", "Chaincode", "Contract", "IdempotencyKey", "BlockNumber", "Successful"):
        assert field in fabric
    assert "/v1/fabric/submit" in fabric and "/v1/fabric/evaluate" in fabric
    assert "response.Statement != statement" in fabric
    for test_name in (
        "TestImmuDBAnchorUsesVerifiedSafeSetAndSafeGet",
        "TestImmuDBAnchorRejectsSubstitutedVerifiedValue",
        "TestFabricAnchorRequiresCommittedExactStatementEcho",
        "TestFabricAnchorRejectsFailedCommitAndChangedEcho",
        "TestAnchorReceiptCannotBeReplayedAcrossProviderOrHead",
    ):
        assert f"func {test_name}" in tests
    for symbol in ("AnchorThresholdPolicy", "AnchorThresholdReport", "ErrAnchorThreshold", "duplicate provider receipt"):
        assert symbol in threshold
    for test_name in (
        "TestAnchorThresholdAcceptsTwoIndependentProviders",
        "TestAnchorThresholdRejectsDuplicatesUnknownsAndInsufficientQuorum",
        "TestAnchorThresholdConfigurationRejectsImpossibleOrDuplicatePolicy",
    ):
        assert f"func {test_name}" in threshold_tests


def test_mermaid_algorithms_and_security_boundaries_are_documented() -> None:
    core_documentation = read("evidencebinding/README.md")
    providers = read("evidencebinding/PROVIDERS.md")
    assert core_documentation.count("```mermaid") == 9
    assert providers.count("```mermaid") == 4
    for phrase in (
        "Hash chaining", "Merkle trees", "Digital signatures", "Immutable database",
        "Permissioned ledger", "RSA-PSS/SHA-256", "ECDSA P-256/SHA-256",
        "ECDSA P-384/SHA-384", "verified safe set/get", "successful commit status",
        "rewritten final entry requires an independently retained old head",
        "AnchorThresholdPolicy", "never increase quorum",
    ):
        assert phrase in providers
    lowered = core_documentation.lower()
    for phrase in (
        "authentic prefix", "completeness not bound", "independently retained witnessed head",
        "key-substitution attempt detected", "truncation detected",
        "does not make ordinary local storage physically immutable",
    ):
        assert phrase in lowered


def test_build_targets_and_package_documentation_remain_connected() -> None:
    targets = read("mk/evidence-binding.mk")
    package_doc = read("evidencebinding/doc.go")
    readme_contract = read("evidencebinding/readme_contract_test.go")
    provider_contract = read("evidencebinding/providers_contract_test.go")
    assert "go test -count=1 ./evidencebinding" in targets
    assert "go test -race -count=1 ./evidencebinding" in targets
    assert "python3 tests/test_evidence_binding.py" in targets
    assert "independently retained witnessed head" in package_doc
    assert 'strings.Count(documentation, "```mermaid")' in readme_contract
    assert "TestAllFiveBindingOptionsHaveExecutableCoverage" in provider_contract


def test_private_research_terms_are_absent() -> None:
    paths = (
        "evidencebinding/nonrepudiation.go", "evidencebinding/nonrepudiation_test.go",
        "evidencebinding/binding_options_test.go", "evidencebinding/signature_suite.go",
        "evidencebinding/signature_suite_test.go", "evidencebinding/anchor.go",
        "evidencebinding/anchor_immudb.go", "evidencebinding/anchor_fabric.go",
        "evidencebinding/anchor_test.go", "evidencebinding/anchor_threshold.go",
        "evidencebinding/anchor_threshold_test.go", "evidencebinding/readme_contract_test.go",
        "evidencebinding/providers_contract_test.go", "evidencebinding/doc.go",
        "evidencebinding/README.md", "evidencebinding/PROVIDERS.md",
    )
    joined = "\n".join(read(path).lower() for path in paths)
    assert "gartner" not in joined
    assert "managed file transfer" not in joined


def main() -> None:
    checks = (
        test_domain_separated_merkle_and_statement_contracts,
        test_trusted_signatures_chain_and_witness_contracts,
        test_multi_algorithm_signature_contracts,
        test_adversarial_chain_and_merkle_coverage,
        test_external_anchor_provider_contracts,
        test_mermaid_algorithms_and_security_boundaries_are_documented,
        test_build_targets_and_package_documentation_remain_connected,
        test_private_research_terms_are_absent,
    )
    for check in checks:
        check()
    print(f"evidence-binding static contract: {len(checks)} checks passed")


if __name__ == "__main__":
    main()
