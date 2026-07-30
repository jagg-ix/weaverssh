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
    assert "payload[0] = 0" in source
    assert "payload[0] = 1" in source

    for symbol in (
        "NewLeaf",
        "VerifyPayload",
        "BuildMerkleRoot",
        "BuildMerkleProof",
        "VerifyMerkleProof",
        "NewStatement",
        "PreviousSHA256",
    ):
        assert symbol in source


def test_trusted_signatures_chain_and_witness_contracts() -> None:
    source = read("evidencebinding/nonrepudiation.go")

    for symbol in (
        "AlgorithmEd25519",
        "GenerateEd25519Signer",
        "KeyID",
        "SignStatement",
        "NewTrustPolicy",
        "ed25519.Verify",
        "VerifyLedger",
        "WitnessedHead",
        "NewWitness",
        "ErrEquivocation",
        "ErrHeadMismatch",
        "DecodeSignedStatement",
        "DisallowUnknownFields",
    ):
        assert symbol in source

    # The embedded key cannot authorize itself. Verification resolves the
    # statement key ID through configured trust, then requires exact key bytes.
    assert "trusted, ok := p.keys[signed.Statement.SignerKeyID]" in source
    assert "!bytes.Equal(trusted, encodedPublic)" in source


def test_adversarial_unit_suite_covers_denial_attempts() -> None:
    tests = read("evidencebinding/nonrepudiation_test.go")

    for test_name in (
        "TestNonRepudiationBindsPayloadMerkleRootAndSigner",
        "TestNonRepudiationRejectsPayloadAndStatementTampering",
        "TestNonRepudiationRejectsKeySubstitutionAndCrossStreamReplay",
        "TestNonRepudiationRejectsRemovalReorderingReplayAndWitnessedTruncation",
        "TestNonRepudiationWitnessDetectsSignerEquivocation",
        "TestNonRepudiationDetachedReceiptSurvivesLocalRecordDenial",
    ):
        assert f"func {test_name}" in tests

    for failure in (
        "ErrInvalidSignature",
        "ErrInvalidProof",
        "ErrUntrustedSigner",
        "ErrWrongStream",
        "ErrBrokenChain",
        "ErrHeadMismatch",
        "ErrEquivocation",
    ):
        assert failure in tests


def test_mermaid_algorithms_and_security_boundary_are_documented() -> None:
    documentation = read("evidencebinding/README.md")

    assert documentation.count("```mermaid") == 9
    for heading in (
        "## 1. Evidence commitment",
        "## 2. Merkle-root construction",
        "## 3. Merkle inclusion proof",
        "## 4. Signed checkpoint creation",
        "## 5. Trusted signature verification",
        "## 6. Append-only ledger verification",
        "## 7. Independently witnessed head",
        "## 8. Equivocation detection",
        "## 9. Detached receipt verification",
    ):
        assert heading in documentation

    lowered = documentation.lower()
    for phrase in (
        "authentic prefix",
        "completeness not bound",
        "independently retained witnessed head",
        "key-substitution attempt detected",
        "truncation detected",
        "does not make ordinary local storage physically immutable",
    ):
        assert phrase in lowered


def test_build_targets_and_package_documentation_remain_connected() -> None:
    targets = read("mk/evidence-binding.mk")
    package_doc = read("evidencebinding/doc.go")
    readme_contract = read("evidencebinding/readme_contract_test.go")

    assert "go test -count=1 ./evidencebinding" in targets
    assert "go test -race -count=1 ./evidencebinding" in targets
    assert "tests/test_evidence_binding.py" in targets
    assert "independently retained witnessed head" in package_doc
    assert 'strings.Count(documentation, "```mermaid")' in readme_contract


def test_private_research_terms_are_absent() -> None:
    paths = (
        "evidencebinding/nonrepudiation.go",
        "evidencebinding/nonrepudiation_test.go",
        "evidencebinding/readme_contract_test.go",
        "evidencebinding/doc.go",
        "evidencebinding/README.md",
    )
    joined = "\n".join(read(path).lower() for path in paths)
    assert "gartner" not in joined
    assert "managed file transfer" not in joined
