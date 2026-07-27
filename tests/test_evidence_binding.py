from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_merkle_and_statement_chain_contracts() -> None:
    merkle = read("evidencebinding/merkle.go")
    manager = read("evidencebinding/manager_seal.go")
    assert "hashLeaf" in merkle and "payload[0] = 0" in merkle
    assert "hashNode" in merkle and "payload[0] = 1" in merkle
    assert "BuildMerkleProof" in merkle
    assert "VerifyMerkleProof" in merkle
    assert "PreviousSHA256" in manager
    assert "pending checkpoint does not match monotonic metadata" in manager


def test_signature_algorithms_and_private_key_boundaries() -> None:
    signer = read("evidencebinding/signer.go")
    trust = read("evidencebinding/signer_trust.go")
    for algorithm in (
        "rsa-pss-sha256",
        "ecdsa-p256-sha256",
        "ecdsa-p384-sha384",
        "ed25519",
    ):
        assert algorithm in signer
    assert "AgentMessageSigner" in signer
    assert "must not be accessible by group or others" in signer
    assert "VerifySignature" in signer
    assert "public key does not match configured trust anchor" in trust


def test_anchor_providers_bind_exact_statement() -> None:
    core = read("evidencebinding/anchor.go")
    immu = read("evidencebinding/anchor_immugw.go")
    bridge = read("evidencebinding/anchor_bridge.go")
    assert 'case "immugw"' in core
    assert 'case "fabric"' in core
    assert 'case "http"' in core
    assert "/v1/immurestproxy/item/safe" in immu
    assert "/v1/immurestproxy/item/safe/get" in immu
    assert "requireStatementEcho" in bridge
    assert "idempotency_key" in bridge
    assert "channel" in bridge and "chaincode" in bridge and "function" in bridge


def test_append_only_state_and_anchor_threshold() -> None:
    manager = read("evidencebinding/manager.go")
    seal = read("evidencebinding/manager_seal.go")
    helpers = read("evidencebinding/manager_helpers.go")
    assert "CompareAndSwap" in manager
    assert "validateAnchorThreshold" in seal
    assert "verifyConfiguredSignatures" in seal
    for prefix in ("leaves/", "digests/", "statements/", "signatures/", "anchors/", "complete/"):
        assert prefix in helpers


def test_cli_examples_and_go123_gate() -> None:
    main = read("cmd/wv/main.go")
    command = read("cmd/wv/evidence.go")
    catalog = read("cmd/wv/command_catalog_complete.go")
    makefile = read("GNUmakefile")
    targets = read("mk/evidence-binding.mk")
    gate = read("tools/verification/build_go123.sh")
    assert 'case "evidence", "notary": os.Exit(cmdEvidence(rest))' in main
    assert '"evidence"' in catalog and '"notary"' in catalog
    for subcommand in ("validate", "append", "status", "verify", "proof", "proof-verify", "ingest-audit"):
        assert f'case "{subcommand}"' in command
    assert 'case "flush", "seal"' in command
    assert "include mk/evidence-binding.mk" in makefile
    assert "evidence-binding-focused-test:" in targets
    assert "evidence-binding-race-test:" in targets
    assert "test-evidence-binding-static:" in targets
    assert "./evidencebinding" in gate
    for name in ("local.json", "immugw.json", "fabric.json"):
        document = json.loads(read(f"docs/examples/evidence-binding/{name}"))
        assert document["version"] == "weaverssh.evidence-binding.v1"


def test_documentation_states_trust_boundaries() -> None:
    documentation = read("docs/architecture/cryptographic-evidence-binding.md").lower()
    for phrase in (
        "does not copy file contents",
        "domain-separated",
        "is not itself an immutable database",
        "does not import a fabric sdk",
        "does not make an ordinary filesystem or database physically immutable",
        "non-repudiation",
        "private keys",
    ):
        assert phrase in documentation


def test_private_research_terms_are_absent() -> None:
    paths = [
        "evidencebinding/config.go",
        "evidencebinding/merkle.go",
        "evidencebinding/signer.go",
        "evidencebinding/anchor.go",
        "evidencebinding/anchor_immugw.go",
        "evidencebinding/anchor_bridge.go",
        "evidencebinding/manager.go",
        "evidencebinding/manager_seal.go",
        "evidencebinding/manager_read.go",
        "cmd/wv/evidence.go",
        "docs/architecture/cryptographic-evidence-binding.md",
    ]
    joined = "\n".join(read(path).lower() for path in paths)
    assert "gartner" not in joined
    assert "managed file transfer" not in joined
