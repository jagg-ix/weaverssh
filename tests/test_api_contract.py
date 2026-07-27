from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_catalog_and_standard_descriptions() -> None:
    catalog = json.loads(read("api/contracts/catalog.json"))
    assert catalog["version"] == "weaverssh.api-contract-catalog.v1"
    kinds = {entry["kind"] for entry in catalog["contracts"]}
    assert {"openapi", "openrpc", "asyncapi", "json-schema", "protobuf"} <= kinds

    openapi = json.loads(read("api/openapi/control-gateway.v1.json"))
    openrpc = json.loads(read("api/openrpc/session-api.v1.json"))
    asyncapi = json.loads(read("api/asyncapi/transfer-events.v1.json"))
    schema = json.loads(read("api/schema/transfer-event.v1.schema.json"))
    assert openapi["openapi"].startswith("3.")
    assert openrpc["openrpc"].startswith("1.")
    assert asyncapi["asyncapi"].startswith("3.")
    assert schema["$schema"].startswith("https://json-schema.org/draft/2020-12/")
    assert "api.contracts" in {method["name"] for method in openrpc["methods"]}
    assert "api.contract.get" in {method["name"] for method in openrpc["methods"]}
    assert 'syntax = "proto3";' in read("api/proto/control/v1/control.proto")


def test_registry_compatibility_provider_and_generators() -> None:
    model = read("apicontract/model.go")
    registry = read("apicontract/registry.go")
    compatibility = read("apicontract/compatibility.go")
    provider = read("apicontract/provider.go")
    generate = read("apicontract/generate.go")
    validators = read("apicontract/validators.go")

    for version in (
        "weaverssh.api-contract-catalog.v1",
        "weaverssh.api-contract-lock.v1",
    ):
        assert version in model
    for kind in ("openapi", "openrpc", "asyncapi", "json-schema", "protobuf", "protobuf-descriptor"):
        assert f'"{kind}"' in model
    assert "func (registry *Registry) ValidateCatalog" in registry
    assert "func CompareLocks" in compatibility
    assert "func OpenFileProvider" in provider
    assert "contract bytes changed after provider initialization" in provider
    assert "type Generator interface" in generate
    assert "generated path escapes output directory" in generate
    assert "edition 2023/2024" in validators


def test_cli_and_session_api_discovery() -> None:
    command = read("cmd/wv/api_contract.go")
    main = read("cmd/wv/main.go")
    protocol = read("sessionapi/protocol.go")
    server = read("sessionapi/server.go")
    client = read("cmd/wv/session_api.go")

    for operation in ("validate", "lock", "compare", "list"):
        assert f'case "{operation}"' in command
    assert 'case "api-contract", "contracts"' in main
    assert 'MethodContractsList = "api.contracts"' in protocol
    assert 'MethodContractGet   = "api.contract.get"' in protocol
    assert "MaxContractPayloadBytes" in protocol
    assert "handleContracts" in server
    assert "base64.StdEncoding.EncodeToString" in server
    assert 'case "contracts"' in client
    assert 'case "contract"' in client


def test_tests_docs_and_build_registration() -> None:
    tests = "\n".join(
        read(path)
        for path in (
            "apicontract/apicontract_test.go",
            "cmd/wv/api_contract_test.go",
            "sessionapi/contracts_test.go",
        )
    )
    for name in (
        "TestRegistryBuildsPortableLock",
        "TestCompareLocksEnforcesBackwardCompatibilityAndSemanticVersions",
        "TestFileProviderDetectsContractReplacement",
        "TestGenerationRegistryConfinesOutput",
        "TestAPIContractLockValidateAndCompare",
        "TestSessionAPIAdvertisesAndServesContracts",
    ):
        assert name in tests

    make = read("mk/api-contract.mk")
    gnu = read("GNUmakefile")
    go123 = read("tools/verification/build_go123.sh")
    assert "api-contract-focused-test" in make
    assert "api-contract-validate" in make
    assert "include mk/api-contract.mk" in gnu
    assert "./apicontract ./sessionapi" in go123
    assert (ROOT / "docs/architecture/api-contract-framework.md").exists()
