from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_crypto_crosslayer_reverse as reverse_verifier


def _contract_path() -> Path:
    return REPO_ROOT / "verification" / "tla" / "SSHX11CryptoCrossLayerContract.tla"


def _loaded_contract() -> dict:
    return reverse_verifier.load_contract(_contract_path())


def test_load_contract_missing_definition_raises(tmp_path: Path) -> None:
    text = _contract_path().read_text(encoding="utf-8")
    text = text.replace('FinalGoalNode == "N39"', "")
    bad = tmp_path / "bad_contract.tla"
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="missing TLA definition: FinalGoalNode"):
        reverse_verifier.load_contract(bad)


def test_parse_nodes_invalid_shape_raises() -> None:
    with pytest.raises(ValueError, match="invalid InteractionNodes tuple shape"):
        reverse_verifier._parse_nodes('{ <<"N01", "sshTransport", "sshClient">> }')


def test_parse_nodes_duplicate_id_raises() -> None:
    defn = (
        '{ <<"N01", "layerA", "actorA", "eventA", "allowed">>, '
        '<<"N01", "layerB", "actorB", "eventB", "allowed">> }'
    )
    with pytest.raises(ValueError, match="duplicate node id: N01"):
        reverse_verifier._parse_nodes(defn)


def test_validate_forward_path_reports_missing_edges() -> None:
    edges = {("A", "B")}
    path = ["A", "B", "C"]
    out = reverse_verifier._validate_forward_path(edges, path)
    assert out["ok"] is False
    assert out["missing_edges"] == [("B", "C")]


def test_validate_reverse_path_goal_mismatch_and_not_exact_reverse() -> None:
    edges = {("A", "B"), ("B", "C")}
    happy = ["A", "B", "C"]
    reverse = ["B", "A", "C"]
    out = reverse_verifier._validate_reverse_path(edges, happy, reverse, final_goal="C")
    assert out["ok"] is False
    assert any("reverse first node must be final goal" in issue for issue in out["issues"])
    assert any("not exact reverse" in issue for issue in out["issues"])


def test_validate_reverse_path_missing_prerequisite_edges() -> None:
    edges = {("A", "B")}
    happy = ["A", "B", "C"]
    reverse = ["C", "B", "A"]
    out = reverse_verifier._validate_reverse_path(edges, happy, reverse, final_goal="C")
    assert out["ok"] is False
    assert ("B", "C") in out["missing_prerequisite_edges"]


def test_validate_layer_coverage_missing_layers() -> None:
    nodes = {
        "A": reverse_verifier.InteractionNode("A", "sshTransport", "sshClient", "start", "allowed"),
        "B": reverse_verifier.InteractionNode("B", "x11Auth", "sshClient", "requestX11ForwardX", "allowed"),
    }
    out = reverse_verifier._validate_layer_coverage(
        nodes=nodes,
        required_layers={"sshTransport", "x11Auth", "relay"},
        happy_path=["A", "B"],
    )
    assert out["ok"] is False
    assert out["missing_layers"] == ["relay"]


def test_validate_obligations_detects_order_failures() -> None:
    obligations = [("A", "B", "A before B")]
    happy = ["B", "A"]
    reverse = ["A", "B"]
    out = reverse_verifier._validate_obligations(obligations, happy, reverse)
    assert out["ok"] is False
    assert out["checks"][0]["forward_order_ok"] is False
    assert out["checks"][0]["reverse_order_ok"] is False


def test_validate_y_rejection_terminal_must_be_blocked() -> None:
    nodes = {
        "Y01": reverse_verifier.InteractionNode("Y01", "x11Auth", "sshClient", "requestX11ForwardY", "allowed"),
        "Y02": reverse_verifier.InteractionNode("Y02", "x11Auth", "sshClient", "openX11Channel", "allowed"),
    }
    out = reverse_verifier._validate_y_rejection(nodes=nodes, y_path=["Y01", "Y02"])
    assert out["ok"] is False
    assert out["has_y_request"] is True
    assert out["terminal_blocked"] is False


def test_build_interaction_payload_schema() -> None:
    contract = _loaded_contract()
    payload = reverse_verifier.build_interaction_payload(contract)
    assert {"contract", "forward_interactions", "reverse_goal_walk", "trusted_forwarding_rejection_path", "cross_layer_obligations"} <= set(payload.keys())
    assert payload["contract"]["final_goal"] == "N39"
    assert len(payload["forward_interactions"]) == payload["contract"]["happy_path_length"]
    assert len(payload["reverse_goal_walk"]) == payload["contract"]["reverse_path_length"]


def test_markdown_render_contains_required_sections() -> None:
    contract = _loaded_contract()
    interactions = reverse_verifier.build_interaction_payload(contract)
    validation = reverse_verifier.run_validation(contract, crosscheck_runtime=False, repo_root=REPO_ROOT)
    md = reverse_verifier._to_markdown(interactions, validation)
    assert "## Forward Interaction Path" in md
    assert "## Reverse Goal Walk (End -> Start)" in md
    assert "## Coverage + Obligation Checks" in md


def test_write_outputs_is_deterministic(tmp_path: Path) -> None:
    contract = _loaded_contract()
    interactions = reverse_verifier.build_interaction_payload(contract)
    validation = reverse_verifier.run_validation(contract, crosscheck_runtime=False, repo_root=REPO_ROOT)
    out_json = tmp_path / "validation.json"
    out_md = tmp_path / "validation.md"
    map_json = tmp_path / "map.json"
    map_md = tmp_path / "map.md"

    reverse_verifier.write_outputs(validation, interactions, out_json, out_md, map_json, map_md)
    first = (out_json.read_text(encoding="utf-8"), out_md.read_text(encoding="utf-8"), map_json.read_text(encoding="utf-8"), map_md.read_text(encoding="utf-8"))
    reverse_verifier.write_outputs(validation, interactions, out_json, out_md, map_json, map_md)
    second = (out_json.read_text(encoding="utf-8"), out_md.read_text(encoding="utf-8"), map_json.read_text(encoding="utf-8"), map_md.read_text(encoding="utf-8"))
    assert first == second
    assert json.loads(first[0])["ok"] is True


def test_runtime_crosscheck_module_load_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reverse_verifier.importlib.util, "spec_from_file_location", lambda *args, **kwargs: None)
    contract = _loaded_contract()
    with pytest.raises(RuntimeError, match="unable to load runtime verifier module"):
        reverse_verifier._runtime_crosscheck(
            repo_root=REPO_ROOT,
            nodes=contract["nodes"],
            happy_path=contract["happy_path"],
        )
