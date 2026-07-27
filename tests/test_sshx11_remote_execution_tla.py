from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_remote_execution_tla as verifier


def test_remote_execution_contract_loads() -> None:
    contract_path = REPO_ROOT / "verification" / "tla" / "SSHX11RemoteExecutionContract.tla"
    contract = verifier.load_contract(contract_path)
    assert "nodes" in contract
    assert len(contract["nodes"]) >= 6
    assert contract["mandatory_sequence"] == ["R01", "R02", "R03", "R04", "R05"]


def test_remote_execution_plan_matches_contract() -> None:
    contract_path = REPO_ROOT / "verification" / "tla" / "SSHX11RemoteExecutionContract.tla"
    contract = verifier.load_contract(contract_path)
    execution = verifier.normalize_steps_from_plan(
        {
            "host": "203.0.113.7",
            "user": "root",
            "port": 22,
        }
    )
    result = verifier.validate_against_contract(contract, execution)
    assert result["ok"] is True, result


def test_remote_execution_scope_delta_is_detected() -> None:
    contract_path = REPO_ROOT / "verification" / "tla" / "SSHX11RemoteExecutionContract.tla"
    contract = verifier.load_contract(contract_path)
    execution = verifier.normalize_steps_from_plan(
        {
            "host": "203.0.113.7",
            "user": "root",
            "port": 22,
        }
    )
    execution["steps"][0]["dest_action"] = "remote_python"
    result = verifier.validate_against_contract(contract, execution)
    assert result["ok"] is False
    kinds = {d["kind"] for d in result["deltas"]}
    assert "execution_scope_mismatch" in kinds

