from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_crypto_crosslayer_reverse as reverse_verifier


def test_crosslayer_contract_forward_reverse_runtime_ok() -> None:
    contract_path = REPO_ROOT / "verification" / "tla" / "SSHX11CryptoCrossLayerContract.tla"
    contract = reverse_verifier.load_contract(contract_path)
    result = reverse_verifier.run_validation(
        contract=contract,
        crosscheck_runtime=True,
        repo_root=REPO_ROOT,
    )
    assert result["ok"] is True
    assert result["forward"]["ok"] is True
    assert result["reverse"]["ok"] is True
    assert result["coverage"]["ok"] is True
    assert result["cross_layer_obligations"]["ok"] is True
    assert result["trusted_forwarding_rejection"]["ok"] is True
    assert result["runtime_crosscheck"]["ok"] is True


def test_crosslayer_artifacts_emit_json_and_markdown(tmp_path: Path) -> None:
    contract_path = REPO_ROOT / "verification" / "tla" / "SSHX11CryptoCrossLayerContract.tla"
    contract = reverse_verifier.load_contract(contract_path)
    interactions = reverse_verifier.build_interaction_payload(contract)
    validation = reverse_verifier.run_validation(
        contract=contract,
        crosscheck_runtime=False,
        repo_root=REPO_ROOT,
    )

    output_json = tmp_path / "validation.json"
    output_md = tmp_path / "validation.md"
    interaction_json = tmp_path / "interactions.json"
    interaction_md = tmp_path / "interactions.md"
    reverse_verifier.write_outputs(
        validation=validation,
        interactions=interactions,
        output_json=output_json,
        output_md=output_md,
        interaction_json=interaction_json,
        interaction_md=interaction_md,
    )

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert "forward" in payload and "reverse" in payload
    assert "Reverse Goal Walk" in output_md.read_text(encoding="utf-8")
    interactions_payload = json.loads(interaction_json.read_text(encoding="utf-8"))
    assert len(interactions_payload["forward_interactions"]) >= 39
    assert interactions_payload["contract"]["final_goal"] == "N39"
