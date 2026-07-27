from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_fsm_python_tla as verifier


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec))
            f.write("\n")


def test_observed_trace_ingestion_and_strict_pass(tmp_path: Path) -> None:
    p = tmp_path / "observed.ndjson"
    _write_ndjson(
        p,
        [
            {"trace": "obs", "actor": "sshClient", "event": "start"},
            {"trace": "obs", "actor": "sshServer", "event": "acceptTransport"},
            {"trace": "obs", "actor": "sshClient", "event": "keyExchangeDone"},
        ],
    )
    observed = verifier.load_observed_traces([p], fmt="ndjson")
    report = verifier.run_verification(tla_path=None, observed_traces=observed)
    assert "observed" in report
    assert report["observed"]["ok"] is True
    assert report["observed"]["trace_count"] == 1


def test_observed_invalid_event_drives_feedback_candidates(tmp_path: Path) -> None:
    p = tmp_path / "observed_bad.ndjson"
    _write_ndjson(
        p,
        [
            {"trace": "obsBad", "actor": "bridgeClient", "event": "startRelay"},
        ],
    )
    observed = verifier.load_observed_traces([p], fmt="ndjson")
    report = verifier.run_verification(tla_path=None, observed_traces=observed)
    assert report["observed"]["ok"] is False
    feedback = verifier.build_hybrid_feedback(report)
    assert feedback["ok"] is False
    assert feedback["summary"]["missing_transition_count"] >= 1
    assert feedback["summary"]["gate_failure_count"] >= 1
