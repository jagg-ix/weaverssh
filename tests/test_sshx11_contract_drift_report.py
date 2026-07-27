from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/sshx11_contract_cases.json"
DRIFT_SCRIPT = ROOT / "tools/verification/build_sshx11_contract_drift_report.py"


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, check=False)


@pytest.mark.sshx11
@pytest.mark.contract
def test_contract_drift_report_is_clean(tmp_path: Path) -> None:
    drift_output = tmp_path / "drift_report.json"
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE}"
    assert DRIFT_SCRIPT.exists(), f"missing drift script: {DRIFT_SCRIPT}"
    proc = _run(
        [
            "python3",
            str(DRIFT_SCRIPT),
            "--fixture",
            str(FIXTURE),
            "--output",
            str(drift_output),
            "--strict",
        ],
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert drift_output.exists(), f"missing drift report output: {drift_output}"
    payload = json.loads(drift_output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["mismatch_count"] == 0
    assert payload["mismatches"] == []
