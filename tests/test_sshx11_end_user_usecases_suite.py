from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUITE = REPO_ROOT / "tools" / "verification" / "end_user_usecases" / "run_end_user_usecases_suite.py"

pytestmark = [pytest.mark.sshx11, pytest.mark.system]


def test_end_user_suite_runner_dry_run(tmp_path: Path) -> None:
    output_dir = tmp_path / "suite"
    summary = output_dir / "summary.json"
    proc = subprocess.run(
        [
            "python3",
            str(SUITE),
            "--output-dir",
            str(output_dir),
            "--summary-output",
            str(summary),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert summary.exists()
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["case_total"] == 12
    assert payload["case_run"] == 12
    assert payload["case_ok"] == 12
    assert payload["live_ssh"] is False
    assert payload["live_chain"] is False
    assert any(case["case_id"] == "UC11" for case in payload["results"])
    assert any(case["case_id"] == "UC13" for case in payload["results"])
    for case in payload["results"]:
        output_path = Path(case["output_path"])
        assert output_path.exists()
