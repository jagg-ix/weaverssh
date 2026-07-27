from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/sshx11_contract_cases.json"
PY_EVAL = ROOT / "tools/verification/sshwb_contract_eval.py"
GO_MOD_ROOT = ROOT / "tools/verification/go/sshwb"


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GOCACHE"] = str(Path(tempfile.gettempdir()) / "go-build-cache")
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, check=False, env=env)


@pytest.mark.sshx11
@pytest.mark.contract
def test_contract_python_and_go_parity() -> None:
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE}"
    assert PY_EVAL.exists(), f"missing python evaluator: {PY_EVAL}"
    assert GO_MOD_ROOT.exists(), f"missing go module: {GO_MOD_ROOT}"

    py_proc = _run(
        ["python3", str(PY_EVAL), "--input", str(FIXTURE), "--output", "/tmp/sshwb_contract_python.json"],
        cwd=ROOT,
    )
    assert py_proc.returncode == 0, py_proc.stderr
    py_out = json.loads(py_proc.stdout)

    go_proc = _run(["go", "run", "./cmd/contracteval", "--input", str(FIXTURE)], cwd=GO_MOD_ROOT)
    assert go_proc.returncode == 0, go_proc.stderr
    go_out = json.loads(go_proc.stdout)

    assert py_out == go_out

    by_id = {item["id"]: item for item in py_out["cases"]}
    assert by_id["c1-linux-basic"]["normalized_platform"] == "linux-generic"
    assert by_id["c2-zos-alias"]["normalized_platform"] == "zos"
    assert by_id["c3-solaris-alias"]["normalized_platform"] == "solaris"
    assert by_id["c5-missing-host"]["ok"] is False
    assert by_id["c5-missing-host"]["error"] == "missing_host"
