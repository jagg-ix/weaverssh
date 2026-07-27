from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
GO_MOD_ROOT = REPO_ROOT / "tools" / "verification" / "go" / "sshwb"


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GOCACHE"] = str(Path(tempfile.gettempdir()) / "go-build-cache")
    return subprocess.run(
        cmd,
        cwd=str(GO_MOD_ROOT),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


@pytest.mark.sshx11
@pytest.mark.unit
def test_go_unit_suite_passes() -> None:
    assert GO_MOD_ROOT.exists(), f"missing go module: {GO_MOD_ROOT}"
    proc = _run(["go", "test", "./..."])
    assert proc.returncode == 0, f"go test failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "FAIL" not in proc.stdout


@pytest.mark.sshx11
@pytest.mark.unit
def test_go_fuzz_seed_regression_entrypoint() -> None:
    proc = _run(["go", "test", "-run", "FuzzParseHostSpec", "./contract"])
    assert proc.returncode == 0, f"go fuzz seed regression failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
