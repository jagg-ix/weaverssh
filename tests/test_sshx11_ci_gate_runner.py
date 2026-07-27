from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/verification/run_sshx11_ci_gate.py"


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, check=False)


def _load_module():
    spec = importlib.util.spec_from_file_location("sshx11_ci_gate_runner", str(SCRIPT))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.mark.sshx11
@pytest.mark.unit
def test_ci_gate_dry_run_outputs_policy(tmp_path: Path) -> None:
    out = tmp_path / "ci_gate_fast.json"
    proc = _run(
        [
            "python3",
            str(SCRIPT),
            "--tier",
            "fast",
            "--dry-run",
            "--output",
            str(out),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "dry_run"
    assert payload["tier"] == "fast"
    assert len(payload["plan"]) == 2
    assert payload["policy"]["must_have_zero_failures_and_errors"] is True


@pytest.mark.sshx11
@pytest.mark.unit
def test_ci_gate_plan_includes_performance_only_on_nightly() -> None:
    module = _load_module()
    fast = module._tier_plan("fast")
    full = module._tier_plan("full")
    nightly = module._tier_plan("nightly")

    fast_names = [step["name"] for step in fast]
    full_names = [step["name"] for step in full]
    nightly_names = [step["name"] for step in nightly]

    assert "performance" not in fast_names
    assert "performance" not in full_names
    assert nightly_names[-1] == "performance"


@pytest.mark.sshx11
@pytest.mark.unit
def test_ci_gate_parse_junit_detects_failures(tmp_path: Path) -> None:
    module = _load_module()
    junit = tmp_path / "sample.xml"
    junit.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite tests="2" failures="1" errors="0" skipped="0">
    <testcase classname="a" name="ok" />
    <testcase classname="a" name="bad">
      <failure message="assertion failed" />
    </testcase>
  </testsuite>
</testsuites>
""",
        encoding="utf-8",
    )
    parsed = module._parse_junit(junit)
    assert parsed["tests"] == 2
    assert parsed["failures"] == 1
    assert parsed["errors"] == 0
    assert len(parsed["failed_cases"]) == 1
    assert parsed["failed_cases"][0]["name"] == "bad"
