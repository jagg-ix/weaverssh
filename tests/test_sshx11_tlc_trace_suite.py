from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_extension_set_tla as tla_verifier
from tools.verification import verify_sshx11_tlc_trace_suite as trace_verifier

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "sshx11_tlc_trace_suite.json"
SCRIPT = REPO_ROOT / "tools" / "verification" / "verify_sshx11_tlc_trace_suite.py"


def test_trace_suite_fixture_covers_every_registered_tlc_target() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    by_target = {row["target"]: row for row in payload["targets"]}
    assert set(by_target) == set(tla_verifier.TLC_TARGET_SPECS)
    for target, (module, cfg) in tla_verifier.TLC_TARGET_SPECS.items():
        row = by_target[target]
        assert row["module"] == module
        assert row["cfg"] == cfg
        assert (tla_verifier.TLA_DIR / module).exists()
        assert (tla_verifier.TLA_DIR / cfg).exists()
        kinds = {trace["kind"] for trace in row["traces"]}
        assert kinds == {"happy", "rejected", "failure"}


def test_trace_suite_validator_reports_clean_fixture() -> None:
    report = trace_verifier.validate_trace_suite(FIXTURE)
    assert report["ok"] is True
    assert report["target_count"] == len(tla_verifier.TLC_TARGET_SPECS)
    assert report["trace_count"] == len(tla_verifier.TLC_TARGET_SPECS) * 3
    assert report["errors"] == []


def test_trace_suite_cli_emits_machine_readable_report(tmp_path: Path) -> None:
    output = tmp_path / "trace_suite_report.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE), "--output", str(output)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["target_count"] == len(tla_verifier.TLC_TARGET_SPECS)
    assert payload["trace_count"] == len(tla_verifier.TLC_TARGET_SPECS) * 3
