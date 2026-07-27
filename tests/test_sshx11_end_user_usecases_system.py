from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = REPO_ROOT / "tools" / "verification" / "end_user_usecases"

pytestmark = [pytest.mark.sshx11, pytest.mark.system]


def _run_case(script_name: str, *args: str) -> dict:
    script = CASES_DIR / script_name
    proc = subprocess.run(
        ["python3", str(script), *args],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True, payload
    return payload


def test_uc01_probe_vhs(tmp_path: Path) -> None:
    probe_output = tmp_path / "uc01_probe.json"
    payload = _run_case("uc01_probe_vhs.py", "--probe-output", str(probe_output))
    assert payload["case_id"] == "UC01"
    assert probe_output.exists()
    assert payload["probe_payload"]["ok"] is True


def test_uc02_render_user_service(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    payload = _run_case(
        "uc02_render_user_service.py",
        "--platform",
        "linux",
        "--label",
        "io.github.jaggix.weaverssh",
        "--state-dir",
        str(state_dir),
    )
    assert payload["case_id"] == "UC02"
    service = payload["service_payload"]
    assert service["platform"] == "linux"
    assert service["files"][0]["kind"] == "systemd_user_service"


def test_uc03_print_windows_task(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    payload = _run_case(
        "uc03_print_windows_task.py",
        "--label",
        "io.github.jaggix.weaverssh",
        "--state-dir",
        str(state_dir),
    )
    assert payload["case_id"] == "UC03"
    task = payload["windows_task_payload"]
    assert task["platform"] == "windows"
    assert task["files"][0]["kind"] == "task_xml"


def test_uc04_verify_ssh_login_dry_run() -> None:
    payload = _run_case(
        "uc04_verify_ssh_login.py",
        "--hosts",
        "203.0.113.10,203.0.113.20",
        "--users",
        "root,kb",
        "--dry-run",
    )
    assert payload["case_id"] == "UC04"
    assert payload["mode"] == "dry_run"
    assert len(payload["results"]) == 2


def test_uc05_ci_gate_dry_run(tmp_path: Path) -> None:
    gate_output = tmp_path / "uc05_ci_gate.json"
    payload = _run_case("uc05_ci_gate_dry_run.py", "--tier", "fast", "--gate-output", str(gate_output))
    assert payload["case_id"] == "UC05"
    assert gate_output.exists()
    assert payload["gate_payload"]["status"] == "dry_run"


def test_uc06_9p_over_socks_dry_run(tmp_path: Path) -> None:
    plan_output = tmp_path / "uc06_9p.json"
    payload = _run_case(
        "uc06_9p_over_socks_dry_run.py",
        "--interop-profile",
        "auto",
        "--plan-output",
        str(plan_output),
    )
    assert payload["case_id"] == "UC06"
    assert plan_output.exists()
    assert payload["interop_payload"]["status"] == "dry_run"


def test_uc07_benchmark_socks5_dry_run(tmp_path: Path) -> None:
    plan_output = tmp_path / "uc07_bench.json"
    payload = _run_case(
        "uc07_benchmark_socks5_dry_run.py",
        "--mode",
        "mock",
        "--scenario",
        "smoke",
        "--plan-output",
        str(plan_output),
    )
    assert payload["case_id"] == "UC07"
    assert plan_output.exists()
    assert payload["benchmark_payload"]["status"] == "dry_run"


def test_uc08_remote_execution_tla_plan(tmp_path: Path) -> None:
    report_output = tmp_path / "uc08_remote_tla.json"
    payload = _run_case(
        "uc08_remote_execution_tla_plan.py",
        "--host",
        "203.0.113.10",
        "--user",
        "root",
        "--port",
        "22",
        "--report-output",
        str(report_output),
    )
    assert payload["case_id"] == "UC08"
    assert report_output.exists()
    assert payload["report_payload"]["validation"]["ok"] is True


def test_uc09_extension_set_tla_report(tmp_path: Path) -> None:
    report_output = tmp_path / "uc09_ext.json"
    markdown_output = tmp_path / "uc09_ext.md"
    payload = _run_case(
        "uc09_extension_set_tla_report.py",
        "--report-output",
        str(report_output),
        "--markdown-output",
        str(markdown_output),
    )
    assert payload["case_id"] == "UC09"
    assert report_output.exists()
    assert markdown_output.exists()
    assert payload["report_payload"]["ok"] is True


def test_uc10_crypto_crosslayer_report(tmp_path: Path) -> None:
    report_output = tmp_path / "uc10_crypto.json"
    markdown_output = tmp_path / "uc10_crypto.md"
    interaction_json = tmp_path / "uc10_interaction.json"
    interaction_md = tmp_path / "uc10_interaction.md"
    payload = _run_case(
        "uc10_crypto_crosslayer_report.py",
        "--report-output",
        str(report_output),
        "--markdown-output",
        str(markdown_output),
        "--interaction-json",
        str(interaction_json),
        "--interaction-md",
        str(interaction_md),
    )
    assert payload["case_id"] == "UC10"
    assert report_output.exists()
    assert markdown_output.exists()
    assert interaction_json.exists()
    assert interaction_md.exists()
    assert payload["report_payload"]["ok"] is True


def test_uc13_scp_sftp_backhaul_unit_test(tmp_path: Path) -> None:
    junit_output = tmp_path / "uc13_backhaul.junit.xml"
    payload = _run_case(
        "uc13_scp_sftp_backhaul_unit_test.py",
        "--x-port",
        "6017",
        "--remote-bind-port",
        "22022",
        "--remote-host",
        "203.0.113.20",
        "--remote-user",
        "root",
        "--remote-port",
        "22",
        "--state-dir",
        str(tmp_path / "uc13_state"),
        "--junit-output",
        str(junit_output),
    )
    assert payload["case_id"] == "UC13"
    assert junit_output.exists()
    assert payload["summary_counts"]["failed"] == 0
    sequence = payload["sequence_preview"]
    step_ids = [step["id"] for step in sequence["steps"]]
    assert "open_reverse_backhaul" in step_ids
    assert "check_reverse_backhaul_status" in step_ids
    assert "chain_scp_to_loopback_endpoint" in step_ids
    assert "close_reverse_backhaul" in step_ids
    policy = sequence["authorization_policy"]
    assert policy["deny_users"] == ["root"]
    assert policy["enforce_publickey_only"] is True
    assert sequence["x_port"] == 6017
    assert sequence["remote_bind_port"] == 22022
