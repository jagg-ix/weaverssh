from __future__ import annotations

import json
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_user_service_install.py"


def _run_json(args: list[str]) -> dict:
    proc = subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_render_linux_user_service_plan() -> None:
    payload = _run_json(["render", "--platform", "linux", "--state-dir", "/tmp/sshx11d-test"])
    assert payload["ok"] is True
    assert payload["platform"] == "linux"
    assert payload["label"] == "local.sshx11d"
    assert payload["files"]
    assert payload["files"][0]["kind"] == "systemd_user_service"
    assert "systemctl" in " ".join(" ".join(row) for row in payload["activation_commands"])


def test_render_windows_task_plan() -> None:
    payload = _run_json(["print-windows-task", "--state-dir", "/tmp/sshx11d-test"])
    assert payload["ok"] is True
    assert payload["platform"] == "windows"
    assert payload["files"]
    assert payload["files"][0]["kind"] == "task_xml"
    assert "<Task version=" in payload["files"][0]["content"]
    assert payload["activation_commands"][0][0].lower() == "schtasks"

def test_render_linux_headless_user_service_plan() -> None:
    payload = _run_json(["render", "--platform", "linux-headless", "--state-dir", "/tmp/sshx11d-test"])
    assert payload["ok"] is True
    assert payload["platform"] == "linux-headless"
    assert payload["files"][0]["kind"] == "systemd_user_service"


def test_render_freebsd_rcd_plan() -> None:
    payload = _run_json(["render", "--platform", "freebsd", "--state-dir", "/tmp/sshx11d-test"])
    assert payload["ok"] is True
    assert payload["platform"] == "freebsd"
    assert payload["files"][0]["kind"] == "freebsd_rcd_service"
    assert payload["activation_commands"][1][0] == "sysrc"


def test_render_openbsd_rcd_plan() -> None:
    payload = _run_json(["render", "--platform", "openbsd", "--state-dir", "/tmp/sshx11d-test"])
    assert payload["ok"] is True
    assert payload["platform"] == "openbsd"
    assert payload["files"][0]["kind"] == "openbsd_rcd_service"
    assert payload["activation_commands"][1][:2] == ["rcctl", "enable"]
