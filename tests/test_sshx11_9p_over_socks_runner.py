from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import json


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "tools" / "verification" / "run_sshx11_9p_over_socks.py"


def test_sshx11_9p_runner_help() -> None:
    proc = subprocess.run(["python3", str(RUNNER), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "--backend" in proc.stdout
    assert "--interop-profile" in proc.stdout
    assert "--protocol-versions" in proc.stdout
    assert "native" in proc.stdout
    assert "qemu" in proc.stdout


def test_sshx11_9p_runner_dry_run_default_native() -> None:
    tmp = Path(tempfile.gettempdir()) / "sshx11_9p_runner_test_dryrun.json"
    proc = subprocess.run(["python3", str(RUNNER), "--dry-run", "--output", str(tmp)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "ok=True" in proc.stdout
    assert "output=" in proc.stdout
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    assert payload["backend"] == "native"
    assert payload["interop_profile"] == "auto"
    assert payload["protocol_candidates"][0] == "9P2000.L"


def test_sshx11_9p_runner_dry_run_plan9port_profile() -> None:
    tmp = Path(tempfile.gettempdir()) / "sshx11_9p_runner_test_plan9port.json"
    proc = subprocess.run(
        [
            "python3",
            str(RUNNER),
            "--dry-run",
            "--interop-profile",
            "plan9port",
            "--output",
            str(tmp),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    assert payload["interop_profile"] == "plan9port"
    assert payload["protocol_candidates"] == ["9P2000"]


def test_sshx11_9p_runner_dry_run_protocol_override() -> None:
    tmp = Path(tempfile.gettempdir()) / "sshx11_9p_runner_test_override.json"
    proc = subprocess.run(
        [
            "python3",
            str(RUNNER),
            "--dry-run",
            "--protocol-versions",
            "9P2000.u,9P2000",
            "--output",
            str(tmp),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    assert payload["protocol_candidates"] == ["9P2000.u", "9P2000"]


def test_sshx11_9p_runner_dry_run_protocol_family_override() -> None:
    tmp = Path(tempfile.gettempdir()) / "sshx11_9p_runner_test_family_override.json"
    proc = subprocess.run(
        [
            "python3",
            str(RUNNER),
            "--dry-run",
            "--protocol-versions",
            "9P2000.L,9P2000.X",
            "--output",
            str(tmp),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    assert payload["protocol_candidates"] == ["9P2000.L", "9P2000.X"]
