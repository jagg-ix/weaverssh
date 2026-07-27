from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from tests import sshx11_remote_testlib as lib


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = int(returncode)
        self.stdout = stdout
        self.stderr = stderr


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "sshx11_ut_py_auth_matrix.json"


@pytest.mark.sshx11
@pytest.mark.unit
def test_parse_csv_running_hosts_filters_status(tmp_path: Path) -> None:
    csv_path = tmp_path / "hosts.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["label", "ipv4", "status"])
        writer.writeheader()
        writer.writerow({"label": "a", "ipv4": "10.0.0.1", "status": "running"})
        writer.writerow({"label": "b", "ipv4": "10.0.0.2", "status": "stopped"})
        writer.writerow({"label": "c", "ipv4": "10.0.0.3", "status": "RUNNING"})
    hosts = lib.parse_csv_running_hosts(csv_path)
    assert hosts == [("a", "10.0.0.1"), ("c", "10.0.0.3")]


@pytest.mark.sshx11
@pytest.mark.unit
def test_discover_hosts_prefers_env_over_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSHX11_REMOTE_HOSTS", "alpha=1.2.3.4,5.6.7.8")
    monkeypatch.setenv("SSHX11_REMOTE_HOST", "9.9.9.9")
    hosts = lib.discover_hosts()
    assert hosts == [("alpha", "1.2.3.4"), ("5.6.7.8", "5.6.7.8")]


@pytest.mark.sshx11
@pytest.mark.unit
def test_ssh_opts_honors_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSHX11_REMOTE_TIMEOUT", "13")
    monkeypatch.setenv("SSHX11_HOSTKEY_MODE", "accept-new")
    monkeypatch.setenv("SSHX11_REMOTE_IGNORE_KNOWN_HOSTS", "true")
    opts = lib.ssh_opts()
    assert "ConnectTimeout=13" in opts
    assert "StrictHostKeyChecking=accept-new" in opts
    assert "UserKnownHostsFile=/dev/null" in opts


@pytest.mark.sshx11
@pytest.mark.unit
def test_choose_auth_for_hosts_first_success(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        ("root", "10.0.0.1"): _FakeProc(255, "", "denied"),
        ("kb", "10.0.0.1"): _FakeProc(0, "AUTH_OK\nkb\n", ""),
        ("root", "10.0.0.2"): _FakeProc(0, "AUTH_OK\nroot\n", ""),
    }

    def _fake_run_ssh(user: str, host: str, remote_command: str) -> _FakeProc:
        assert remote_command.startswith("echo AUTH_OK")
        return responses[(user, host)]

    monkeypatch.setattr(lib, "run_ssh", _fake_run_ssh)
    attempts, selected = lib.choose_auth_for_hosts(
        [("h1", "10.0.0.1"), ("h2", "10.0.0.2")],
        users=["root", "kb"],
    )
    assert selected == {"10.0.0.1": "kb", "10.0.0.2": "root"}
    assert len(attempts) == 3
    assert attempts[0]["ok"] is False
    assert attempts[1]["ok"] is True
    assert attempts[2]["ok"] is True


@pytest.mark.sshx11
@pytest.mark.unit
def test_choose_auth_for_hosts_timeout_retry_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    scenarios = payload["scenarios"]

    for scenario in scenarios:
        hosts = [(h[0], h[1]) for h in scenario["hosts"]]
        users = scenario["users"]
        response_map = {
            (row["user"], row["host"]): _FakeProc(row["rc"], row["stdout"], row["stderr"])
            for row in scenario["responses"]
        }

        def _fake_run_ssh(user: str, host: str, remote_command: str) -> _FakeProc:
            assert remote_command.startswith("echo AUTH_OK")
            return response_map[(user, host)]

        monkeypatch.setattr(lib, "run_ssh", _fake_run_ssh)
        attempts, selected = lib.choose_auth_for_hosts(hosts, users=users)

        assert selected == scenario["expected_selected"]
        assert len(attempts) == int(scenario["expected_attempts"])
        if scenario["name"] == "timeout_then_retry_success":
            assert "timed out" in attempts[0]["stderr"].lower()
            assert attempts[1]["ok"] is True
        if scenario["name"] == "validation_failure_missing_auth_marker":
            assert attempts[0]["returncode"] == 0
            assert attempts[0]["ok"] is False

@pytest.mark.sshx11
@pytest.mark.unit
def test_remote_auth_required_env_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSHX11_REMOTE_REQUIRED", raising=False)
    assert lib.remote_auth_required() is False
    monkeypatch.setenv("SSHX11_REMOTE_REQUIRED", "1")
    assert lib.remote_auth_required() is True
