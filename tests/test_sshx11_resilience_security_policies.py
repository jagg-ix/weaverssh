from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.sshx11_remote_testlib import (
    choose_auth_for_hosts,
    discover_hosts,
    discover_users,
    identity_opt,
    remote_auth_required,
    run_ssh,
    ssh_opts,
)


DEFAULT_ET_ROOT = Path("/path/to/research")
FAKE_ED25519_PUB = "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti"


def _et_root() -> Path:
    return Path(os.getenv("SSHX11_ET_ROOT", str(DEFAULT_ET_ROOT))).expanduser()


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


@pytest.fixture(scope="module")
def et_root() -> Path:
    root = _et_root()
    if not root.exists():
        pytest.skip(f"SSHX11 tooling repo not found at {root}")
    return root


@pytest.fixture(scope="module")
def remote_target() -> tuple[str, str]:
    hosts = discover_hosts()
    if not hosts:
        pytest.skip("No remote hosts discovered for resilience/security policy tests.")
    attempts, selected = choose_auth_for_hosts(hosts, discover_users("root,kb"))
    for _, host in hosts:
        user = selected.get(host)
        if user:
            return user, host
    msg = "No authenticated remote target found.\n" + json.dumps(attempts, indent=2)
    if remote_auth_required():
        pytest.fail(msg)
    pytest.skip(msg)


@pytest.mark.sshx11
@pytest.mark.security
@pytest.mark.resilience
def test_strict_hostkey_tamper_fails_closed(remote_target: tuple[str, str]) -> None:
    user, host = remote_target
    with tempfile.NamedTemporaryFile(
        mode="w", prefix="sshx11_tampered_known_hosts_", suffix=".txt", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(f"{host} ssh-ed25519 {FAKE_ED25519_PUB}\n")
        known_hosts = Path(handle.name)

    try:
        cmd = [
            "ssh",
            *ssh_opts(),
            *identity_opt(),
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            f"{user}@{host}",
            "echo HOSTKEY_SHOULD_FAIL",
        ]
        proc = _run(cmd)
    finally:
        known_hosts.unlink(missing_ok=True)

    assert proc.returncode != 0
    assert "HOSTKEY_SHOULD_FAIL" not in proc.stdout
    assert (
        "Host key verification failed" in proc.stderr
        or "REMOTE HOST IDENTIFICATION HAS CHANGED" in proc.stderr
    ), proc.stderr


@pytest.mark.sshx11
@pytest.mark.security
@pytest.mark.resilience
def test_transport_fault_then_recovery(remote_target: tuple[str, str]) -> None:
    user, host = remote_target
    bad_port_proc = _run(
        [
            "ssh",
            *ssh_opts(),
            *identity_opt(),
            "-p",
            "22223",
            f"{user}@{host}",
            "echo BADPORT_SHOULD_FAIL",
        ]
    )
    assert bad_port_proc.returncode != 0
    assert "BADPORT_SHOULD_FAIL" not in bad_port_proc.stdout

    recovery = run_ssh(user, host, "echo TRANSPORT_RECOVERED && whoami")
    assert recovery.returncode == 0, recovery.stderr
    assert "TRANSPORT_RECOVERED" in recovery.stdout


@pytest.mark.sshx11
@pytest.mark.security
@pytest.mark.resilience
def test_failure_artifact_redacts_secret_values(
    et_root: Path, remote_target: tuple[str, str]
) -> None:
    user, host = remote_target
    script = et_root / "tools/verification/verify_sshx11_reverse_socks_smoke.py"
    assert script.exists(), f"missing smoke script: {script}"

    out_path = Path(tempfile.gettempdir()) / "sshx11_reverse_socks_smoke_redaction_pytest.json"
    out_path.unlink(missing_ok=True)
    secret = "SSHX11_SECRET_TOKEN_ABC123"
    env = os.environ.copy()
    env["SSHX11_TEST_SECRET"] = secret

    proc = _run(
        [
            "python3",
            str(script),
            "--host",
            host,
            "--user",
            user,
            "--port",
            "22223",
            "--timeout-s",
            "4",
            "--output",
            str(out_path),
        ],
        cwd=et_root,
        env=env,
    )
    assert proc.returncode != 0
    assert out_path.exists(), "expected artifact was not written"

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, sort_keys=True)
    assert payload.get("ok") is False
    assert secret not in serialized
    assert secret not in proc.stdout
    assert secret not in proc.stderr
    assert "BEGIN OPENSSH PRIVATE KEY" not in serialized
    assert "PRIVATE KEY-----" not in serialized

