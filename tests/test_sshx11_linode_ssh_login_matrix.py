from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PY_SCRIPT = ROOT / "tools/verification/check_linode_ssh_login_matrix.py"
SH_SCRIPT = ROOT / "tools/verification/check_linode_ssh_login_matrix.sh"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_linode_ssh_login_matrix", str(PY_SCRIPT))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _has_ssh_credentials() -> bool:
    """True when there is a usable public-key context (agent identity or explicit key)."""
    if os.getenv("WEAVERSSH_LINODE_IDENTITY_FILE", "").strip():
        return True
    probe = subprocess.run(["ssh-add", "-l"], text=True, capture_output=True, check=False)
    # ssh-add -l: 0 = identities present, 1 = none, 2 = no agent.
    return probe.returncode == 0


@pytest.mark.sshx11
@pytest.mark.unit
def test_linode_login_matrix_builds_publickey_only_ssh_command() -> None:
    """The matrix must never fall back to passwords: publickey-only + BatchMode."""
    module = _load_module()
    args = argparse.Namespace(
        timeout_s=8,
        strict_hostkey="accept-new",
        port=22,
        identity_file="",
    )
    base = module._ssh_base_args(args)
    assert base[0] == "ssh"
    assert "BatchMode=yes" in base
    assert "PreferredAuthentications=publickey" in base
    assert "StrictHostKeyChecking=accept-new" in base
    assert "ConnectTimeout=8" in base
    # No identity file requested -> no -i flag injected.
    assert "-i" not in base

    args_with_key = argparse.Namespace(
        timeout_s=8,
        strict_hostkey="accept-new",
        port=2222,
        identity_file="~/.ssh/id_ed25519",
    )
    keyed = module._ssh_base_args(args_with_key)
    assert "-i" in keyed
    assert "2222" in keyed


@pytest.mark.sshx11
@pytest.mark.unit
def test_linode_login_matrix_reports_no_hosts_cleanly() -> None:
    """Empty host list is a clean, non-crashing failure (exit 2)."""
    proc = subprocess.run(
        ["python3", str(PY_SCRIPT), "--hosts", "", "--no-plain"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["error"] == "no hosts provided"


@pytest.mark.sshx11
@pytest.mark.system
def test_linode_login_matrix_root_and_kb_succeed(tmp_path: Path) -> None:
    """Live gate: root and kb must log in on every configured Linode host.

    Skips when there is no public-key context (no agent identity / no key file),
    so credential-less CI does not see a spurious failure.
    """
    if not _has_ssh_credentials():
        pytest.skip("No SSH agent identity or WEAVERSSH_LINODE_IDENTITY_FILE configured.")

    out = tmp_path / "linode_login_matrix.json"
    proc = subprocess.run(
        [str(SH_SCRIPT), "--no-plain"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "WEAVERSSH_LINODE_IDENTITY_FILE": os.getenv("WEAVERSSH_LINODE_IDENTITY_FILE", "")},
    )
    payload = json.loads(proc.stdout)
    assert payload["case_id"] == "WEAVERSSH_LINODE_SSH_LOGIN_MATRIX"

    explicit = [a for a in payload["attempts"] if a["mode"] == "explicit_user"]
    failures = [a for a in explicit if not bool(a["ok"])]
    assert not failures, json.dumps(payload, indent=2)

    # Every (host, user) pair in the matrix must have authenticated.
    hosts = payload["hosts"]
    users = payload["explicit_users_expected_success"]
    succeeded = {(a["host"], a["user"]) for a in explicit if bool(a["ok"])}
    for host in hosts:
        for user in users:
            assert (host, user) in succeeded, f"{user}@{host} did not authenticate"

    assert proc.returncode == 0, proc.stdout
