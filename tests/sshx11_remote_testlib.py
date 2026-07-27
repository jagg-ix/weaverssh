from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path

DEFAULT_CSV = Path("~/Downloads/linodes-2026-05-30.csv").expanduser()


def parse_csv_running_hosts(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    rows: list[tuple[str, str]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            status = (row.get("status") or "").strip().lower()
            host = (row.get("ipv4") or "").strip()
            label = (row.get("label") or host).strip() or host
            if status == "running" and host:
                rows.append((label, host))
    return rows


def discover_hosts() -> list[tuple[str, str]]:
    host_list = os.getenv("SSHX11_REMOTE_HOSTS", "").strip()
    if host_list:
        out = []
        for raw in host_list.split(","):
            token = raw.strip()
            if not token:
                continue
            if "=" in token:
                label, host = token.split("=", 1)
                out.append((label.strip() or host.strip(), host.strip()))
            else:
                out.append((token, token))
        return out

    single = os.getenv("SSHX11_REMOTE_HOST", "").strip()
    if single:
        return [(single, single)]

    csv_path = Path(os.getenv("SSHX11_REMOTE_HOST_CSV", str(DEFAULT_CSV))).expanduser()
    return parse_csv_running_hosts(csv_path)


def discover_users(default_csv: str = "root,kb") -> list[str]:
    raw = os.getenv("SSHX11_REMOTE_USERS", default_csv)
    users = [u.strip() for u in raw.split(",") if u.strip()]
    return users or ["root"]


def ssh_opts() -> list[str]:
    timeout = os.getenv("SSHX11_REMOTE_TIMEOUT", "10").strip() or "10"
    strict = os.getenv("SSHX11_HOSTKEY_MODE", "accept-new").strip() or "accept-new"
    opts = [
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        f"StrictHostKeyChecking={strict}",
    ]
    if os.getenv("SSHX11_REMOTE_IGNORE_KNOWN_HOSTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        opts += ["-o", "UserKnownHostsFile=/dev/null"]
    return opts


def identity_opt() -> list[str]:
    identity = os.getenv("SSHX11_REMOTE_IDENTITY_FILE", "").strip()
    if not identity:
        return []
    return ["-i", str(Path(identity).expanduser())]


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, env=env)


def run_ssh(user: str, host: str, remote_command: str) -> subprocess.CompletedProcess[str]:
    cmd = ["ssh", *ssh_opts(), *identity_opt(), f"{user}@{host}", remote_command]
    return run(cmd)


def choose_auth_for_hosts(
    hosts: list[tuple[str, str]],
    users: list[str] | None = None,
) -> tuple[list[dict[str, object]], dict[str, str]]:
    user_list = users if users is not None else discover_users()
    attempts: list[dict[str, object]] = []
    selected: dict[str, str] = {}
    for label, host in hosts:
        for user in user_list:
            probe = run_ssh(user, host, "echo AUTH_OK && whoami")
            ok = probe.returncode == 0 and "AUTH_OK" in probe.stdout
            attempts.append(
                {
                    "label": label,
                    "host": host,
                    "user": user,
                    "ok": ok,
                    "returncode": probe.returncode,
                    "stdout": probe.stdout.strip(),
                    "stderr": probe.stderr.strip(),
                }
            )
            if ok:
                selected[host] = user
                break
    return attempts, selected

def remote_auth_required() -> bool:
    return os.getenv("SSHX11_REMOTE_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}
