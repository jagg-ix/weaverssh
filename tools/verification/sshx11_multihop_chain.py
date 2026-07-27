#!/usr/bin/env python3
from __future__ import annotations

"""Helpers for SSHX11 multi-hop SSH chain execution and probing."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import shlex
import subprocess
from typing import Iterable
import uuid


PREFERRED_CHAIN_HOSTS = ("203.0.113.10", "203.0.113.20")


@dataclass(frozen=True)
class Hop:
    user: str
    host: str

    def render(self) -> str:
        if self.user.strip():
            return f"{self.user.strip()}@{self.host.strip()}"
        return self.host.strip()


def to_hops(values: Iterable[tuple[str, str]]) -> list[Hop]:
    hops: list[Hop] = []
    for user, host in values:
        user_s = str(user).strip()
        host_s = str(host).strip()
        if not host_s:
            raise ValueError("host must be non-empty")
        hops.append(Hop(user=user_s, host=host_s))
    return hops


def build_proxy_jump(hops: Iterable[tuple[str, str]]) -> str:
    rendered = [hop.render() for hop in to_hops(hops)]
    if not rendered:
        raise ValueError("at least one hop is required")
    return ",".join(rendered)


def build_chain_command(
    *,
    target_user: str,
    target_host: str,
    jumps: Iterable[tuple[str, str]],
    remote_command: str,
    ssh_options: list[str] | None = None,
    identity_args: list[str] | None = None,
    target_port: int = 22,
) -> list[str]:
    target_user_s = str(target_user).strip()
    target_host_s = str(target_host).strip()
    if not target_user_s:
        raise ValueError("target_user must be non-empty")
    if not target_host_s:
        raise ValueError("target_host must be non-empty")
    if not str(remote_command).strip():
        raise ValueError("remote_command must be non-empty")

    cmd = ["ssh"]
    if ssh_options:
        cmd.extend(ssh_options)
    if identity_args:
        cmd.extend(identity_args)
    cmd.extend(["-p", str(int(target_port))])
    cmd.extend(["-o", f"ProxyJump={build_proxy_jump(jumps)}"])
    cmd.append(f"{target_user_s}@{target_host_s}")
    cmd.append(str(remote_command))
    return cmd


def build_scp_chain_command(
    *,
    target_user: str,
    target_host: str,
    jumps: Iterable[tuple[str, str]],
    source_path: str | Path,
    destination_path: str | Path,
    upload: bool,
    scp_options: list[str] | None = None,
    identity_args: list[str] | None = None,
    target_port: int = 22,
) -> list[str]:
    target_user_s = str(target_user).strip()
    target_host_s = str(target_host).strip()
    if not target_user_s:
        raise ValueError("target_user must be non-empty")
    if not target_host_s:
        raise ValueError("target_host must be non-empty")

    source_s = str(source_path).strip()
    dest_s = str(destination_path).strip()
    if not source_s:
        raise ValueError("source_path must be non-empty")
    if not dest_s:
        raise ValueError("destination_path must be non-empty")

    cmd = ["scp"]
    if scp_options:
        cmd.extend(scp_options)
    if identity_args:
        cmd.extend(identity_args)
    cmd.extend(["-P", str(int(target_port))])
    cmd.extend(["-o", f"ProxyJump={build_proxy_jump(jumps)}"])

    remote_prefix = f"{target_user_s}@{target_host_s}:"
    if upload:
        cmd.extend([source_s, f"{remote_prefix}{dest_s}"])
    else:
        cmd.extend([f"{remote_prefix}{source_s}", dest_s])
    return cmd


def _sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 64)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_chain_file_roundtrip(
    *,
    jump_user: str,
    jump_host: str,
    target_user: str,
    target_host: str,
    local_source_path: str | Path,
    local_return_path: str | Path,
    remote_path: str | None = None,
    ssh_options: list[str] | None = None,
    scp_options: list[str] | None = None,
    identity_args: list[str] | None = None,
    target_port: int = 22,
    cleanup_remote: bool = True,
) -> dict[str, object]:
    source = Path(local_source_path).expanduser()
    local_return = Path(local_return_path).expanduser()
    if not source.exists():
        raise FileNotFoundError(f"local source file not found: {source}")
    local_return.parent.mkdir(parents=True, exist_ok=True)

    remote_file = remote_path or f"/tmp/sshx11_chain_roundtrip_{uuid.uuid4().hex}.bin"
    jumps = [(jump_user, jump_host)]

    upload_cmd = build_scp_chain_command(
        target_user=target_user,
        target_host=target_host,
        target_port=target_port,
        jumps=jumps,
        source_path=str(source),
        destination_path=remote_file,
        upload=True,
        scp_options=scp_options or [],
        identity_args=identity_args or [],
    )
    up = subprocess.run(upload_cmd, text=True, capture_output=True, check=False)

    download_cmd = build_scp_chain_command(
        target_user=target_user,
        target_host=target_host,
        target_port=target_port,
        jumps=jumps,
        source_path=remote_file,
        destination_path=str(local_return),
        upload=False,
        scp_options=scp_options or [],
        identity_args=identity_args or [],
    )
    down = subprocess.run(download_cmd, text=True, capture_output=True, check=False)

    local_sha = _sha256_hex(source)
    return_sha = _sha256_hex(local_return) if local_return.exists() else ""
    sha_match = bool(local_return.exists() and local_sha == return_sha)

    cleanup_result: dict[str, object] = {
        "attempted": bool(cleanup_remote),
        "ok": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    if cleanup_remote:
        cleanup_cmd = (
            f"rm -f -- {shlex.quote(remote_file)} && echo CHAIN_OK && echo CLEANED_REMOTE_FILE"
        )
        cleanup = run_chain_probe(
            jump_user=jump_user,
            jump_host=jump_host,
            target_user=target_user,
            target_host=target_host,
            remote_command=cleanup_cmd,
            ssh_options=ssh_options or [],
            identity_args=identity_args or [],
            target_port=target_port,
        )
        cleanup_result = {
            "attempted": True,
            "ok": bool(cleanup.get("ok")),
            "returncode": int(cleanup.get("returncode", -1)),
            "stdout": str(cleanup.get("stdout", "")),
            "stderr": str(cleanup.get("stderr", "")),
        }

    ok = bool(up.returncode == 0 and down.returncode == 0 and sha_match)
    return {
        "ok": ok,
        "upload": {
            "ok": up.returncode == 0,
            "returncode": int(up.returncode),
            "stdout": up.stdout,
            "stderr": up.stderr,
            "command": upload_cmd,
        },
        "download": {
            "ok": down.returncode == 0,
            "returncode": int(down.returncode),
            "stdout": down.stdout,
            "stderr": down.stderr,
            "command": download_cmd,
        },
        "paths": {
            "local_source": str(source),
            "local_return": str(local_return),
            "remote_file": str(remote_file),
        },
        "sha256": {
            "local_source": local_sha,
            "local_return": return_sha,
            "match": sha_match,
        },
        "cleanup": cleanup_result,
        "proxy_jump": build_proxy_jump(jumps),
        "target": {"user": str(target_user), "host": str(target_host), "port": int(target_port)},
    }


def run_chain_probe(
    *,
    jump_user: str,
    jump_host: str,
    target_user: str,
    target_host: str,
    remote_command: str = "echo CHAIN_OK && whoami && hostname",
    ssh_options: list[str] | None = None,
    identity_args: list[str] | None = None,
    target_port: int = 22,
) -> dict[str, object]:
    cmd = build_chain_command(
        target_user=target_user,
        target_host=target_host,
        jumps=[(jump_user, jump_host)],
        remote_command=remote_command,
        ssh_options=ssh_options or [],
        identity_args=identity_args or [],
        target_port=target_port,
    )
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return {
        "ok": bool(proc.returncode == 0 and "CHAIN_OK" in (proc.stdout or "")),
        "returncode": int(proc.returncode),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": cmd,
        "proxy_jump": build_proxy_jump([(jump_user, jump_host)]),
        "target": {"user": str(target_user), "host": str(target_host), "port": int(target_port)},
    }


def select_chain_hosts(hosts: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Select the 2-host chain, preferring known Linode IPs when present."""
    if len(hosts) < 2:
        return []
    by_ip = {host: (label, host) for label, host in hosts}
    preferred: list[tuple[str, str]] = []
    for ip in PREFERRED_CHAIN_HOSTS:
        row = by_ip.get(ip)
        if row is not None:
            preferred.append(row)
    if len(preferred) == 2:
        return preferred
    return hosts[:2]


def resolve_identity_path(identity_args: list[str]) -> str:
    """Extract and normalize `-i <identity>` path when present."""
    for idx, token in enumerate(identity_args):
        if token == "-i" and idx + 1 < len(identity_args):
            return str(Path(identity_args[idx + 1]).expanduser())
    return ""
