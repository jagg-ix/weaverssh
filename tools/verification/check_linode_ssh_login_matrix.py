#!/usr/bin/env python3
from __future__ import annotations

"""Live SSH login matrix for the two Linode hosts used by weaverssh tests.

The default expectations come from the verified operator context:
- root and kb should log in on both hosts using the loaded SSH agent key.
- plain "ssh <ip>" should fail because OpenSSH uses the local user by default.
"""

import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


DEFAULT_HOSTS = "203.0.113.10,203.0.113.20"
DEFAULT_USERS = "root,kb"


def _csv(raw: str) -> list[str]:
    return [item.strip() for item in str(raw or "").split(",") if item.strip()]


def _ssh_base_args(args: argparse.Namespace) -> list[str]:
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        f"ConnectTimeout={int(args.timeout_s)}",
        "-o",
        f"StrictHostKeyChecking={args.strict_hostkey}",
        "-p",
        str(int(args.port)),
    ]
    if str(args.identity_file or "").strip():
        cmd.extend(["-i", str(Path(args.identity_file).expanduser())])
    return cmd


def _run_ssh(args: argparse.Namespace, target: str) -> dict[str, Any]:
    remote_cmd = 'printf "user="; id -un; printf "host="; hostname'
    cmd = [*_ssh_base_args(args), target, remote_cmd]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(Path(__file__).resolve().parents[2]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=max(float(args.timeout_s) + 4.0, 8.0),
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "target": target,
            "command": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "ssh_ok": False,
            "timed_out": True,
        }
    return {
        "target": target,
        "command": cmd,
        "returncode": int(proc.returncode),
        "stdout": str(proc.stdout or "").strip(),
        "stderr": str(proc.stderr or "").strip(),
        "ssh_ok": proc.returncode == 0,
        "timed_out": False,
    }


def _attempt(args: argparse.Namespace, host: str, user: str | None, expect_success: bool) -> dict[str, Any]:
    target = host if user is None else f"{user}@{host}"
    raw = _run_ssh(args, target)
    ok = bool(raw["ssh_ok"]) if expect_success else not bool(raw["ssh_ok"])
    return {
        "host": host,
        "user": user or "",
        "mode": "plain_default_user" if user is None else "explicit_user",
        "expected": "success" if expect_success else "failure",
        "ok": ok,
        **raw,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check weaverssh Linode SSH login matrix.")
    parser.add_argument("--hosts", default=os.environ.get("WEAVERSSH_LINODE_HOSTS", DEFAULT_HOSTS))
    parser.add_argument("--users", default=os.environ.get("WEAVERSSH_LINODE_USERS", DEFAULT_USERS))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEAVERSSH_LINODE_SSH_PORT", "22")))
    parser.add_argument("--timeout-s", type=int, default=int(os.environ.get("WEAVERSSH_LINODE_SSH_TIMEOUT", "8")))
    parser.add_argument("--identity-file", default=os.environ.get("WEAVERSSH_LINODE_IDENTITY_FILE", ""))
    parser.add_argument("--strict-hostkey", default=os.environ.get("WEAVERSSH_LINODE_STRICT_HOSTKEY", "accept-new"))
    parser.add_argument("--include-plain", action="store_true", default=True)
    parser.add_argument("--no-plain", action="store_false", dest="include_plain")
    parser.add_argument("--plain-expected-success", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    hosts = _csv(args.hosts)
    users = _csv(args.users)
    if not hosts:
        print(json.dumps({"ok": False, "error": "no hosts provided"}, indent=2))
        return 2
    if not users:
        print(json.dumps({"ok": False, "error": "no users provided"}, indent=2))
        return 2

    attempts: list[dict[str, Any]] = []
    for host in hosts:
        for user in users:
            attempts.append(_attempt(args, host, user, expect_success=True))
        if args.include_plain:
            attempts.append(_attempt(args, host, None, expect_success=bool(args.plain_expected_success)))

    payload = {
        "ok": all(bool(item["ok"]) for item in attempts),
        "case_id": "WEAVERSSH_LINODE_SSH_LOGIN_MATRIX",
        "local_default_user": getpass.getuser(),
        "hosts": hosts,
        "explicit_users_expected_success": users,
        "plain_ssh_expected": "success" if args.plain_expected_success else "failure",
        "attempts": attempts,
    }

    if args.output:
        Path(args.output).expanduser().write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
