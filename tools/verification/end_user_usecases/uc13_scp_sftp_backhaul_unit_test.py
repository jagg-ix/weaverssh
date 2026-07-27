#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11_scp_sftp_backhaul as backhaul
from tools.verification.end_user_usecases.common import base_payload, emit, run_command


def _summary_counts(stdout: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for key in counts:
        match = re.search(rf"(\d+)\s+{key}", stdout)
        if match:
            counts[key] = int(match.group(1))
    return counts


def _parse_jumps(raw: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for token in [x.strip() for x in str(raw).split(",") if x.strip()]:
        if "@" in token:
            user, host = token.split("@", 1)
        else:
            user, host = "", token
        items.append((user.strip(), host.strip()))
    return [(u, h) for u, h in items if h]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Use case UC13: validate SCP/SFTP reverse-backhaul command sequence unit tests."
    )
    parser.add_argument("--x-port", type=int, default=6017)
    parser.add_argument("--remote-bind-port", type=int, default=22022)
    parser.add_argument("--remote-host", default="203.0.113.20")
    parser.add_argument("--remote-user", default="root")
    parser.add_argument("--remote-port", type=int, default=22)
    parser.add_argument("--alise-user", default=getpass.getuser())
    parser.add_argument("--jumps", default="root@203.0.113.10")
    parser.add_argument("--identity-file", default="~/.ssh/id_ed25519")
    parser.add_argument("--authorized-keys-path", default="~/.ssh/authorized_keys")
    parser.add_argument("--state-dir", default="/tmp/sshx11_scp_backhaul")
    parser.add_argument("--junit-output", default="/tmp/sshx11_scp_sftp_backhaul_unit.junit.xml")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    jumps = _parse_jumps(args.jumps)

    cmd = [
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_sshx11_scp_sftp_backhaul_unit.py",
        "--junitxml",
        str(Path(args.junit_output).expanduser()),
    ]
    payload = base_payload("UC13", "Validate SCP/SFTP reverse-backhaul sequence unit tests", cmd)
    payload["junit_output"] = str(Path(args.junit_output).expanduser())

    payload["sequence_preview"] = backhaul.build_backhaul_sequence(
        x_port=int(args.x_port),
        remote_bind_port=int(args.remote_bind_port),
        remote_user=str(args.remote_user),
        remote_host=str(args.remote_host),
        remote_ssh_port=int(args.remote_port),
        alise_user=str(args.alise_user),
        jumps=jumps,
        state_dir=str(args.state_dir),
        identity_file=str(args.identity_file),
        authorized_keys_path=str(args.authorized_keys_path),
    )

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    payload["summary_counts"] = _summary_counts(proc.stdout)
    payload["ok"] = bool(proc.returncode == 0 and Path(args.junit_output).expanduser().exists())

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())
