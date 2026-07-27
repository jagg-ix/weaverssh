#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.end_user_usecases.common import emit, run_command


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Use case UC04: verify SSH login readiness on remote hosts.")
    parser.add_argument("--hosts", default="203.0.113.10,203.0.113.20")
    parser.add_argument("--users", default="root,kb")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--strict-hostkey", default="accept-new")
    parser.add_argument("--timeout-s", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    hosts = _split_csv(args.hosts)
    users = _split_csv(args.users)
    if not hosts:
        print('{"ok": false, "error": "no hosts provided"}')
        return 1
    if not users:
        print('{"ok": false, "error": "no users provided"}')
        return 1

    results: list[dict[str, object]] = []
    for host in hosts:
        host_result: dict[str, object] = {"host": host, "ok": False, "attempts": []}
        for user in users:
            cmd = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                f"StrictHostKeyChecking={args.strict_hostkey}",
                "-o",
                f"ConnectTimeout={args.timeout_s}",
                "-p",
                str(args.port),
                f"{user}@{host}",
                "hostname && whoami",
            ]
            if args.dry_run:
                host_result["ok"] = True
                host_result["selected_user"] = user
                host_result["planned_command"] = cmd
                break
            proc = run_command(cmd)
            attempt = {
                "user": user,
                "returncode": proc.returncode,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "command": cmd,
            }
            attempts = host_result["attempts"]
            assert isinstance(attempts, list)
            attempts.append(attempt)
            if proc.returncode == 0:
                host_result["ok"] = True
                host_result["selected_user"] = user
                break
        results.append(host_result)

    payload = {
        "case_id": "UC04",
        "title": "Verify remote SSH login readiness",
        "ok": all(bool(item.get("ok")) for item in results),
        "mode": "dry_run" if args.dry_run else "live",
        "hosts": hosts,
        "users": users,
        "port": args.port,
        "results": results,
    }
    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

