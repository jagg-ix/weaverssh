#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.end_user_usecases.common import base_payload, emit, load_json_file, run_command


def main() -> int:
    parser = argparse.ArgumentParser(description="Use case UC06: preview 9P-over-SOCKS interop plan.")
    parser.add_argument("--interop-profile", default="auto")
    parser.add_argument("--plan-output", default="/tmp/sshx11_9p_over_socks.json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    plan_output = Path(args.plan_output).expanduser()
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/run_sshx11_9p_over_socks.py"),
        "--dry-run",
        "--interop-profile",
        args.interop_profile,
        "--output",
        str(plan_output),
    ]
    payload = base_payload("UC06", "9P-over-SOCKS dry-run interop profile", cmd)
    payload["plan_output"] = str(plan_output)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    if proc.returncode == 0 and plan_output.exists():
        interop_payload = load_json_file(plan_output)
        payload["interop_payload"] = interop_payload
        payload["ok"] = bool(interop_payload.get("ok", False))
    else:
        payload["ok"] = False

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

