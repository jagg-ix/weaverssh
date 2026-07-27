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
    parser = argparse.ArgumentParser(description="Use case UC08: validate remote execution TLA contract from static plan.")
    parser.add_argument("--host", default="203.0.113.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--report-output", default="/tmp/sshx11_remote_execution_tla.json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    report_output = Path(args.report_output).expanduser()
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/verify_sshx11_remote_execution_tla.py"),
        "--source",
        "plan",
        "--host",
        args.host,
        "--user",
        args.user,
        "--port",
        str(args.port),
        "--output",
        str(report_output),
    ]
    payload = base_payload("UC08", "Remote execution TLA validation (plan source)", cmd)
    payload["report_output"] = str(report_output)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    if proc.returncode == 0 and report_output.exists():
        report = load_json_file(report_output)
        payload["report_payload"] = report
        payload["ok"] = bool(report.get("ok", False))
    else:
        payload["ok"] = False

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

