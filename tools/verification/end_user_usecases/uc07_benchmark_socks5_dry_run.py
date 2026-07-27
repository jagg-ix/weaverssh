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
    parser = argparse.ArgumentParser(description="Use case UC07: preview SOCKS5 benchmark plan in mock mode.")
    parser.add_argument("--mode", default="mock")
    parser.add_argument("--scenario", default="smoke")
    parser.add_argument("--plan-output", default="/tmp/sshx11_socks5_perf.json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    plan_output = Path(args.plan_output).expanduser()
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/benchmark_sshx11_socks5_flows.py"),
        "--mode",
        args.mode,
        "--scenario",
        args.scenario,
        "--dry-run",
        "--output",
        str(plan_output),
    ]
    payload = base_payload("UC07", "SOCKS5 benchmark dry-run plan", cmd)
    payload["plan_output"] = str(plan_output)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    if proc.returncode == 0 and plan_output.exists():
        bench_payload = load_json_file(plan_output)
        payload["benchmark_payload"] = bench_payload
        payload["ok"] = bool(bench_payload.get("ok", False))
    else:
        payload["ok"] = False

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

