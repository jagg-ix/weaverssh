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
    parser = argparse.ArgumentParser(description="Use case UC05: preview CI gate plan in dry-run mode.")
    parser.add_argument("--tier", default="fast", choices=["fast", "full", "nightly"])
    parser.add_argument("--gate-output", default="/tmp/sshx11_ci_gate_fast.json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    gate_output = Path(args.gate_output).expanduser()
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/run_sshx11_ci_gate.py"),
        "--tier",
        args.tier,
        "--dry-run",
        "--output",
        str(gate_output),
    ]
    payload = base_payload("UC05", "CI gate dry-run preview", cmd)
    payload["gate_output"] = str(gate_output)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    if proc.returncode == 0 and gate_output.exists():
        gate_payload = load_json_file(gate_output)
        payload["gate_payload"] = gate_payload
        payload["ok"] = bool(gate_payload.get("ok", False))
    else:
        payload["ok"] = False

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

