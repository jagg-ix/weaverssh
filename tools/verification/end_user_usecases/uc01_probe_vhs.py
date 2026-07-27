#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.end_user_usecases.common import base_payload, emit, run_command, write_json_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Use case UC01: probe VHS and shell tooling availability.")
    parser.add_argument("--probe-output", default="/tmp/sshx11_probe.json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    probe_output = Path(args.probe_output).expanduser()
    cmd = ["python3", str(REPO_ROOT / "tools/verification/sshx11_vhs_record.py"), "probe", "--json"]
    payload = base_payload("UC01", "Probe local prerequisites and VHS tooling", cmd)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    payload["probe_output"] = str(probe_output)

    if proc.returncode == 0:
        try:
            probe_payload = json.loads(proc.stdout)
            write_json_file(probe_output, probe_payload)
            payload["probe_payload"] = probe_payload
            payload["ok"] = bool(probe_payload.get("ok", False))
        except json.JSONDecodeError as exc:
            payload["ok"] = False
            payload["parse_error"] = str(exc)
    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

