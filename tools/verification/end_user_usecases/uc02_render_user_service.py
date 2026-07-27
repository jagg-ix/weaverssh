#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.end_user_usecases.common import base_payload, emit, run_command


def main() -> int:
    parser = argparse.ArgumentParser(description="Use case UC02: preview Linux/macOS user service definition.")
    parser.add_argument("--platform", default="linux")
    parser.add_argument("--label", default="io.github.jaggix.weaverssh")
    parser.add_argument("--state-dir", default="/tmp/sshx11d-test")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/sshx11_user_service_install.py"),
        "render",
        "--platform",
        args.platform,
        "--label",
        args.label,
        "--state-dir",
        args.state_dir,
    ]
    payload = base_payload("UC02", "Render user service plan without installation", cmd)
    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr

    if proc.returncode == 0:
        try:
            service_payload = json.loads(proc.stdout)
            payload["service_payload"] = service_payload
            payload["ok"] = bool(service_payload.get("ok", False))
        except json.JSONDecodeError as exc:
            payload["ok"] = False
            payload["parse_error"] = str(exc)

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

