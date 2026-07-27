#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.end_user_usecases.common import base_payload, emit, run_command


def _summary_counts(stdout: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for key in counts:
        match = re.search(rf"(\d+)\s+{key}", stdout)
        if match:
            counts[key] = int(match.group(1))
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Use case UC12: run live SSHX11 multi-hop system integration test."
    )
    parser.add_argument("--junit-output", default="/tmp/sshx11_multihop_chain_system.junit.xml")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    junit_output = Path(args.junit_output).expanduser()
    cmd = [
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_sshx11_multihop_chain_system.py",
        "--junitxml",
        str(junit_output),
    ]
    payload = base_payload("UC12", "Run SSHX11 multi-hop chain system test", cmd)
    payload["junit_output"] = str(junit_output)

    proc = run_command(cmd)
    payload["returncode"] = proc.returncode
    payload["stdout"] = proc.stdout
    payload["stderr"] = proc.stderr
    payload["summary_counts"] = _summary_counts(proc.stdout)

    # pytest returns 0 for all-pass and all-skipped, which is acceptable here.
    payload["ok"] = bool(proc.returncode == 0 and junit_output.exists())

    output = Path(args.output).expanduser() if args.output else None
    return emit(payload, output)


if __name__ == "__main__":
    raise SystemExit(main())

