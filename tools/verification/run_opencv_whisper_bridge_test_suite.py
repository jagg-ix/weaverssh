#!/usr/bin/env python3
"""Run unit/integration tests for the OpenCV-Whisper-MCP bridge and emit JSON."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "verification_results" / "stack_audits" / "opencv_whisper_bridge_test_suite.json"
TEST_TARGET = "tests/test_opencv_whisper_bridge.py"


def _mode_expr(mode: str) -> str:
    m = str(mode or "all").strip().lower()
    if m == "unit":
        return "not bridge_dry_run_smoke_events and not bridge_mcp_stdio_roundtrip"
    if m == "integration":
        return "bridge_dry_run_smoke_events or bridge_mcp_stdio_roundtrip"
    return ""


def run_suite(*, mode: str, extra_pytest_args: list[str]) -> dict[str, Any]:
    cmd = [sys.executable, "-m", "pytest", "-q", TEST_TARGET]
    expr = _mode_expr(mode)
    if expr:
        cmd.extend(["-k", expr])
    cmd.extend(list(extra_pytest_args))
    cp = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, capture_output=True)
    return {
        "ok": bool(cp.returncode == 0),
        "returncode": int(cp.returncode),
        "command": cmd,
        "stdout": cp.stdout,
        "stderr": cp.stderr,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("all", "unit", "integration"), default="all")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--pytest-arg", action="append", default=[], help="Additional pytest arg; repeatable.")
    args = ap.parse_args(argv)

    result = run_suite(mode=str(args.mode), extra_pytest_args=[str(x) for x in args.pytest_arg])
    artifact = {
        "validator": "opencv_whisper_bridge_test_suite",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": str(args.mode),
        "result": result,
        "pass": bool(result["ok"]),
        "status": "pass" if bool(result["ok"]) else "fail",
    }

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(artifact, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"status={artifact['status']}")
    print(f"pass={artifact['pass']}")
    print(f"output={out_path}")
    return 0 if artifact["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
