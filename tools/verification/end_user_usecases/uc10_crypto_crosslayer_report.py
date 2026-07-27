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
    parser = argparse.ArgumentParser(description="Use case UC10: generate cross-layer crypto contract reports.")
    parser.add_argument("--report-output", default="/tmp/sshx11_crypto_crosslayer_reverse.json")
    parser.add_argument("--markdown-output", default="/tmp/sshx11_crypto_crosslayer_reverse.md")
    parser.add_argument("--interaction-json", default="/tmp/sshx11_crypto_interaction.json")
    parser.add_argument("--interaction-md", default="/tmp/sshx11_crypto_interaction.md")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    report_output = Path(args.report_output).expanduser()
    markdown_output = Path(args.markdown_output).expanduser()
    interaction_json = Path(args.interaction_json).expanduser()
    interaction_md = Path(args.interaction_md).expanduser()
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/verification/verify_sshx11_crypto_crosslayer_reverse.py"),
        "--skip-runtime-crosscheck",
        "--output-json",
        str(report_output),
        "--output-md",
        str(markdown_output),
        "--interaction-json",
        str(interaction_json),
        "--interaction-md",
        str(interaction_md),
    ]
    payload = base_payload("UC10", "Cross-layer crypto validation and interaction reports", cmd)
    payload["report_output"] = str(report_output)
    payload["markdown_output"] = str(markdown_output)
    payload["interaction_json"] = str(interaction_json)
    payload["interaction_md"] = str(interaction_md)

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

