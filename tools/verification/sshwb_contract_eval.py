#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from tools.verification import sshx11_remote_compat as remote_compat
except Exception:  # pragma: no cover - direct script execution path
    import sshx11_remote_compat as remote_compat

SUPPORTED_REMOTE_PLATFORMS = remote_compat.SUPPORTED_REMOTE_PLATFORMS
normalize_remote_platform = remote_compat.normalize_remote_platform


def parse_host_spec(host_spec: str) -> tuple[str, str]:
    token = str(host_spec or "").strip()
    if not token:
        raise ValueError("missing_host")
    if "=" in token:
        label, host = token.split("=", 1)
        host = host.strip()
        label = (label.strip() or host).strip()
    else:
        host = token
        label = token
    if not host:
        raise ValueError("missing_host")
    return label, host


def evaluate_case(case: dict) -> dict:
    case_id = str(case.get("id", "")).strip()
    user = str(case.get("user", "")).strip() or "root"
    try:
        label, host = parse_host_spec(str(case.get("host_spec", "")))
        target = f"{user}@{host}"
        return {
            "id": case_id,
            "normalized_platform": normalize_remote_platform(case.get("platform")),
            "label": label,
            "host": host,
            "user": user,
            "target": target,
            "ok": True,
            "error": "",
        }
    except Exception as exc:
        return {
            "id": case_id,
            "normalized_platform": normalize_remote_platform(case.get("platform")),
            "label": "",
            "host": "",
            "user": user,
            "target": "",
            "ok": False,
            "error": str(exc),
        }


def evaluate(payload: dict) -> dict:
    cases = payload.get("cases", [])
    out = [evaluate_case(case) for case in cases]
    return {"cases": out}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("/tmp/sshwb_contract_eval_python.json"))
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    out = evaluate(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

