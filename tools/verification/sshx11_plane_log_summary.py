#!/usr/bin/env python3
from __future__ import annotations

"""Summarize control-plane and data-plane NDJSON logs for SSHX11 stack."""

import argparse
import json
from pathlib import Path
from typing import Any, Dict


def _read_ndjson(path: Path) -> list[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except Exception:
            continue
        if isinstance(rec, dict):
            rows.append(rec)
    return rows


def _count_events(rows: list[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in rows:
        ev = str(r.get("event", "unknown"))
        counts[ev] = counts.get(ev, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--control-log",
        type=Path,
        default=Path("verification_results/stack_audits/sshx11_control_plane_events.ndjson"),
    )
    parser.add_argument(
        "--data-log",
        type=Path,
        default=Path("verification_results/stack_audits/sshx11_data_plane_events.ndjson"),
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path("verification_results/runtime/sshx11_plane_state.json"),
    )
    parser.add_argument("--output", type=Path, default=Path("verification_results/stack_audits/sshx11_plane_log_summary.json"))
    args = parser.parse_args()

    control = _read_ndjson(args.control_log)
    data = _read_ndjson(args.data_log)
    state = {}
    if args.state_file.exists():
        try:
            payload = json.loads(args.state_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                state = payload
        except Exception:
            state = {}

    out = {
        "ok": True,
        "control_log": str(args.control_log),
        "data_log": str(args.data_log),
        "state_file": str(args.state_file),
        "control_event_count": len(control),
        "data_event_count": len(data),
        "control_events": _count_events(control),
        "data_events": _count_events(data),
        "current_state": state,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"ok={out['ok']}")
    print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
