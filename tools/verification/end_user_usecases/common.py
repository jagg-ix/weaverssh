#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]


def run_command(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def emit(payload: dict[str, Any], output_path: Path | None = None) -> int:
    if output_path is not None:
        write_json_file(output_path, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


def base_payload(case_id: str, title: str, cmd: Sequence[str]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "title": title,
        "ok": False,
        "generated_at_unix": int(time.time()),
        "repo_root": str(REPO_ROOT),
        "command": list(cmd),
    }

