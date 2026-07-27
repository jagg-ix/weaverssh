#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = ROOT / "tests/fixtures/sshx11_contract_cases.json"
DEFAULT_OUTPUT = ROOT / "artifacts/contracts/drift_report.json"
PY_EVAL = ROOT / "tools/verification/sshwb_contract_eval.py"
GO_MOD_ROOT = ROOT / "tools/verification/go/sshwb"


def _run(cmd: list[str], cwd: Path, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, check=False, env=env)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _diff_cases(py_cases: list[dict[str, Any]], go_cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id_py = {str(c.get("id", "")): c for c in py_cases}
    by_id_go = {str(c.get("id", "")): c for c in go_cases}
    ids = sorted(set(by_id_py) | set(by_id_go))
    mismatches: list[dict[str, Any]] = []
    for case_id in ids:
        if case_id not in by_id_py:
            mismatches.append({"id": case_id, "kind": "missing_in_python"})
            continue
        if case_id not in by_id_go:
            mismatches.append({"id": case_id, "kind": "missing_in_go"})
            continue
        py_case = by_id_py[case_id]
        go_case = by_id_go[case_id]
        if py_case == go_case:
            continue
        keys = sorted(set(py_case) | set(go_case))
        field_drift = []
        for key in keys:
            if py_case.get(key) != go_case.get(key):
                field_drift.append(
                    {"field": key, "python": py_case.get(key), "go": go_case.get(key)}
                )
        mismatches.append({"id": case_id, "kind": "field_mismatch", "fields": field_drift})
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--strict", action="store_true", default=False)
    args = parser.parse_args()

    fixture = args.fixture.expanduser().resolve()
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if not fixture.exists():
        payload = {
            "ok": False,
            "status": "failed",
            "error": "missing_fixture",
            "fixture": str(fixture),
        }
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 2

    py_tmp = Path(tempfile.gettempdir()) / "sshwb_contract_eval_python_tmp.json"
    py_tmp.unlink(missing_ok=True)
    py_proc = _run(
        [sys.executable, str(PY_EVAL), "--input", str(fixture), "--output", str(py_tmp)],
        cwd=ROOT,
    )

    go_env = os.environ.copy()
    go_env["GOCACHE"] = str(Path(tempfile.gettempdir()) / "go-build-cache")
    go_proc = _run(
        ["go", "run", "./cmd/contracteval", "--input", str(fixture)],
        cwd=GO_MOD_ROOT,
        env=go_env,
    )

    py_payload: dict[str, Any] | None = None
    go_payload: dict[str, Any] | None = None
    load_errors: list[str] = []

    if py_proc.returncode == 0 and py_tmp.exists():
        try:
            py_payload = _load_json(py_tmp)
        except Exception as exc:  # pragma: no cover
            load_errors.append(f"python_json_parse_error:{exc}")
    else:
        load_errors.append("python_eval_failed")

    if go_proc.returncode == 0:
        try:
            go_payload = json.loads(go_proc.stdout)
        except Exception as exc:  # pragma: no cover
            load_errors.append(f"go_json_parse_error:{exc}")
    else:
        load_errors.append("go_eval_failed")

    mismatches: list[dict[str, Any]] = []
    py_cases = []
    go_cases = []
    if py_payload and go_payload:
        py_cases = list(py_payload.get("cases", []))
        go_cases = list(go_payload.get("cases", []))
        mismatches = _diff_cases(py_cases, go_cases)

    ok = (
        py_proc.returncode == 0
        and go_proc.returncode == 0
        and len(load_errors) == 0
        and len(mismatches) == 0
    )
    report = {
        "ok": bool(ok),
        "status": "pass" if ok else "fail",
        "generated_at_unix": int(time.time()),
        "fixture": str(fixture),
        "python_eval": {
            "returncode": int(py_proc.returncode),
            "stdout_excerpt": py_proc.stdout[-500:],
            "stderr_excerpt": py_proc.stderr[-500:],
            "artifact": str(py_tmp),
            "case_count": len(py_cases),
        },
        "go_eval": {
            "returncode": int(go_proc.returncode),
            "stdout_excerpt": go_proc.stdout[-500:],
            "stderr_excerpt": go_proc.stderr[-500:],
            "case_count": len(go_cases),
        },
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "load_errors": load_errors,
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if args.strict and not ok:
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
