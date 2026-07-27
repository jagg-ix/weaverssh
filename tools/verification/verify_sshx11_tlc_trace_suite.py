#!/usr/bin/env python3
from __future__ import annotations

"""Validate the weaverssh TLC trace-suite fixture against the verifier registry."""

import argparse
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_extension_set_tla as tla_verifier
DEFAULT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "sshx11_tlc_trace_suite.json"
DEFAULT_OUTPUT = REPO_ROOT / "verification_results" / "stack_audits" / "sshx11_tlc_trace_suite_validation.json"
REQUIRED_TRACE_KINDS = {"happy", "rejected", "failure"}
EXPECTED_RESULTS = {"success", "rejection", "fail_closed"}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _tuple_rows_from_tla(module_path: Path, name: str) -> list[tuple[str, ...]]:
    text = tla_verifier._read_tla(module_path)
    return tla_verifier._parse_tuple_set(tla_verifier._must_def(text, name))


def validate_trace_suite(fixture_path: Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    fixture = _load_json(fixture_path)
    errors: list[dict[str, Any]] = []
    targets = fixture.get("targets")
    if not isinstance(targets, list):
        targets = []
        errors.append({"kind": "targets_not_list"})

    by_target: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(targets):
        if not isinstance(row, dict):
            errors.append({"kind": "target_row_not_object", "index": idx})
            continue
        target = str(row.get("target", ""))
        if not target:
            errors.append({"kind": "target_missing_key", "index": idx})
            continue
        if target in by_target:
            errors.append({"kind": "duplicate_target", "target": target})
        by_target[target] = row

    expected_specs = dict(tla_verifier.TLC_TARGET_SPECS)
    expected_targets = set(expected_specs)
    observed_targets = set(by_target)
    for target in sorted(expected_targets - observed_targets):
        errors.append({"kind": "missing_fixture_target", "target": target})
    for target in sorted(observed_targets - expected_targets):
        errors.append({"kind": "unknown_fixture_target", "target": target})

    for target, spec in sorted(expected_specs.items()):
        row = by_target.get(target)
        if not row:
            continue
        module, cfg = spec
        if row.get("module") != module:
            errors.append({"kind": "module_mismatch", "target": target, "expected": module, "observed": row.get("module")})
        if row.get("cfg") != cfg:
            errors.append({"kind": "cfg_mismatch", "target": target, "expected": cfg, "observed": row.get("cfg")})
        for rel in (module, cfg):
            if not (tla_verifier.TLA_DIR / rel).exists():
                errors.append({"kind": "missing_tla_file", "target": target, "path": str(tla_verifier.TLA_DIR / rel)})
        traces = row.get("traces")
        if not isinstance(traces, list):
            errors.append({"kind": "traces_not_list", "target": target})
            continue
        kinds: set[str] = set()
        ids: set[str] = set()
        for t_idx, trace in enumerate(traces):
            if not isinstance(trace, dict):
                errors.append({"kind": "trace_not_object", "target": target, "index": t_idx})
                continue
            trace_id = str(trace.get("id", ""))
            kind = str(trace.get("kind", ""))
            expected_result = str(trace.get("expected_result", ""))
            if not trace_id:
                errors.append({"kind": "trace_missing_id", "target": target, "index": t_idx})
            if trace_id in ids:
                errors.append({"kind": "duplicate_trace_id", "target": target, "id": trace_id})
            ids.add(trace_id)
            if kind not in REQUIRED_TRACE_KINDS:
                errors.append({"kind": "trace_bad_kind", "target": target, "id": trace_id, "kind": kind})
            kinds.add(kind)
            if expected_result not in EXPECTED_RESULTS:
                errors.append({"kind": "trace_bad_expected_result", "target": target, "id": trace_id, "expected_result": expected_result})
            for field in ("description", "entry_state", "terminal_state"):
                if not str(trace.get(field, "")).strip():
                    errors.append({"kind": "trace_missing_field", "target": target, "id": trace_id, "field": field})
        for missing_kind in sorted(REQUIRED_TRACE_KINDS - kinds):
            errors.append({"kind": "missing_trace_kind", "target": target, "kind": missing_kind})

    trace_suite_tla = tla_verifier.TLA_DIR / "SSHX11TraceSuite.tla"
    tla_target_rows = _tuple_rows_from_tla(trace_suite_tla, "TraceTargetRows") if trace_suite_tla.exists() else []
    tla_fixture_rows = _tuple_rows_from_tla(trace_suite_tla, "TraceFixtureRows") if trace_suite_tla.exists() else []
    tla_targets = {row[0] for row in tla_target_rows if len(row) >= 1}
    if tla_targets != expected_targets:
        errors.append({"kind": "tla_target_rows_mismatch", "expected": sorted(expected_targets), "observed": sorted(tla_targets)})
    fixture_pairs = {(row[0], row[1]) for row in tla_fixture_rows if len(row) >= 2}
    for target in expected_targets:
        for kind in REQUIRED_TRACE_KINDS:
            if (target, kind) not in fixture_pairs:
                errors.append({"kind": "tla_missing_trace_kind", "target": target, "kind": kind})

    return {
        "ok": len(errors) == 0,
        "fixture": str(fixture_path),
        "target_count": len(by_target),
        "expected_target_count": len(expected_targets),
        "trace_count": sum(len(row.get("traces", [])) for row in by_target.values() if isinstance(row.get("traces"), list)),
        "required_trace_kinds": sorted(REQUIRED_TRACE_KINDS),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = validate_trace_suite(args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"ok={report['ok']}")
    print(f"output={args.output}")
    print(f"target_count={report['target_count']}")
    print(f"trace_count={report['trace_count']}")
    print(f"error_count={len(report['errors'])}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
