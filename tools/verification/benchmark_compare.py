#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = ROOT / "artifacts/perf/baseline.json"
DEFAULT_CURRENT = ROOT / "artifacts/perf/current.json"
DEFAULT_OUTPUT = ROOT / "artifacts/perf/compare_report.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _extract_scenario(payload: dict[str, Any]) -> str | None:
    battery = payload.get("battery_config")
    if isinstance(battery, dict):
        scenario = battery.get("scenario")
        if isinstance(scenario, str) and scenario.strip():
            return scenario.strip()
    return None


def _extract_connection_min_per_path(payload: dict[str, Any]) -> int | None:
    accounting = payload.get("connection_accounting")
    if not isinstance(accounting, dict):
        return None
    raw = accounting.get("connection_min_per_path")
    value = _as_float(raw)
    if value is None:
        return None
    return int(value)


def _extract_connect_p95_us(payload: dict[str, Any]) -> float | None:
    latency = payload.get("latency")
    if not isinstance(latency, dict):
        return None
    connect_socks = latency.get("connect_socks")
    if not isinstance(connect_socks, dict):
        return None
    return _as_float(connect_socks.get("p95_us"))


def _extract_rtt_p95_us_worst(payload: dict[str, Any]) -> float | None:
    latency = payload.get("latency")
    if not isinstance(latency, dict):
        return None
    rtt_cases = latency.get("rtt_cases")
    if not isinstance(rtt_cases, list):
        return None
    values: list[float] = []
    for case in rtt_cases:
        if not isinstance(case, dict):
            continue
        socks = case.get("socks")
        if not isinstance(socks, dict):
            continue
        p95 = _as_float(socks.get("p95_us"))
        if p95 is not None:
            values.append(p95)
    if not values:
        return None
    return max(values)


def _extract_stream_min_throughput_mbps(payload: dict[str, Any]) -> float | None:
    bandwidth = payload.get("bandwidth")
    if not isinstance(bandwidth, dict):
        return None
    stream_cases = bandwidth.get("stream_cases")
    if not isinstance(stream_cases, list):
        return None
    values: list[float] = []
    for case in stream_cases:
        if not isinstance(case, dict):
            continue
        socks = case.get("socks")
        if not isinstance(socks, dict):
            continue
        mbps = _as_float(socks.get("mbps"))
        if mbps is not None:
            values.append(mbps)
    if not values:
        return None
    return min(values)


def _compare_metric(
    *,
    metric: str,
    baseline_value: float | None,
    current_value: float | None,
    threshold_pct: float,
    higher_is_worse: bool,
) -> dict[str, Any]:
    if baseline_value is None or current_value is None:
        return {
            "metric": metric,
            "status": "skipped",
            "reason": "metric_missing",
            "baseline": baseline_value,
            "current": current_value,
            "threshold_pct": float(threshold_pct),
        }
    if baseline_value <= 0:
        return {
            "metric": metric,
            "status": "fail",
            "reason": "invalid_baseline_nonpositive",
            "baseline": baseline_value,
            "current": current_value,
            "threshold_pct": float(threshold_pct),
            "regression_pct": None,
        }

    if higher_is_worse:
        regression_pct = ((current_value - baseline_value) / baseline_value) * 100.0
    else:
        regression_pct = ((baseline_value - current_value) / baseline_value) * 100.0
    ok = regression_pct <= float(threshold_pct)
    return {
        "metric": metric,
        "status": "pass" if ok else "fail",
        "direction": "higher_is_worse" if higher_is_worse else "lower_is_worse",
        "baseline": baseline_value,
        "current": current_value,
        "threshold_pct": float(threshold_pct),
        "regression_pct": regression_pct,
    }


def _build_structural_checks(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    baseline_scenario = _extract_scenario(baseline)
    current_scenario = _extract_scenario(current)
    if baseline_scenario and current_scenario:
        checks.append(
            {
                "name": "scenario_match",
                "baseline": baseline_scenario,
                "current": current_scenario,
                "ok": baseline_scenario == current_scenario,
            }
        )

    baseline_conn_min = _extract_connection_min_per_path(baseline)
    current_conn_min = _extract_connection_min_per_path(current)
    if baseline_conn_min is not None and current_conn_min is not None:
        checks.append(
            {
                "name": "connection_min_per_path_match",
                "baseline": baseline_conn_min,
                "current": current_conn_min,
                "ok": baseline_conn_min == current_conn_min,
            }
        )
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--current", type=Path, default=DEFAULT_CURRENT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-connect-p95-regression-pct", type=float, default=15.0)
    parser.add_argument("--max-rtt-p95-regression-pct", type=float, default=15.0)
    parser.add_argument("--max-throughput-drop-pct", type=float, default=10.0)
    parser.add_argument("--ignore-baseline-thresholds", action="store_true", default=False)
    parser.add_argument("--require-metrics", action="store_true", default=False)
    args = parser.parse_args()

    baseline_path = args.baseline.expanduser().resolve()
    current_path = args.current.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    baseline_payload: dict[str, Any] = {}
    current_payload: dict[str, Any] = {}

    if not baseline_path.exists():
        failures.append(f"missing_baseline:{baseline_path}")
    if not current_path.exists():
        failures.append(f"missing_current:{current_path}")

    if not failures:
        try:
            baseline_payload = _load_json(baseline_path)
        except Exception as exc:  # pragma: no cover
            failures.append(f"baseline_json_parse_error:{exc}")
        try:
            current_payload = _load_json(current_path)
        except Exception as exc:  # pragma: no cover
            failures.append(f"current_json_parse_error:{exc}")

    thresholds = {
        "max_connect_p95_regression_pct": float(args.max_connect_p95_regression_pct),
        "max_rtt_p95_regression_pct": float(args.max_rtt_p95_regression_pct),
        "max_throughput_drop_pct": float(args.max_throughput_drop_pct),
    }
    baseline_thresholds = baseline_payload.get("regression_thresholds")
    if isinstance(baseline_thresholds, dict) and not bool(args.ignore_baseline_thresholds):
        for key in list(thresholds):
            parsed = _as_float(baseline_thresholds.get(key))
            if parsed is not None:
                thresholds[key] = float(parsed)

    structural_checks = _build_structural_checks(baseline_payload, current_payload)
    for check in structural_checks:
        if not bool(check.get("ok")):
            failures.append(
                f"structural_check_failed:{check.get('name')}:{check.get('baseline')}!={check.get('current')}"
            )

    comparisons = [
        _compare_metric(
            metric="connect_socks_p95_us",
            baseline_value=_extract_connect_p95_us(baseline_payload),
            current_value=_extract_connect_p95_us(current_payload),
            threshold_pct=thresholds["max_connect_p95_regression_pct"],
            higher_is_worse=True,
        ),
        _compare_metric(
            metric="rtt_socks_p95_us_worst",
            baseline_value=_extract_rtt_p95_us_worst(baseline_payload),
            current_value=_extract_rtt_p95_us_worst(current_payload),
            threshold_pct=thresholds["max_rtt_p95_regression_pct"],
            higher_is_worse=True,
        ),
        _compare_metric(
            metric="stream_socks_throughput_mbps_min",
            baseline_value=_extract_stream_min_throughput_mbps(baseline_payload),
            current_value=_extract_stream_min_throughput_mbps(current_payload),
            threshold_pct=thresholds["max_throughput_drop_pct"],
            higher_is_worse=False,
        ),
    ]
    compared_count = 0
    for comp in comparisons:
        status = str(comp.get("status"))
        if status == "fail":
            failures.append(f"metric_regression:{comp.get('metric')}")
        if status in {"pass", "fail"}:
            compared_count += 1

    if bool(args.require_metrics) and compared_count == 0:
        failures.append("no_comparable_metrics")

    ok = len(failures) == 0
    report = {
        "ok": ok,
        "status": "pass" if ok else "fail",
        "generated_at_unix": int(time.time()),
        "baseline": str(baseline_path),
        "current": str(current_path),
        "output": str(output_path),
        "thresholds": thresholds,
        "structural_checks": structural_checks,
        "comparisons": comparisons,
        "compared_metric_count": compared_count,
        "failures": failures,
        "metadata": {
            "baseline_status": baseline_payload.get("status"),
            "current_status": current_payload.get("status"),
            "baseline_scenario": _extract_scenario(baseline_payload),
            "current_scenario": _extract_scenario(current_payload),
        },
    }
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"ok={report['ok']}")
    print(f"status={report['status']}")
    print(f"output={output_path}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
