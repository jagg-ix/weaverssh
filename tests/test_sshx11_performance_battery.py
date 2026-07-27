from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
VERIFICATION_DIR = ROOT / "tools" / "verification"
SOCKS_BENCH = VERIFICATION_DIR / "benchmark_sshx11_socks5_flows.py"
COMPARE_SCRIPT = VERIFICATION_DIR / "benchmark_compare.py"
FIXTURE_BASELINE = ROOT / "tests/fixtures/sshx11_perf_baseline.json"
FIXTURE_CURRENT_PASS = ROOT / "tests/fixtures/sshx11_perf_current_pass.json"
FIXTURE_CURRENT_REGRESSION = ROOT / "tests/fixtures/sshx11_perf_current_regression.json"


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, check=False)


def _copy_json(src: Path, dst: Path) -> None:
    payload = json.loads(src.read_text(encoding="utf-8"))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


@pytest.mark.sshx11
@pytest.mark.performance
def test_socks5_perf_dry_run_artifact_schema(tmp_path: Path) -> None:
    dry_run_out = tmp_path / "dry_run_current.json"
    assert SOCKS_BENCH.exists(), f"missing benchmark script: {SOCKS_BENCH}"
    proc = _run(
        [
            "python3",
            str(SOCKS_BENCH),
            "--mode",
            "mock",
            "--scenario",
            "smoke",
            "--dry-run",
            "--output",
            str(dry_run_out),
        ],
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert dry_run_out.exists(), "missing dry-run artifact"
    payload = json.loads(dry_run_out.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "dry_run"
    assert payload["battery_config"]["scenario"] == "smoke"
    assert payload["connection_accounting"]["connection_min_per_path"] > 0


@pytest.mark.sshx11
@pytest.mark.performance
def test_perf_parser_and_accounting_boundaries() -> None:
    spec = importlib.util.spec_from_file_location("socks_bench", str(SOCKS_BENCH))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    levels = module._parse_int_csv("1,2,4", minimum=1)
    assert levels == [1, 2, 4]
    bw_cases = module._parse_bw_cases("1024x8,2048x4")
    assert bw_cases == [(1024, 8), (2048, 4)]
    udp_cases = module._derive_udp_bw_cases([(16384, 32)], max_payload=1200)
    assert udp_cases[0][0] <= 1200
    assert udp_cases[0][1] >= 32

    acc = module._build_connection_accounting(
        latency_connect_count=12,
        latency_per_message_conn=False,
        rtt_cases_count=2,
        rtt_count_each=24,
        stream_cases_count=1,
        concurrency_levels=[2],
    )
    assert acc["connection_min_per_path"] == 17
    assert acc["connection_min_both_paths_direct_plus_socks"] == 34


@pytest.mark.sshx11
@pytest.mark.performance
def test_perf_compare_pass_and_archive_outputs(tmp_path: Path) -> None:
    archive_baseline = tmp_path / "baseline.json"
    archive_current = tmp_path / "current.json"
    archive_compare = tmp_path / "compare_report.json"
    assert COMPARE_SCRIPT.exists(), f"missing compare script: {COMPARE_SCRIPT}"
    assert FIXTURE_BASELINE.exists(), f"missing baseline fixture: {FIXTURE_BASELINE}"
    assert FIXTURE_CURRENT_PASS.exists(), f"missing current fixture: {FIXTURE_CURRENT_PASS}"

    _copy_json(FIXTURE_BASELINE, archive_baseline)
    _copy_json(FIXTURE_CURRENT_PASS, archive_current)
    archive_compare.unlink(missing_ok=True)

    proc = _run(
        [
            "python3",
            str(COMPARE_SCRIPT),
            "--baseline",
            str(archive_baseline),
            "--current",
            str(archive_current),
            "--output",
            str(archive_compare),
            "--require-metrics",
        ],
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert archive_compare.exists(), "missing compare report"
    payload = json.loads(archive_compare.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "pass"
    assert payload["compared_metric_count"] == 3
    assert payload["failures"] == []
    checks = {item["name"]: item for item in payload["structural_checks"]}
    assert checks["scenario_match"]["ok"] is True
    assert checks["connection_min_per_path_match"]["ok"] is True


@pytest.mark.sshx11
@pytest.mark.performance
def test_perf_compare_detects_regression(tmp_path: Path) -> None:
    assert FIXTURE_BASELINE.exists(), f"missing baseline fixture: {FIXTURE_BASELINE}"
    assert FIXTURE_CURRENT_REGRESSION.exists(), (
        f"missing regressed fixture: {FIXTURE_CURRENT_REGRESSION}"
    )
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current_regression.json"
    report = tmp_path / "compare_report.json"
    _copy_json(FIXTURE_BASELINE, baseline)
    _copy_json(FIXTURE_CURRENT_REGRESSION, current)

    proc = _run(
        [
            "python3",
            str(COMPARE_SCRIPT),
            "--baseline",
            str(baseline),
            "--current",
            str(current),
            "--output",
            str(report),
            "--require-metrics",
        ],
        cwd=ROOT,
    )
    assert proc.returncode != 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["status"] == "fail"
    failures = payload["failures"]
    assert any(str(item).startswith("metric_regression:") for item in failures)


@pytest.mark.sshx11
@pytest.mark.performance
def test_roundtrip_latency_under_load_produces_stable_metrics(tmp_path: Path) -> None:
    """Exercise RTT/connect paths with high call counts and validate metric shape."""
    out = tmp_path / "latency_load.json"
    proc = _run(
        [
            "python3",
            str(SOCKS_BENCH),
            "--mode",
            "mock",
            "--scenario",
            "latency",
            "--socks-port",
            "0",
            "--target-port",
            "0",
            "--output",
            str(out),
        ],
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "pass"
    assert payload["battery_config"]["scenario"] == "latency"

    # This scenario is intentionally load-heavy; enforce non-trivial socket volume.
    accounting = payload["connection_accounting"]
    assert accounting["connection_min_both_paths_direct_plus_socks"] >= 500
    assert accounting["max_parallel_connections_per_path"] >= 2

    connect_direct = payload["latency"]["connect_direct"]
    connect_socks = payload["latency"]["connect_socks"]
    assert connect_direct["count"] >= 60
    assert connect_socks["count"] >= 60
    assert connect_direct["p95_us"] > 0
    assert connect_socks["p95_us"] > 0

    rtt_cases = payload["latency"]["rtt_cases"]
    assert len(rtt_cases) >= 2
    for case in rtt_cases:
        assert case["count"] >= 100
        assert case["direct"]["p95_us"] > 0
        assert case["socks"]["p95_us"] > 0
        assert case["direct"]["count"] == case["count"]
        assert case["socks"]["count"] == case["count"]
        assert case["direct"]["errors"] == []
        assert case["socks"]["errors"] == []


@pytest.mark.sshx11
@pytest.mark.performance
def test_bandwidth_under_load_tracks_socket_concurrency_and_throughput(tmp_path: Path) -> None:
    """Exercise stream/concurrency throughput under load and validate outputs."""
    out = tmp_path / "bandwidth_load.json"
    proc = _run(
        [
            "python3",
            str(SOCKS_BENCH),
            "--mode",
            "mock",
            "--scenario",
            "bandwidth",
            "--socks-port",
            "0",
            "--target-port",
            "0",
            "--output",
            str(out),
        ],
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "pass"
    assert payload["battery_config"]["scenario"] == "bandwidth"

    accounting = payload["connection_accounting"]
    assert accounting["connection_min_both_paths_direct_plus_socks"] >= 150
    assert accounting["max_parallel_connections_per_path"] >= 4

    stream_cases = payload["bandwidth"]["stream_cases"]
    concurrency_cases = payload["bandwidth"]["concurrency_cases"]
    assert len(stream_cases) >= 2
    assert len(concurrency_cases) >= 2

    for case in stream_cases:
        assert case["direct"]["ok"] is True
        assert case["socks"]["ok"] is True
        assert case["direct"]["ops_failed"] == 0
        assert case["socks"]["ops_failed"] == 0
        assert case["direct"]["mbps"] > 0.0
        assert case["socks"]["mbps"] > 0.0

    for case in concurrency_cases:
        workers = int(case["workers"])
        assert workers >= 1
        assert case["direct"]["ok"] is True
        assert case["socks"]["ok"] is True
        assert case["direct"]["worker_result_count"] == workers
        assert case["socks"]["worker_result_count"] == workers
        assert case["direct"]["ops_failed"] == 0
        assert case["socks"]["ops_failed"] == 0
        assert case["direct"]["mbps"] > 0.0
        assert case["socks"]["mbps"] > 0.0
