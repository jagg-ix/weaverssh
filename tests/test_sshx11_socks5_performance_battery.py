from __future__ import annotations

from pathlib import Path
import importlib.util
import itertools
import json
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "benchmark_sshx11_socks5_flows.py"
SPEC = importlib.util.spec_from_file_location("benchmark_sshx11_socks5_flows", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf)


def test_socks5_performance_battery_help() -> None:
    proc = subprocess.run(["python3", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "--mode" in proc.stdout
    assert "--latency-connect-count" in proc.stdout
    assert "--latency-rtt-count" in proc.stdout
    assert "--bandwidth-cases" in proc.stdout
    assert "--concurrency-levels" in proc.stdout
    assert "--udp-enable" in proc.stdout
    assert "--udp-target-port" in proc.stdout


def test_socks5_performance_battery_mock_smoke_dry_run(tmp_path: Path) -> None:
    output = tmp_path / "socks5_perf_smoke.json"
    proc = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--mode",
            "mock",
            "--socks-port",
            "0",
            "--target-port",
            "0",
            "--scenario",
            "smoke",
            "--dry-run",
            "--latency-connect-count",
            "8",
            "--latency-rtt-count",
            "12",
            "--latency-sizes",
            "64,256",
            "--bandwidth-cases",
            "8192x12",
            "--concurrency-levels",
            "1,2",
            "--concurrency-chunk-size",
            "8192",
            "--concurrency-chunks-per-worker",
            "8",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "dry_run"
    assert payload["mode"] == "mock"
    assert "battery_config" in payload
    assert payload["battery_config"]["latency_connect_count"] >= 1
    assert len(payload["battery_config"]["latency_sizes"]) >= 1
    assert len(payload["battery_config"]["bandwidth_cases"]) >= 1
    assert len(payload["battery_config"]["concurrency_levels"]) >= 1
    assert payload["connection_accounting"]["max_parallel_connections_per_path"] >= 1
    assert payload["connection_accounting"]["connection_min_per_path"] >= 1


def test_udp_bw_cases_default_derives_safe_payload_sizes() -> None:
    cases = perf._derive_udp_bw_cases([(16384, 32), (1200, 8), (512, 4)])
    assert cases[0][0] == perf.DEFAULT_SAFE_UDP_PAYLOAD_BYTES
    assert cases[0][1] > 32
    assert cases[1] == (1200, 8)
    assert cases[2] == (512, 4)


def test_socks5_concurrency_aggregation_parallel_workers_success(monkeypatch) -> None:
    calls: list[tuple[int, int]] = []

    def _fake_stream(
        *,
        connect_fn,
        chunk_size: int,
        chunk_count: int,
        warmup_chunks: int,
    ) -> dict:
        del connect_fn, warmup_chunks
        calls.append((int(chunk_size), int(chunk_count)))
        bytes_total = int(chunk_size) * int(chunk_count)
        return {
            "ok": True,
            "bytes_total": bytes_total,
            "duration_s": 0.01,
            "bytes_per_s": float(bytes_total / 0.01),
            "mbps": float((bytes_total * 8.0) / (0.01 * 1_000_000.0)),
            "ops_ok": int(chunk_count),
            "ops_failed": 0,
            "errors": [],
            "chunk_size": int(chunk_size),
            "chunk_count": int(chunk_count),
        }

    monkeypatch.setattr(perf, "_measure_stream_bandwidth", _fake_stream)
    out = perf._measure_concurrency_bandwidth(
        connect_fn=lambda: None,
        workers=4,
        chunk_size=4096,
        chunks_per_worker=10,
        warmup_chunks=1,
    )

    assert len(calls) == 4
    assert out["worker_result_count"] == 4
    assert out["workers"] == 4
    assert out["ops_ok"] == 40
    assert out["ops_failed"] == 0
    assert out["ok"] is True
    assert out["bytes_total"] == 4 * 4096 * 10


def test_socks5_concurrency_aggregation_parallel_workers_failure(monkeypatch) -> None:
    seq = itertools.count()

    def _fake_stream(
        *,
        connect_fn,
        chunk_size: int,
        chunk_count: int,
        warmup_chunks: int,
    ) -> dict:
        del connect_fn, chunk_size, warmup_chunks
        idx = next(seq)
        if idx == 2:
            return {
                "ok": False,
                "bytes_total": 0,
                "duration_s": 0.01,
                "bytes_per_s": 0.0,
                "mbps": 0.0,
                "ops_ok": 0,
                "ops_failed": int(chunk_count),
                "errors": ["simulated_failure"],
                "chunk_size": 0,
                "chunk_count": int(chunk_count),
            }
        return {
            "ok": True,
            "bytes_total": int(chunk_count) * 1024,
            "duration_s": 0.01,
            "bytes_per_s": float((int(chunk_count) * 1024) / 0.01),
            "mbps": 1.0,
            "ops_ok": int(chunk_count),
            "ops_failed": 0,
            "errors": [],
            "chunk_size": 1024,
            "chunk_count": int(chunk_count),
        }

    monkeypatch.setattr(perf, "_measure_stream_bandwidth", _fake_stream)
    out = perf._measure_concurrency_bandwidth(
        connect_fn=lambda: None,
        workers=4,
        chunk_size=1024,
        chunks_per_worker=6,
        warmup_chunks=1,
    )

    assert out["worker_result_count"] == 4
    assert out["ops_ok"] == 18
    assert out["ops_failed"] == 6
    assert out["ok"] is False
    assert any("worker=2:" in err for err in out["worker_errors"])
