from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "benchmark_sshx11_transport_profiles.py"


def test_transport_profile_benchmark_managed_service(tmp_path: Path) -> None:
    output = tmp_path / "bench.json"
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--host",
        "127.0.0.1",
        "--control-port",
        "18111",
        "--bulk-port",
        "19220",
        "--realtime-port",
        "19221",
        "--managed-service",
        "--realtime-count",
        "12",
        "--realtime-size",
        "128",
        "--bulk-count",
        "8",
        "--bulk-size",
        "2048",
        "--output",
        str(output),
    ]
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    if proc.returncode != 0 and "Operation not permitted" in (proc.stdout + proc.stderr):
        pytest.skip("local socket bind not permitted in this environment")
    assert proc.returncode == 0, proc.stderr + "\n" + proc.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["realtime_metrics"]["count_ok"] == 12
    assert payload["bulk_metrics"]["count_ok"] == 8
    assert payload["realtime_metrics"]["latency_us_p95"] >= 0
    assert payload["bulk_metrics"]["bytes_per_s"] > 0
