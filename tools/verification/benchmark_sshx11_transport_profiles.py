#!/usr/bin/env python3
from __future__ import annotations

"""Benchmark SSHX11 transport profiles (realtime vs bulk) with dynamic buffers."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request


REPO_ROOT = Path(__file__).resolve().parents[2]


def _post(base: str, path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read()
    out = json.loads(raw.decode("utf-8"))
    return out if isinstance(out, dict) else {"ok": False}


def _get(base: str, path: str) -> dict:
    req = urllib.request.Request(f"{base}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read()
    out = json.loads(raw.decode("utf-8"))
    return out if isinstance(out, dict) else {"ok": False}


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def _pctl(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    idx = int(max(0, min(len(s) - 1, round((len(s) - 1) * float(q)))))
    return int(s[idx])


def _measure(host: str, port: int, payload: bytes, count: int, per_packet_retries: int) -> dict:
    lat_us: list[int] = []
    failures: list[str] = []
    total_bytes = 0
    t0 = time.perf_counter()
    retries = max(0, int(per_packet_retries))
    for i in range(max(0, int(count))):
        last_error = "unknown"
        done = False
        for attempt in range(retries + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            try:
                a0 = time.perf_counter_ns()
                s.connect((host, int(port)))
                s.sendall(payload)
                chunks: list[bytes] = []
                total = 0
                blocked = False
                while total < len(payload):
                    part = s.recv(min(65535, len(payload) - total))
                    if not part:
                        break
                    chunks.append(part)
                    total += len(part)
                    if part == b"BLOCKED\n" or b"BLOCKED\n" in part:
                        blocked = True
                        break
                got = b"".join(chunks)
                a1 = time.perf_counter_ns()
                if blocked:
                    last_error = "blocked"
                    continue
                if got != payload:
                    last_error = f"mismatch:{got[:16]!r}"
                    continue
                total_bytes += len(payload)
                lat_us.append(int(max(0, (a1 - a0) // 1000)))
                done = True
                break
            except Exception as exc:
                last_error = f"socket_error:{exc}"
                continue
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        if not done:
            failures.append(f"idx={i}:{last_error}")
    t1 = time.perf_counter()
    duration_s = max(1e-9, float(t1 - t0))
    packets = len(lat_us)
    return {
        "ok": len(failures) == 0 and packets == int(count),
        "count_requested": int(count),
        "count_ok": packets,
        "count_failed": len(failures),
        "failures": failures[:10],
        "bytes_total": int(total_bytes),
        "duration_s": duration_s,
        "packets_per_s": float(packets / duration_s),
        "bytes_per_s": float(total_bytes / duration_s),
        "latency_us_min": int(min(lat_us) if lat_us else 0),
        "latency_us_p50": int(_pctl(lat_us, 0.50)),
        "latency_us_p95": int(_pctl(lat_us, 0.95)),
        "latency_us_max": int(max(lat_us) if lat_us else 0),
        "latency_us_avg": float((sum(lat_us) / packets) if packets > 0 else 0.0),
    }


def _configure(base: str, args: argparse.Namespace) -> list[dict]:
    steps: list[dict] = []
    sequence = [
        ("reset", {}),
        ("start_session", {"session_id": "bench-session"}),
        ("request_x11_forward", {"mode": "X"}),
        ("set_mit_cookie_generated", {"value": True}),
        ("set_xauth_invoked", {"value": True}),
        ("set_proxy_cookie_issued", {"value": True}),
        ("set_client_cookie_checked", {"value": True}),
        ("set_proxy_cookie_verified", {"value": True}),
        ("set_websocket_ready", {"value": True}),
        ("set_l2_required", {"value": bool(args.l2_required)}),
        ("set_l2_ready", {"value": (not args.l2_required)}),
        ("sync_buffers", {"ssh_buffer_kb": 256, "x11_buffer_kb": 256, "ws_buffer_kb": 256}),
        ("set_transport_mode", {"value": str(args.transport_mode)}),
        ("set_transport_route_policy", {"value": str(args.route_policy)}),
        ("set_transport_auto_realtime_max_bytes", {"value": int(args.auto_realtime_max_bytes)}),
        (
            "set_transport_buffers",
            {
                "realtime_buffer_kb": int(args.realtime_buffer_kb),
                "bulk_buffer_kb": int(args.bulk_buffer_kb),
            },
        ),
        ("set_relay_enabled", {"value": True}),
    ]
    for cmd, a in sequence:
        path = "/sync-buffers" if cmd == "sync_buffers" else "/command"
        payload = a if cmd == "sync_buffers" else {"command": cmd, "args": a}
        result = _post(base, path, payload)
        steps.append({"name": cmd, "result": result})
    return steps


def _apply_scenario(args: argparse.Namespace) -> argparse.Namespace:
    scenario = str(getattr(args, "scenario", "mixed")).strip().lower()
    if scenario == "realtime_optimized":
        args.transport_mode = "dual"
        args.route_policy = "realtime"
        args.realtime_buffer_kb = min(int(args.realtime_buffer_kb), 64)
        args.bulk_buffer_kb = max(int(args.bulk_buffer_kb), 1024)
        args.auto_realtime_max_bytes = max(int(args.auto_realtime_max_bytes), 8192)
        return args
    if scenario == "bulk_optimized":
        args.transport_mode = "dual"
        args.route_policy = "bulk"
        args.realtime_buffer_kb = min(int(args.realtime_buffer_kb), 64)
        args.bulk_buffer_kb = max(int(args.bulk_buffer_kb), 2048)
        args.auto_realtime_max_bytes = max(1, min(int(args.auto_realtime_max_bytes), 1024))
        return args
    # mixed (default)
    args.transport_mode = str(args.transport_mode)
    args.route_policy = str(args.route_policy)
    return args


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--control-port", type=int, default=8101)
    p.add_argument("--bulk-port", type=int, default=19090)
    p.add_argument("--realtime-port", type=int, default=19091)
    p.add_argument("--managed-service", action="store_true")
    p.add_argument("--l2-required", action="store_true")
    p.add_argument("--scenario", choices=["mixed", "realtime_optimized", "bulk_optimized"], default="mixed")
    p.add_argument("--transport-mode", choices=["single", "dual"], default="dual")
    p.add_argument("--route-policy", choices=["auto", "realtime", "bulk"], default="auto")
    p.add_argument("--auto-realtime-max-bytes", type=int, default=4096)
    p.add_argument("--realtime-buffer-kb", type=int, default=64)
    p.add_argument("--bulk-buffer-kb", type=int, default=1024)
    p.add_argument("--realtime-count", type=int, default=200)
    p.add_argument("--realtime-size", type=int, default=128)
    p.add_argument("--bulk-count", type=int, default=80)
    p.add_argument("--bulk-size", type=int, default=65536)
    p.add_argument("--per-packet-retries", type=int, default=2)
    p.add_argument(
        "--output",
        type=Path,
        default=Path("verification_results/stack_audits/sshx11_transport_profile_benchmark.json"),
    )
    return p.parse_args()


def main() -> int:
    args = _apply_scenario(parse_args())
    svc_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "verification" / "sshx11_plane_service.py"),
        "--host",
        str(args.host),
        "--control-port",
        str(args.control_port),
        "--data-port",
        str(args.bulk_port),
        "--realtime-port",
        str(args.realtime_port),
    ]
    started = False
    if args.managed_service:
        rc, out = _run_cmd(svc_cmd + ["start"])
        started = rc == 0
        if not started:
            print(out)
            return 2
        time.sleep(0.5)

    base = f"http://{args.host}:{args.control_port}"
    try:
        health = _get(base, "/health")
        config_steps = _configure(base, args)
        policy = _get(base, "/policy")
        route_small = _get(base, f"/transport-route?bytes={int(args.realtime_size)}&hint=")
        route_large = _get(base, f"/transport-route?bytes={int(args.bulk_size)}&hint=")

        rt_payload = b"r" * max(1, int(args.realtime_size))
        bulk_payload = b"b" * max(1, int(args.bulk_size))
        rt_metrics = _measure(
            str(args.host),
            int(args.realtime_port),
            rt_payload,
            int(args.realtime_count),
            int(args.per_packet_retries),
        )
        bulk_metrics = _measure(
            str(args.host),
            int(args.bulk_port),
            bulk_payload,
            int(args.bulk_count),
            int(args.per_packet_retries),
        )
        state = _get(base, "/state")
        ok = bool(health.get("ok")) and bool(policy.get("relay_allowed")) and bool(rt_metrics.get("ok")) and bool(
            bulk_metrics.get("ok")
        )
        out = {
            "ok": ok,
            "host": str(args.host),
            "control_port": int(args.control_port),
            "bulk_port": int(args.bulk_port),
            "realtime_port": int(args.realtime_port),
            "policy": policy,
            "transport_route_small": route_small,
            "transport_route_large": route_large,
            "scenario_config": {
                "scenario": str(args.scenario),
                "transport_mode": str(args.transport_mode),
                "route_policy": str(args.route_policy),
                "auto_realtime_max_bytes": int(args.auto_realtime_max_bytes),
                "realtime_buffer_kb": int(args.realtime_buffer_kb),
                "bulk_buffer_kb": int(args.bulk_buffer_kb),
                "realtime_count": int(args.realtime_count),
                "realtime_size": int(args.realtime_size),
                "bulk_count": int(args.bulk_count),
                "bulk_size": int(args.bulk_size),
                "per_packet_retries": int(args.per_packet_retries),
            },
            "health": health,
            "config_steps": config_steps,
            "realtime_metrics": rt_metrics,
            "bulk_metrics": bulk_metrics,
            "state": state,
        }
    finally:
        if args.managed_service and started:
            _run_cmd(svc_cmd + ["stop"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"ok={out['ok']}")
    print(f"output={args.output}")
    return 0 if bool(out["ok"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
