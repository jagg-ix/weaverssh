#!/usr/bin/env python3
from __future__ import annotations

"""Run a profile-routed transfer session using /transport-route for each packet."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


def _get(base: str, path: str) -> dict:
    req = urllib.request.Request(f"{base}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read()
    payload = json.loads(raw.decode("utf-8"))
    return payload if isinstance(payload, dict) else {"ok": False}


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
    data = json.loads(raw.decode("utf-8"))
    return data if isinstance(data, dict) else {"ok": False}


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def _chunk_bytes(data: bytes, n: int) -> list[bytes]:
    n = max(1, int(n))
    return [data[i : i + n] for i in range(0, len(data), n)]


def _hint_for_packet(
    idx: int,
    packet: bytes,
    *,
    hint_mode: str,
    hint_threshold: int,
) -> str:
    mode = str(hint_mode or "").strip().lower()
    if mode == "alternating":
        return "realtime" if (idx % 2 == 0) else "bulk"
    if mode == "realtime_small":
        return "realtime" if len(packet) <= int(hint_threshold) else ""
    if mode == "bulk_large":
        return "bulk" if len(packet) >= int(hint_threshold) else ""
    return ""


def _relay_probe(host: str, port: int, payload: bytes) -> tuple[bool, str, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        t0 = time.perf_counter_ns()
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
        echoed = b"".join(chunks)
        t1 = time.perf_counter_ns()
        rtt_us = int(max(0, (t1 - t0) // 1000))
        if blocked:
            return False, "blocked", rtt_us
        if echoed == payload:
            return True, "echo_ok", rtt_us
        return False, f"mismatch:{echoed[:32]!r}", rtt_us
    except Exception as exc:
        return False, f"socket_error:{exc}", 0
    finally:
        try:
            s.close()
        except Exception:
            pass


def _configure_ready_state(base: str, args: argparse.Namespace) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    sequence = [
        ("start_session", {"session_id": "profile-routed-session"}),
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
        ("set_transport_buffers", {"realtime_buffer_kb": int(args.realtime_buffer_kb), "bulk_buffer_kb": int(args.bulk_buffer_kb)}),
        ("set_relay_enabled", {"value": True}),
    ]
    for cmd, a in sequence:
        path = "/sync-buffers" if cmd == "sync_buffers" else "/command"
        payload = a if cmd == "sync_buffers" else {"command": cmd, "args": a}
        steps.append({"name": cmd, "result": _post(base, path, payload)})
    return steps


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--control-port", type=int, default=18101)
    p.add_argument("--bulk-port", type=int, default=19190)
    p.add_argument("--realtime-port", type=int, default=19191)
    p.add_argument("--payload-file", required=True)
    p.add_argument("--chunk-size", type=int, default=4096)
    p.add_argument("--managed-service", action="store_true")
    p.add_argument("--l2-required", action="store_true")
    p.add_argument("--transport-mode", choices=["single", "dual"], default="dual")
    p.add_argument("--route-policy", choices=["auto", "realtime", "bulk"], default="auto")
    p.add_argument("--auto-realtime-max-bytes", type=int, default=4096)
    p.add_argument("--realtime-buffer-kb", type=int, default=64)
    p.add_argument("--bulk-buffer-kb", type=int, default=1024)
    p.add_argument("--hint-mode", choices=["none", "alternating", "realtime_small", "bulk_large"], default="none")
    p.add_argument("--hint-threshold", type=int, default=1024)
    p.add_argument("--output", default="verification_results/stack_audits/sshx11_profile_routed_transfer_session.json")
    return p.parse_args()


def main() -> int:
    args = parse_args()
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
        started = (rc == 0)
        if not started:
            print(out)
            return 2
        time.sleep(0.4)

    payload_path = Path(str(args.payload_file))
    output_path = Path(str(args.output))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    base = f"http://{args.host}:{args.control_port}"

    try:
        health = _get(base, "/health")
        config_steps = _configure_ready_state(base, args)
        policy = _get(base, "/policy")
        data = payload_path.read_bytes()
        packets = _chunk_bytes(data, int(args.chunk_size))
        per_packet: list[dict[str, Any]] = []
        profile_counts = {"realtime": 0, "bulk": 0}
        profile_bytes = {"realtime": 0, "bulk": 0}
        transfer_ok = True
        transfer_reason = "ok"
        for i, pkt in enumerate(packets):
            hint = _hint_for_packet(i, pkt, hint_mode=str(args.hint_mode), hint_threshold=int(args.hint_threshold))
            qs = urllib.parse.urlencode({"bytes": len(pkt), "hint": hint})
            route = _get(base, f"/transport-route?{qs}")
            selected_profile = str(route.get("selected_profile", "bulk"))
            target_port = int(route.get("target_port", args.bulk_port))
            probe_ok, probe_reason, rtt_us = _relay_probe(str(args.host), target_port, pkt)
            per_packet.append(
                {
                    "packet_index": int(i),
                    "packet_bytes": int(len(pkt)),
                    "hint": hint,
                    "selected_profile": selected_profile,
                    "target_port": target_port,
                    "route_reason": route.get("route_reason"),
                    "probe_ok": bool(probe_ok),
                    "probe_reason": probe_reason,
                    "rtt_us": int(rtt_us),
                }
            )
            if selected_profile in profile_counts:
                profile_counts[selected_profile] += 1
                profile_bytes[selected_profile] += len(pkt)
            if not probe_ok:
                transfer_ok = False
                transfer_reason = f"packet_{i}:{probe_reason}"
                break
        state = _get(base, "/state")
        result = {
            "ok": bool(health.get("ok")) and bool(policy.get("relay_allowed")) and transfer_ok,
            "health": health,
            "policy": policy,
            "transfer_ok": transfer_ok,
            "transfer_reason": transfer_reason,
            "packet_count": len(packets),
            "packet_total_bytes": len(data),
            "profile_counts": profile_counts,
            "profile_bytes": profile_bytes,
            "config_steps": config_steps,
            "per_packet": per_packet,
            "state": state,
            "scenario": {
                "transport_mode": str(args.transport_mode),
                "route_policy": str(args.route_policy),
                "hint_mode": str(args.hint_mode),
                "hint_threshold": int(args.hint_threshold),
                "chunk_size": int(args.chunk_size),
                "bulk_port": int(args.bulk_port),
                "realtime_port": int(args.realtime_port),
            },
        }
    finally:
        if args.managed_service and started:
            _run_cmd(svc_cmd + ["stop"])

    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"ok={result['ok']}")
    print(f"output={output_path}")
    return 0 if bool(result["ok"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

