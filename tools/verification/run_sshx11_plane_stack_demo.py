#!/usr/bin/env python3
from __future__ import annotations

"""Run a local control/data-plane demo and emit a stack audit artifact."""

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
    data = json.loads(raw.decode("utf-8"))
    return data if isinstance(data, dict) else {"ok": False}


def _get(base: str, path: str) -> dict:
    req = urllib.request.Request(f"{base}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read()
    data = json.loads(raw.decode("utf-8"))
    return data if isinstance(data, dict) else {"ok": False}


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


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
        if echoed == payload:
            return True, "echo_ok", rtt_us
        if blocked or echoed == b"BLOCKED\n":
            return False, "blocked", rtt_us
        return False, f"unexpected_reply:{echoed[:64]!r}", rtt_us
    except Exception as exc:
        return False, f"socket_error:{exc}", 0
    finally:
        try:
            s.close()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--control-port", type=int, default=8101)
    parser.add_argument("--data-port", type=int, default=19090)
    parser.add_argument("--realtime-port", type=int, default=-1)
    parser.add_argument("--managed-service", action="store_true")
    parser.add_argument("--l2-required", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("verification_results/stack_audits/sshx11_plane_stack_demo.json"))
    args = parser.parse_args()

    realtime_port = int(args.realtime_port if int(args.realtime_port) > 0 else (int(args.data_port) + 1))

    svc_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "verification" / "sshx11_plane_service.py"),
        "--host",
        str(args.host),
        "--control-port",
        str(args.control_port),
        "--data-port",
        str(args.data_port),
        "--realtime-port",
        str(realtime_port),
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
    steps: list[dict] = []
    try:
        steps.append({"name": "health", "result": _get(base, "/health")})
        sequence = [
            ("reset", {}),
            ("start_session", {"session_id": "demo-session"}),
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
            ("set_transport_mode", {"value": "dual"}),
            ("set_transport_route_policy", {"value": "auto"}),
            ("set_transport_auto_realtime_max_bytes", {"value": 4096}),
            ("set_transport_buffers", {"realtime_buffer_kb": 64, "bulk_buffer_kb": 1024}),
            ("set_relay_enabled", {"value": True}),
        ]
        for cmd, a in sequence:
            path = "/sync-buffers" if cmd == "sync_buffers" else "/command"
            payload = a if cmd == "sync_buffers" else {"command": cmd, "args": a}
            steps.append({"name": cmd, "result": _post(base, path, payload)})

        pol = _get(base, "/policy")
        route_small = _get(base, "/transport-route?bytes=128&hint=")
        route_large = _get(base, "/transport-route?bytes=65536&hint=")
        rt_ok, rt_reason, rt_rtt_us = _relay_probe(args.host, realtime_port, b"x11-rt")
        bulk_payload = b"sshx11-bulk-demo-" + (b"a" * 16384)
        bulk_ok, bulk_reason, bulk_rtt_us = _relay_probe(args.host, args.data_port, bulk_payload)
        state = _get(base, "/state")
        result = {
            "ok": bool(pol.get("relay_allowed")) and rt_ok and bulk_ok,
            "policy": pol,
            "transport_route_small": route_small,
            "transport_route_large": route_large,
            "relay_realtime_probe_ok": rt_ok,
            "relay_realtime_probe_reason": rt_reason,
            "relay_realtime_rtt_us": rt_rtt_us,
            "relay_bulk_probe_ok": bulk_ok,
            "relay_bulk_probe_reason": bulk_reason,
            "relay_bulk_rtt_us": bulk_rtt_us,
            "bulk_port": int(args.data_port),
            "realtime_port": int(realtime_port),
            "state": state,
            "steps": steps,
        }
    finally:
        if args.managed_service and started:
            _run_cmd(svc_cmd + ["stop"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"ok={result['ok']}")
    print(f"output={args.output}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
