#!/usr/bin/env python3
from __future__ import annotations

"""Local control-plane daemon for SSHX11 transport + crypto policy state."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.sshx11_plane_model import (
    PlaneState,
    append_ndjson,
    apply_command,
    load_state,
    relay_policy,
    save_state,
    transport_profile_route,
    utc_now_iso,
)


def _json_response(handler: BaseHTTPRequestHandler, code: int, payload: Dict[str, Any]) -> None:
    body = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    raw_len = handler.headers.get("Content-Length", "0").strip()
    try:
        n = int(raw_len)
    except Exception:
        n = 0
    if n <= 0:
        return {}
    raw = handler.rfile.read(n)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _record(
    log_path: Path,
    event: str,
    payload: Dict[str, Any],
    state: PlaneState,
) -> None:
    append_ndjson(
        log_path,
        {
            "ts": utc_now_iso(),
            "source": "sshx11_control_plane",
            "event": event,
            "payload": payload,
            "state": state.to_dict(),
        },
    )


def build_handler(
    state_path: Path,
    log_path: Path,
    *,
    bulk_port: int,
    realtime_port: int,
):  # type: ignore[no-untyped-def]
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args):  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            with lock:
                state = load_state(state_path)
            if path == "/health":
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "service": "sshx11_control_plane",
                        "state_file": str(state_path),
                        "log_file": str(log_path),
                    },
                )
                return
            if path == "/state":
                _json_response(self, 200, {"ok": True, "state": state.to_dict()})
                return
            if path == "/policy":
                allowed, reason = relay_policy(state)
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "relay_allowed": allowed,
                        "relay_reason": reason,
                        "state": state.to_dict(),
                    },
                )
                return
            if path == "/transport-route":
                q = parse_qs(parsed.query or "")
                try:
                    payload_bytes = int(str((q.get("bytes") or ["0"])[0]))
                except Exception:
                    payload_bytes = 0
                hint = str((q.get("hint") or [""])[0])
                profile, route_reason = transport_profile_route(state, payload_bytes=payload_bytes, hint=hint)
                target_port = int(realtime_port if profile == "realtime" else bulk_port)
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "payload_bytes": int(payload_bytes),
                        "hint": hint,
                        "selected_profile": profile,
                        "route_reason": route_reason,
                        "target_port": target_port,
                        "bulk_port": int(bulk_port),
                        "realtime_port": int(realtime_port),
                        "state": state.to_dict(),
                    },
                )
                return
            _json_response(self, 404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            payload = _read_json_body(self)
            if self.path == "/sync-buffers":
                payload = {
                    "command": "sync_buffers",
                    "args": {
                        "ssh_buffer_kb": payload.get("ssh_buffer_kb", 256),
                        "x11_buffer_kb": payload.get("x11_buffer_kb", 256),
                        "ws_buffer_kb": payload.get("ws_buffer_kb", 256),
                    },
                }
            if self.path != "/command" and self.path != "/sync-buffers":
                _json_response(self, 404, {"ok": False, "error": "not_found"})
                return
            command = str(payload.get("command", "")).strip()
            args = payload.get("args", {})
            if not isinstance(args, dict):
                args = {}
            with lock:
                state = load_state(state_path)
                nxt, result = apply_command(state, command=command, args=args)
                if result.get("ok"):
                    save_state(state_path, nxt)
                    _record(
                        log_path=log_path,
                        event="command_applied",
                        payload={"command": command, "args": args, "result": result},
                        state=nxt,
                    )
                    _json_response(self, 200, {"ok": True, "result": result, "state": nxt.to_dict()})
                else:
                    _record(
                        log_path=log_path,
                        event="command_rejected",
                        payload={"command": command, "args": args, "result": result},
                        state=state,
                    )
                    _json_response(self, 400, {"ok": False, "result": result, "state": state.to_dict()})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8101)
    parser.add_argument("--bulk-port", type=int, default=19090)
    parser.add_argument("--realtime-port", type=int, default=19091)
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path("verification_results/runtime/sshx11_plane_state.json"),
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("verification_results/stack_audits/sshx11_control_plane_events.ndjson"),
    )
    args = parser.parse_args()

    state = load_state(args.state_file)
    save_state(args.state_file, state)
    handler = build_handler(
        state_path=args.state_file,
        log_path=args.log_file,
        bulk_port=int(args.bulk_port),
        realtime_port=int(args.realtime_port),
    )
    server = ThreadingHTTPServer((str(args.host), int(args.port)), handler)
    append_ndjson(
        args.log_file,
        {
            "ts": utc_now_iso(),
            "source": "sshx11_control_plane",
            "event": "service_start",
            "payload": {"host": args.host, "port": int(args.port)},
            "state": state.to_dict(),
        },
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
