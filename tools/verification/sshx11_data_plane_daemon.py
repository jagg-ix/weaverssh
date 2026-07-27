#!/usr/bin/env python3
from __future__ import annotations

"""Local data-plane daemon for SSHX11 relay, gated by control-plane policy."""

import argparse
import socket
import socketserver
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification.sshx11_plane_model import (
    append_ndjson,
    apply_command,
    load_state,
    relay_policy,
    save_state,
    utc_now_iso,
)


class _RelayTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        handler_cls,
        state_path: Path,
        log_path: Path,
        *,
        profile_name: str,
    ):  # type: ignore[no-untyped-def]
        super().__init__(server_address, handler_cls)
        self.state_path = state_path
        self.log_path = log_path
        self.lock = threading.Lock()
        self.profile_name = profile_name


def _record(log_path: Path, event: str, payload: Dict[str, Any], state: Dict[str, Any]) -> None:
    append_ndjson(
        log_path,
        {
            "ts": utc_now_iso(),
            "source": "sshx11_data_plane",
            "event": event,
            "payload": payload,
            "state": state,
        },
    )


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        assert isinstance(server, _RelayTCPServer)
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        active_profile = str(getattr(server, "profile_name", "bulk"))
        while True:
            data = self.request.recv(65535)
            if not data:
                return
            with server.lock:
                state = load_state(server.state_path)
                if active_profile == "realtime":
                    buffer_kb = max(1, int(getattr(state, "realtime_buffer_kb", 64)))
                else:
                    buffer_kb = max(1, int(getattr(state, "bulk_buffer_kb", 1024)))
                try:
                    self.request.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_kb * 1024)
                    self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_kb * 1024)
                except Exception:
                    pass
                allowed, reason = relay_policy(state)
                if not allowed:
                    nxt, _ = apply_command(state, "record_dataplane_block", {"profile": active_profile})
                    save_state(server.state_path, nxt)
                    _record(
                        log_path=server.log_path,
                        event="packet_blocked",
                        payload={
                            "peer": peer,
                            "bytes": len(data),
                            "reason": reason,
                            "profile": active_profile,
                            "buffer_kb": buffer_kb,
                        },
                        state=nxt.to_dict(),
                    )
                    try:
                        self.request.sendall(b"BLOCKED\n")
                    except Exception:
                        pass
                    return

                t0 = time.perf_counter_ns()
                tx1, _ = apply_command(
                    state,
                    "record_dataplane_tx",
                    {
                        "direction": "client_to_target",
                        "bytes": len(data),
                        "profile": active_profile,
                    },
                )
                tx2, _ = apply_command(
                    tx1,
                    "record_dataplane_tx",
                    {
                        "direction": "target_to_client",
                        "bytes": len(data),
                        "profile": active_profile,
                    },
                )
                save_state(server.state_path, tx2)
                _record(
                    log_path=server.log_path,
                    event="packet_relayed",
                    payload={
                        "peer": peer,
                        "bytes": len(data),
                        "reason": "ok",
                        "profile": active_profile,
                        "buffer_kb": buffer_kb,
                    },
                    state=tx2.to_dict(),
                )
            self.request.sendall(data)
            t1 = time.perf_counter_ns()
            rtt_us = max(0, int((t1 - t0) // 1000))
            with server.lock:
                state2 = load_state(server.state_path)
                nxt3, _ = apply_command(
                    state2,
                    "record_dataplane_tx",
                    {
                        "direction": "client_to_target",
                        "bytes": 0,
                        "profile": active_profile,
                        "rtt_us": rtt_us,
                    },
                )
                save_state(server.state_path, nxt3)
                _record(
                    log_path=server.log_path,
                    event="packet_latency_observed",
                    payload={
                        "peer": peer,
                        "rtt_us": rtt_us,
                        "profile": active_profile,
                    },
                    state=nxt3.to_dict(),
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=-1, help="legacy alias for --bulk-port")
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
        default=Path("verification_results/stack_audits/sshx11_data_plane_events.ndjson"),
    )
    args = parser.parse_args()

    state = load_state(args.state_file)
    save_state(args.state_file, state)
    bulk_port = int(args.bulk_port if int(args.port) < 0 else args.port)
    realtime_port = int(args.realtime_port)
    bindings = [("bulk", bulk_port)]
    if realtime_port > 0 and realtime_port != bulk_port:
        bindings.append(("realtime", realtime_port))

    servers: list[_RelayTCPServer] = []
    threads: list[threading.Thread] = []
    for profile, port in bindings:
        srv = _RelayTCPServer(
            (str(args.host), int(port)),
            RelayHandler,
            args.state_file,
            args.log_file,
            profile_name=profile,
        )
        th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        th.start()
        servers.append(srv)
        threads.append(th)

    _record(
        log_path=args.log_file,
        event="service_start",
        payload={
            "host": args.host,
            "bulk_port": int(bulk_port),
            "realtime_port": int(realtime_port),
            "active_bindings": [{"profile": p, "port": int(port)} for p, port in bindings],
        },
        state=state.to_dict(),
    )

    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:
                pass
        for srv in servers:
            try:
                srv.server_close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
