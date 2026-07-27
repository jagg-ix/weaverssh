#!/usr/bin/env python3
from __future__ import annotations

"""Shared state/policy model for SSHX11 control-plane and data-plane daemons."""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PlaneState:
    session_id: str = ""
    ssh_forward_mode: str = "none"  # none|X|Y
    xauth_invoked: bool = False
    mit_cookie_generated: bool = False
    proxy_cookie_issued: bool = False
    proxy_cookie_verified: bool = False
    client_cookie_checked: bool = False
    websocket_ready: bool = False
    l2_required: bool = False
    l2_ready: bool = False
    ssh_buffer_kb: int = 256
    x11_buffer_kb: int = 256
    ws_buffer_kb: int = 256
    buffer_profiles_synced: bool = False
    relay_enabled: bool = False
    transport_mode: str = "dual"  # single|dual
    transport_route_policy: str = "auto"  # auto|realtime|bulk
    transport_auto_realtime_max_bytes: int = 4096
    realtime_buffer_kb: int = 64
    bulk_buffer_kb: int = 1024
    control_plane_version: str = "v1"
    data_plane_version: str = "v1"
    bytes_client_to_target: int = 0
    bytes_target_to_client: int = 0
    packets_client_to_target: int = 0
    packets_target_to_client: int = 0
    blocked_packets: int = 0
    realtime_packets: int = 0
    bulk_packets: int = 0
    realtime_bytes: int = 0
    bulk_bytes: int = 0
    realtime_rtt_us_total: int = 0
    realtime_rtt_us_count: int = 0
    realtime_rtt_us_min: int = 0
    realtime_rtt_us_max: int = 0
    bulk_rtt_us_total: int = 0
    bulk_rtt_us_count: int = 0
    bulk_rtt_us_min: int = 0
    bulk_rtt_us_max: int = 0
    last_reason: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(payload: Dict[str, Any]) -> "PlaneState":
        s = PlaneState()
        for k, v in payload.items():
            if hasattr(s, k):
                setattr(s, k, v)
        return s


def initial_state() -> PlaneState:
    s = PlaneState()
    s.updated_at = utc_now_iso()
    return s


def buffer_sync_ok(s: PlaneState) -> bool:
    return int(s.ssh_buffer_kb) == int(s.x11_buffer_kb) == int(s.ws_buffer_kb)


def _sanitize_transport_mode(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in {"single", "dual"} else "dual"


def _sanitize_transport_policy(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in {"auto", "realtime", "bulk"} else "auto"


def _sanitize_transport_profile(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in {"realtime", "bulk"} else "bulk"


def transport_profile_route(s: PlaneState, payload_bytes: int, hint: str = "") -> Tuple[str, str]:
    payload_bytes = max(0, int(payload_bytes))
    hint_v = str(hint or "").strip().lower()
    if hint_v in {"realtime", "bulk"}:
        if s.transport_mode == "single" and hint_v == "realtime":
            return "bulk", "single_mode_fallback_to_bulk"
        return hint_v, "hint_override"
    policy = _sanitize_transport_policy(s.transport_route_policy)
    if s.transport_mode == "single":
        return "bulk", "single_mode"
    if policy == "realtime":
        return "realtime", "policy_realtime"
    if policy == "bulk":
        return "bulk", "policy_bulk"
    if payload_bytes <= int(s.transport_auto_realtime_max_bytes):
        return "realtime", "auto_small_payload"
    return "bulk", "auto_large_payload"


def relay_policy(s: PlaneState) -> Tuple[bool, str]:
    if s.ssh_forward_mode != "X":
        return False, "ssh_forward_mode_must_be_X"
    if not s.mit_cookie_generated:
        return False, "mit_cookie_not_generated"
    if not s.xauth_invoked:
        return False, "xauth_not_invoked"
    if not s.proxy_cookie_issued:
        return False, "proxy_cookie_not_issued"
    if not s.client_cookie_checked:
        return False, "client_cookie_not_checked"
    if not s.proxy_cookie_verified:
        return False, "proxy_cookie_not_verified"
    if not s.websocket_ready:
        return False, "websocket_not_ready"
    if s.l2_required and not s.l2_ready:
        return False, "l2_required_but_not_ready"
    if not s.buffer_profiles_synced:
        return False, "buffer_profiles_not_synced"
    if not s.relay_enabled:
        return False, "relay_not_enabled"
    return True, "ok"


def _bool_arg(args: Dict[str, Any], key: str, default: bool = False) -> bool:
    raw = args.get(key, default)
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _int_arg(args: Dict[str, Any], key: str, default: int) -> int:
    raw = args.get(key, default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _update_profile_rtt(s: PlaneState, profile: str, rtt_us: int) -> None:
    p = _sanitize_transport_profile(profile)
    val = max(0, int(rtt_us))
    if val <= 0:
        return
    if p == "realtime":
        s.realtime_rtt_us_total += val
        s.realtime_rtt_us_count += 1
        if s.realtime_rtt_us_min <= 0 or val < s.realtime_rtt_us_min:
            s.realtime_rtt_us_min = val
        if val > s.realtime_rtt_us_max:
            s.realtime_rtt_us_max = val
        return
    s.bulk_rtt_us_total += val
    s.bulk_rtt_us_count += 1
    if s.bulk_rtt_us_min <= 0 or val < s.bulk_rtt_us_min:
        s.bulk_rtt_us_min = val
    if val > s.bulk_rtt_us_max:
        s.bulk_rtt_us_max = val


def apply_command(state: PlaneState, command: str, args: Dict[str, Any] | None = None) -> Tuple[PlaneState, Dict[str, Any]]:
    args = dict(args or {})
    s = PlaneState.from_dict(state.to_dict())
    cmd = str(command or "").strip()

    if cmd == "reset":
        s = initial_state()
    elif cmd == "start_session":
        s.session_id = str(args.get("session_id", "")).strip()
    elif cmd == "request_x11_forward":
        mode = str(args.get("mode", "X")).strip().upper()
        if mode not in {"X", "Y"}:
            mode = "X"
        s.ssh_forward_mode = mode
    elif cmd == "set_mit_cookie_generated":
        s.mit_cookie_generated = _bool_arg(args, "value", True)
    elif cmd == "set_xauth_invoked":
        s.xauth_invoked = _bool_arg(args, "value", True)
    elif cmd == "set_proxy_cookie_issued":
        s.proxy_cookie_issued = _bool_arg(args, "value", True)
    elif cmd == "set_client_cookie_checked":
        s.client_cookie_checked = _bool_arg(args, "value", True)
    elif cmd == "set_proxy_cookie_verified":
        s.proxy_cookie_verified = _bool_arg(args, "value", True)
    elif cmd == "set_websocket_ready":
        s.websocket_ready = _bool_arg(args, "value", True)
    elif cmd == "set_l2_required":
        s.l2_required = _bool_arg(args, "value", True)
    elif cmd == "set_l2_ready":
        s.l2_ready = _bool_arg(args, "value", True)
    elif cmd == "sync_buffers":
        s.ssh_buffer_kb = _int_arg(args, "ssh_buffer_kb", s.ssh_buffer_kb)
        s.x11_buffer_kb = _int_arg(args, "x11_buffer_kb", s.x11_buffer_kb)
        s.ws_buffer_kb = _int_arg(args, "ws_buffer_kb", s.ws_buffer_kb)
        s.buffer_profiles_synced = buffer_sync_ok(s)
    elif cmd == "set_transport_mode":
        s.transport_mode = _sanitize_transport_mode(str(args.get("value", s.transport_mode)))
    elif cmd == "set_transport_route_policy":
        s.transport_route_policy = _sanitize_transport_policy(str(args.get("value", s.transport_route_policy)))
    elif cmd == "set_transport_auto_realtime_max_bytes":
        s.transport_auto_realtime_max_bytes = max(
            1,
            _int_arg(args, "value", s.transport_auto_realtime_max_bytes),
        )
    elif cmd == "set_transport_buffers":
        s.realtime_buffer_kb = max(1, _int_arg(args, "realtime_buffer_kb", s.realtime_buffer_kb))
        s.bulk_buffer_kb = max(1, _int_arg(args, "bulk_buffer_kb", s.bulk_buffer_kb))
    elif cmd == "set_relay_enabled":
        s.relay_enabled = _bool_arg(args, "value", True)
    elif cmd == "record_dataplane_tx":
        direction = str(args.get("direction", "client_to_target")).strip()
        nbytes = max(0, _int_arg(args, "bytes", 0))
        profile = _sanitize_transport_profile(str(args.get("profile", "bulk")))
        rtt_us = max(0, _int_arg(args, "rtt_us", 0))
        if nbytes > 0:
            if direction == "target_to_client":
                s.bytes_target_to_client += nbytes
                s.packets_target_to_client += 1
            else:
                s.bytes_client_to_target += nbytes
                s.packets_client_to_target += 1
            if profile == "realtime":
                s.realtime_bytes += nbytes
                s.realtime_packets += 1
            else:
                s.bulk_bytes += nbytes
                s.bulk_packets += 1
        _update_profile_rtt(s, profile, rtt_us)
    elif cmd == "record_dataplane_block":
        s.blocked_packets += 1
    else:
        return s, {"ok": False, "error": f"unsupported_command:{cmd}"}

    allowed, reason = relay_policy(s)
    s.last_reason = reason
    s.updated_at = utc_now_iso()
    return s, {"ok": True, "relay_allowed": allowed, "relay_reason": reason}


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_state(path: Path) -> PlaneState:
    if not path.exists():
        return initial_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return PlaneState.from_dict(payload)
    except Exception:
        pass
    return initial_state()


def save_state(path: Path, state: PlaneState) -> None:
    ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def append_ndjson(path: Path, record: Dict[str, Any]) -> None:
    ensure_parent(path)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True))
        f.write("\n")
