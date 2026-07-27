from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11_plane_model as model


def _ready_state(*, l2_required: bool = False, l2_ready: bool = False) -> model.PlaneState:
    s = model.initial_state()
    s.ssh_forward_mode = "X"
    s.mit_cookie_generated = True
    s.xauth_invoked = True
    s.proxy_cookie_issued = True
    s.client_cookie_checked = True
    s.proxy_cookie_verified = True
    s.websocket_ready = True
    s.relay_enabled = True
    s.ssh_buffer_kb = 256
    s.x11_buffer_kb = 256
    s.ws_buffer_kb = 256
    s.buffer_profiles_synced = True
    s.l2_required = l2_required
    s.l2_ready = l2_ready
    return s


def test_relay_policy_allows_ready_state_without_l2_requirement() -> None:
    s = _ready_state(l2_required=False, l2_ready=False)
    allowed, reason = model.relay_policy(s)
    assert allowed is True
    assert reason == "ok"


def test_relay_policy_requires_l2_when_enabled() -> None:
    s = _ready_state(l2_required=True, l2_ready=False)
    allowed, reason = model.relay_policy(s)
    assert allowed is False
    assert reason == "l2_required_but_not_ready"

    s.l2_ready = True
    allowed, reason = model.relay_policy(s)
    assert allowed is True
    assert reason == "ok"


def test_relay_policy_rejects_ssh_y_mode() -> None:
    s = _ready_state()
    s.ssh_forward_mode = "Y"
    allowed, reason = model.relay_policy(s)
    assert allowed is False
    assert reason == "ssh_forward_mode_must_be_X"


def test_apply_command_sequence_reaches_relay_allowed() -> None:
    s = model.initial_state()
    sequence = [
        ("request_x11_forward", {"mode": "X"}),
        ("set_mit_cookie_generated", {"value": True}),
        ("set_xauth_invoked", {"value": True}),
        ("set_proxy_cookie_issued", {"value": True}),
        ("set_client_cookie_checked", {"value": True}),
        ("set_proxy_cookie_verified", {"value": True}),
        ("set_websocket_ready", {"value": True}),
        ("sync_buffers", {"ssh_buffer_kb": 256, "x11_buffer_kb": 256, "ws_buffer_kb": 256}),
        ("set_relay_enabled", {"value": True}),
    ]
    for cmd, args in sequence:
        s, res = model.apply_command(s, cmd, args)
        assert res["ok"] is True
    allowed, reason = model.relay_policy(s)
    assert allowed is True
    assert reason == "ok"


def test_apply_command_unsupported() -> None:
    s = model.initial_state()
    nxt, res = model.apply_command(s, "unknown_command", {})
    assert nxt.to_dict() == s.to_dict()
    assert res["ok"] is False
    assert "unsupported_command" in res["error"]


def test_apply_command_sync_buffers_updates_flag() -> None:
    s = model.initial_state()
    s, res = model.apply_command(s, "sync_buffers", {"ssh_buffer_kb": 256, "x11_buffer_kb": 128, "ws_buffer_kb": 256})
    assert res["ok"] is True
    assert s.buffer_profiles_synced is False
    s, res = model.apply_command(s, "sync_buffers", {"ssh_buffer_kb": 256, "x11_buffer_kb": 256, "ws_buffer_kb": 256})
    assert res["ok"] is True
    assert s.buffer_profiles_synced is True


def test_dataplane_counters_increment() -> None:
    s = model.initial_state()
    s, _ = model.apply_command(s, "record_dataplane_tx", {"direction": "client_to_target", "bytes": 32})
    s, _ = model.apply_command(s, "record_dataplane_tx", {"direction": "target_to_client", "bytes": 16})
    s, _ = model.apply_command(s, "record_dataplane_block", {})
    assert s.bytes_client_to_target == 32
    assert s.bytes_target_to_client == 16
    assert s.packets_client_to_target == 1
    assert s.packets_target_to_client == 1
    assert s.blocked_packets == 1


def test_transport_profile_route_auto_and_overrides() -> None:
    s = model.initial_state()
    s.transport_mode = "dual"
    s.transport_route_policy = "auto"
    s.transport_auto_realtime_max_bytes = 512
    profile, reason = model.transport_profile_route(s, payload_bytes=128, hint="")
    assert profile == "realtime"
    assert reason == "auto_small_payload"
    profile, reason = model.transport_profile_route(s, payload_bytes=4096, hint="")
    assert profile == "bulk"
    assert reason == "auto_large_payload"
    profile, reason = model.transport_profile_route(s, payload_bytes=4096, hint="realtime")
    assert profile == "realtime"
    assert reason == "hint_override"
    s.transport_mode = "single"
    profile, reason = model.transport_profile_route(s, payload_bytes=64, hint="realtime")
    assert profile == "bulk"
    assert reason == "single_mode_fallback_to_bulk"


def test_transport_commands_update_state() -> None:
    s = model.initial_state()
    s, r = model.apply_command(s, "set_transport_mode", {"value": "single"})
    assert r["ok"] is True
    assert s.transport_mode == "single"
    s, r = model.apply_command(s, "set_transport_route_policy", {"value": "realtime"})
    assert r["ok"] is True
    assert s.transport_route_policy == "realtime"
    s, r = model.apply_command(s, "set_transport_auto_realtime_max_bytes", {"value": 2048})
    assert r["ok"] is True
    assert s.transport_auto_realtime_max_bytes == 2048
    s, r = model.apply_command(s, "set_transport_buffers", {"realtime_buffer_kb": 48, "bulk_buffer_kb": 2048})
    assert r["ok"] is True
    assert s.realtime_buffer_kb == 48
    assert s.bulk_buffer_kb == 2048


def test_dataplane_profile_counters_and_latency_stats() -> None:
    s = model.initial_state()
    s, _ = model.apply_command(
        s,
        "record_dataplane_tx",
        {"direction": "client_to_target", "bytes": 100, "profile": "realtime", "rtt_us": 300},
    )
    s, _ = model.apply_command(
        s,
        "record_dataplane_tx",
        {"direction": "target_to_client", "bytes": 200, "profile": "bulk", "rtt_us": 900},
    )
    s, _ = model.apply_command(
        s,
        "record_dataplane_tx",
        {"direction": "client_to_target", "bytes": 0, "profile": "realtime", "rtt_us": 150},
    )
    assert s.realtime_packets == 1
    assert s.realtime_bytes == 100
    assert s.bulk_packets == 1
    assert s.bulk_bytes == 200
    assert s.realtime_rtt_us_count == 2
    assert s.realtime_rtt_us_total == 450
    assert s.realtime_rtt_us_min == 150
    assert s.realtime_rtt_us_max == 300
    assert s.bulk_rtt_us_count == 1
    assert s.bulk_rtt_us_total == 900


def test_load_save_state_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    s = _ready_state(l2_required=True, l2_ready=True)
    model.save_state(p, s)
    out = model.load_state(p)
    assert out.to_dict() == s.to_dict()


def test_append_ndjson_writes_parseable_rows(tmp_path: Path) -> None:
    p = tmp_path / "events.ndjson"
    model.append_ndjson(p, {"event": "one", "v": 1})
    model.append_ndjson(p, {"event": "two", "v": 2})
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 2
    assert rows[0]["event"] == "one"
    assert rows[1]["event"] == "two"
