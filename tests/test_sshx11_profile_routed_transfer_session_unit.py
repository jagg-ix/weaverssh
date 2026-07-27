from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11_profile_routed_transfer_session as prs


def test_chunk_bytes_splits_as_expected() -> None:
    payload = b"abcdefghij"
    out = prs._chunk_bytes(payload, 4)
    assert out == [b"abcd", b"efgh", b"ij"]


def test_hint_for_packet_modes() -> None:
    pkt_small = b"a" * 128
    pkt_large = b"b" * 4096
    assert prs._hint_for_packet(0, pkt_small, hint_mode="none", hint_threshold=512) == ""
    assert prs._hint_for_packet(0, pkt_small, hint_mode="alternating", hint_threshold=512) == "realtime"
    assert prs._hint_for_packet(1, pkt_small, hint_mode="alternating", hint_threshold=512) == "bulk"
    assert prs._hint_for_packet(0, pkt_small, hint_mode="realtime_small", hint_threshold=512) == "realtime"
    assert prs._hint_for_packet(0, pkt_large, hint_mode="realtime_small", hint_threshold=512) == ""
    assert prs._hint_for_packet(0, pkt_large, hint_mode="bulk_large", hint_threshold=1024) == "bulk"
    assert prs._hint_for_packet(0, pkt_small, hint_mode="bulk_large", hint_threshold=1024) == ""

