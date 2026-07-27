from __future__ import annotations

from pathlib import Path
import importlib.util


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "benchmark_sshx11_socks5_flows.py"
SPEC = importlib.util.spec_from_file_location("benchmark_sshx11_socks5_flows_udp", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf)


def test_socks5_udp_wrap_unwrap_roundtrip() -> None:
    payload = b"udp-associate-roundtrip"
    packet = perf._socks5_udp_wrap(payload=payload, dst_host="127.0.0.1", dst_port=19999)
    frag, host, port, got = perf._socks5_udp_unwrap(packet)
    assert frag == 0
    assert host == "127.0.0.1"
    assert port == 19999
    assert got == payload


def test_minisocks5_udp_associate_echo_path() -> None:
    udp_echo = perf.UDPEchoServer(host="127.0.0.1", port=0)
    socks = perf.MiniSocks5Proxy(host="127.0.0.1", port=0)
    ctrl = None
    udp = None
    try:
        udp_echo.start()
        socks.start()
        ctrl, udp, relay = perf._socks_udp_associate(
            socks_host="127.0.0.1",
            socks_port=int(socks.bound_port),
            timeout_s=2.0,
        )
        payload = b"udp-associate-e2e"
        pkt = perf._socks5_udp_wrap(
            payload=payload,
            dst_host="127.0.0.1",
            dst_port=int(udp_echo.bound_port),
        )
        udp.sendto(pkt, relay)
        got, _ = udp.recvfrom(65535)
        frag, host, port, data = perf._socks5_udp_unwrap(got)
        assert frag == 0
        assert host == "127.0.0.1"
        assert port == int(udp_echo.bound_port)
        assert data == payload
    finally:
        if udp is not None:
            udp.close()
        if ctrl is not None:
            ctrl.close()
        socks.stop()
        udp_echo.stop()


def test_udp_associate_connect_latency_samples() -> None:
    socks = perf.MiniSocks5Proxy(host="127.0.0.1", port=0)
    try:
        socks.start()
        samples, errors = perf._measure_udp_assoc_connect_latency(
            socks_host="127.0.0.1",
            socks_port=int(socks.bound_port),
            timeout_s=2.0,
            count=4,
            warmup=1,
        )
        assert len(samples) == 4
        assert errors == []
    finally:
        socks.stop()
