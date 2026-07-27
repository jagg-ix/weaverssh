#!/usr/bin/env python3
from __future__ import annotations

"""Performance battery for SOCKS5 flows (latency + bandwidth).

Measures both:
- direct TCP baseline to target
- SOCKS5 CONNECT flow to same target

Modes:
- mock: start local echo server + in-process SOCKS5 proxy (self-contained)
- external: use existing SOCKS5 endpoint and target endpoint
- managed-service: start sshx11 SOCKS fallback service, then benchmark

Optional UDP battery:
- SOCKS5 UDP ASSOCIATE (RFC1928 CMD=0x03)
- direct UDP baseline vs SOCKS5 UDP relay path
"""

import argparse
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = Path("verification_results/stack_audits/sshx11_socks5_performance_battery.json")
DEFAULT_SAFE_UDP_PAYLOAD_BYTES = 1200


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return int(proc.returncode), (proc.stdout + proc.stderr).strip()


def _read_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise RuntimeError(f"socket closed while reading {n} bytes")
        out.extend(part)
    return bytes(out)


def _encode_socks_addr(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_aton(host)
        return b"\x01" + packed + struct.pack("!H", int(port))
    except OSError:
        pass
    try:
        packed6 = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + packed6 + struct.pack("!H", int(port))
    except OSError:
        pass
    raw = host.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("domain name too long for SOCKS5")
    return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", int(port))


def _read_socks_addr(sock: socket.socket, atyp: int) -> tuple[str, int]:
    if atyp == 0x01:
        host = socket.inet_ntoa(_read_exact(sock, 4))
    elif atyp == 0x03:
        ln = _read_exact(sock, 1)[0]
        host = _read_exact(sock, int(ln)).decode("utf-8", errors="replace")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, _read_exact(sock, 16))
    else:
        raise RuntimeError(f"unsupported SOCKS ATYP: {atyp}")
    port = struct.unpack("!H", _read_exact(sock, 2))[0]
    return host, int(port)


def _socks5_udp_wrap(*, payload: bytes, dst_host: str, dst_port: int, frag: int = 0) -> bytes:
    if int(frag) != 0:
        raise ValueError("only FRAG=0 is supported")
    return b"\x00\x00" + bytes([int(frag) & 0xFF]) + _encode_socks_addr(str(dst_host), int(dst_port)) + bytes(payload)


def _socks5_udp_unwrap(packet: bytes) -> tuple[int, str, int, bytes]:
    if len(packet) < 4:
        raise ValueError("short SOCKS5 UDP packet")
    if packet[0:2] != b"\x00\x00":
        raise ValueError("invalid SOCKS5 UDP RSV")
    frag = int(packet[2])
    atyp = int(packet[3])
    idx = 4
    if atyp == 0x01:
        if len(packet) < idx + 4 + 2:
            raise ValueError("short IPv4 UDP packet")
        host = socket.inet_ntoa(packet[idx : idx + 4])
        idx += 4
    elif atyp == 0x03:
        if len(packet) < idx + 1:
            raise ValueError("short domain UDP packet")
        ln = int(packet[idx])
        idx += 1
        if len(packet) < idx + ln + 2:
            raise ValueError("short domain payload")
        host = packet[idx : idx + ln].decode("utf-8", errors="replace")
        idx += ln
    elif atyp == 0x04:
        if len(packet) < idx + 16 + 2:
            raise ValueError("short IPv6 UDP packet")
        host = socket.inet_ntop(socket.AF_INET6, packet[idx : idx + 16])
        idx += 16
    else:
        raise ValueError(f"unsupported SOCKS5 UDP ATYP: {atyp}")
    port = struct.unpack("!H", packet[idx : idx + 2])[0]
    idx += 2
    return frag, host, int(port), packet[idx:]


def _recv_until(sock: socket.socket, total_bytes: int) -> bytes:
    buf = bytearray()
    while len(buf) < total_bytes:
        part = sock.recv(min(65535, total_bytes - len(buf)))
        if not part:
            raise RuntimeError(f"socket closed before receiving expected payload ({len(buf)} < {total_bytes})")
        buf.extend(part)
    return bytes(buf)


def _find_free_port(host: str = "127.0.0.1") -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    idx = int(max(0, min(len(s) - 1, round((len(s) - 1) * float(q)))))
    return int(s[idx])


def _latency_stats(samples_us: list[int]) -> dict[str, Any]:
    n = len(samples_us)
    if n == 0:
        return {
            "count": 0,
            "min_us": 0,
            "p50_us": 0,
            "p95_us": 0,
            "p99_us": 0,
            "max_us": 0,
            "avg_us": 0.0,
        }
    return {
        "count": int(n),
        "min_us": int(min(samples_us)),
        "p50_us": int(_percentile(samples_us, 0.50)),
        "p95_us": int(_percentile(samples_us, 0.95)),
        "p99_us": int(_percentile(samples_us, 0.99)),
        "max_us": int(max(samples_us)),
        "avg_us": float(sum(samples_us) / n),
    }


def _throughput_stats(*, bytes_total: int, duration_s: float, ops_ok: int, ops_failed: int) -> dict[str, Any]:
    d = max(1e-9, float(duration_s))
    bps = float(bytes_total / d)
    return {
        "ok": int(ops_failed) == 0,
        "bytes_total": int(bytes_total),
        "duration_s": float(d),
        "bytes_per_s": float(bps),
        "mbps": float((bps * 8.0) / 1_000_000.0),
        "ops_ok": int(ops_ok),
        "ops_failed": int(ops_failed),
    }


def _ratio_pct(a: float, b: float) -> float:
    # returns ((a/b)-1)*100 ; 0 if baseline is zero.
    if abs(float(b)) < 1e-12:
        return 0.0
    return float((float(a) / float(b) - 1.0) * 100.0)


def _parse_int_csv(raw: str, *, minimum: int = 1) -> list[int]:
    out: list[int] = []
    for tok in str(raw).split(","):
        t = tok.strip()
        if not t:
            continue
        v = int(t)
        if v < int(minimum):
            raise ValueError(f"value must be >= {minimum}: {v}")
        out.append(v)
    if not out:
        raise ValueError(f"invalid empty integer csv: {raw!r}")
    return out


def _parse_bw_cases(raw: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for tok in str(raw).split(","):
        t = tok.strip().lower()
        if not t:
            continue
        if "x" in t:
            a, b = t.split("x", 1)
        elif ":" in t:
            a, b = t.split(":", 1)
        else:
            raise ValueError(f"invalid bandwidth case token {tok!r}; expected <chunk>x<count>")
        chunk = int(a)
        count = int(b)
        if chunk <= 0 or count <= 0:
            raise ValueError(f"invalid bandwidth case {tok!r}")
        out.append((chunk, count))
    if not out:
        raise ValueError(f"invalid empty bandwidth case list: {raw!r}")
    return out


def _derive_udp_bw_cases(tcp_bw_cases: list[tuple[int, int]], max_payload: int = DEFAULT_SAFE_UDP_PAYLOAD_BYTES) -> list[tuple[int, int]]:
    """Derive UDP-safe bandwidth cases from TCP-oriented cases.

    UDP payloads that are too large can trigger EMSGSIZE depending on host MTU/path.
    When explicit UDP cases are not provided, keep each case near the same byte budget
    by clamping payload size and scaling chunk_count accordingly.
    """
    out: list[tuple[int, int]] = []
    safe_max = max(1, int(max_payload))
    for chunk_size, chunk_count in tcp_bw_cases:
        original = max(1, int(chunk_size))
        safe_chunk = max(1, min(original, safe_max))
        scale = max(1, (original + safe_chunk - 1) // safe_chunk)
        safe_count = max(1, int(chunk_count) * scale)
        out.append((safe_chunk, safe_count))
    return out


def _build_connection_accounting(
    *,
    latency_connect_count: int,
    latency_per_message_conn: bool,
    rtt_cases_count: int,
    rtt_count_each: int,
    stream_cases_count: int,
    concurrency_levels: list[int],
) -> dict[str, Any]:
    if bool(latency_per_message_conn):
        rtt_conn_min_per_path = int(rtt_cases_count) * int(rtt_count_each)
    else:
        rtt_conn_min_per_path = int(rtt_cases_count)
    stream_conn_min_per_path = int(stream_cases_count)
    conc_conn_min_per_path = int(sum(int(x) for x in concurrency_levels))
    max_parallel_per_path = int(max(concurrency_levels) if concurrency_levels else 0)
    min_per_path = int(latency_connect_count) + rtt_conn_min_per_path + stream_conn_min_per_path + conc_conn_min_per_path
    return {
        "latency_connect_connections_per_path": int(latency_connect_count),
        "rtt_connection_min_per_path": int(rtt_conn_min_per_path),
        "stream_connection_min_per_path": int(stream_conn_min_per_path),
        "concurrency_connection_min_per_path": int(conc_conn_min_per_path),
        "concurrency_levels": [int(x) for x in concurrency_levels],
        "max_parallel_connections_per_path": int(max_parallel_per_path),
        "connection_min_per_path": int(min_per_path),
        "connection_min_both_paths_direct_plus_socks": int(min_per_path * 2),
    }


class EchoServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = int(port)
        self._srv: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.bound_port = 0

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, int(self.port)))
        srv.listen(64)
        self.bound_port = int(srv.getsockname()[1])
        self._srv = srv

        def _accept_loop() -> None:
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

        self._thread = threading.Thread(target=_accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    @staticmethod
    def _handle_conn(conn: socket.socket) -> None:
        with conn:
            while True:
                try:
                    data = conn.recv(65535)
                except OSError:
                    return
                if not data:
                    return
                try:
                    conn.sendall(data)
                except OSError:
                    return


class UDPEchoServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = int(port)
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.bound_port = 0

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, int(self.port)))
        self.bound_port = int(s.getsockname()[1])
        self._sock = s

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    s.settimeout(0.5)
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not data:
                    continue
                try:
                    s.sendto(data, addr)
                except OSError:
                    return

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)


class MiniSocks5Proxy:
    """Minimal SOCKS5 NOAUTH proxy with CONNECT + UDP ASSOCIATE support."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = int(port)
        self._srv: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.bound_port = 0

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, int(self.port)))
        srv.listen(64)
        self.bound_port = int(srv.getsockname()[1])
        self._srv = srv

        def _accept_loop() -> None:
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    client, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

        self._thread = threading.Thread(target=_accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        udp_relay: socket.socket | None = None
        udp_stop = threading.Event()
        udp_thread: threading.Thread | None = None
        try:
            client.settimeout(5.0)
            # Greeting: VER, NMETHODS, METHODS...
            head = _read_exact(client, 2)
            ver, n_methods = head[0], head[1]
            if ver != 5:
                return
            _read_exact(client, int(n_methods))
            client.sendall(b"\x05\x00")  # NOAUTH accepted

            # Request: VER CMD RSV ATYP ...
            req_head = _read_exact(client, 4)
            ver, cmd, _rsv, atyp = req_head
            if ver != 5:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                return
            try:
                host, port = _read_socks_addr(client, atyp)
            except Exception:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if cmd == 1:  # CONNECT
                upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream.settimeout(5.0)
                upstream.connect((host, int(port)))

                bound_ip = socket.inet_aton("127.0.0.1")
                bound_port = struct.pack("!H", 0)
                client.sendall(b"\x05\x00\x00\x01" + bound_ip + bound_port)

                client.settimeout(None)
                upstream.settimeout(None)
                self._relay_bidi(client, upstream)
                return

            if cmd == 3:  # UDP ASSOCIATE
                udp_relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_relay.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_relay.bind((self.host, 0))
                relay_host, relay_port = udp_relay.getsockname()
                client.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(str(relay_host)) + struct.pack("!H", int(relay_port)))

                client_udp_addr: tuple[str, int] | None = None

                def _udp_loop() -> None:
                    nonlocal client_udp_addr
                    assert udp_relay is not None
                    while not udp_stop.is_set():
                        try:
                            udp_relay.settimeout(0.5)
                            data, src = udp_relay.recvfrom(65535)
                        except socket.timeout:
                            continue
                        except OSError:
                            return
                        if not data:
                            continue
                        src_host, src_port = str(src[0]), int(src[1])
                        # Client-to-target leg (first sender pins client UDP endpoint).
                        if client_udp_addr is None or (src_host, src_port) == client_udp_addr:
                            if client_udp_addr is None:
                                client_udp_addr = (src_host, src_port)
                            try:
                                frag, dst_host, dst_port, payload = _socks5_udp_unwrap(data)
                            except Exception:
                                continue
                            if int(frag) != 0:
                                continue
                            try:
                                udp_relay.sendto(payload, (dst_host, int(dst_port)))
                            except OSError:
                                continue
                            continue
                        # Target-to-client leg.
                        if client_udp_addr is None:
                            continue
                        try:
                            pkt = _socks5_udp_wrap(payload=data, dst_host=src_host, dst_port=src_port)
                            udp_relay.sendto(pkt, client_udp_addr)
                        except Exception:
                            continue

                udp_thread = threading.Thread(target=_udp_loop, daemon=True)
                udp_thread.start()
                client.settimeout(0.5)
                while not udp_stop.is_set():
                    try:
                        chunk = client.recv(1)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                return

            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        except Exception:
            return
        finally:
            udp_stop.set()
            if udp_thread is not None:
                udp_thread.join(timeout=1.0)
            if udp_relay is not None:
                try:
                    udp_relay.close()
                except Exception:
                    pass
            try:
                client.close()
            except Exception:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    @staticmethod
    def _relay_bidi(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        while True:
            r, _w, _x = select.select(sockets, [], [], 1.0)
            if not r:
                continue
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(65535)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return


def _direct_connect(*, host: str, port: int, timeout_s: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout_s))
    s.connect((host, int(port)))
    return s


def _socks_connect(*, socks_host: str, socks_port: int, target_host: str, target_port: int, timeout_s: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout_s))
    s.connect((socks_host, int(socks_port)))
    s.sendall(b"\x05\x01\x00")
    if _read_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed (NOAUTH not accepted)")
    ip = socket.inet_aton(target_host)
    req = b"\x05\x01\x00\x01" + ip + struct.pack("!H", int(target_port))
    s.sendall(req)
    head = _read_exact(s, 4)
    if head[0] != 0x05 or head[1] != 0x00:
        raise RuntimeError(f"SOCKS CONNECT failed: rep=0x{head[1]:02x}")
    atyp = head[3]
    if atyp == 0x01:
        _read_exact(s, 4)
    elif atyp == 0x03:
        ln = _read_exact(s, 1)[0]
        _read_exact(s, ln)
    elif atyp == 0x04:
        _read_exact(s, 16)
    else:
        raise RuntimeError(f"unsupported SOCKS ATYP: {atyp}")
    _read_exact(s, 2)
    return s


def _socks_udp_associate(
    *,
    socks_host: str,
    socks_port: int,
    timeout_s: float,
) -> tuple[socket.socket, socket.socket, tuple[str, int]]:
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(float(timeout_s))
    ctrl.connect((socks_host, int(socks_port)))
    ctrl.sendall(b"\x05\x01\x00")
    if _read_exact(ctrl, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed (NOAUTH not accepted)")
    # UDP ASSOCIATE with wildcard client endpoint.
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = _read_exact(ctrl, 4)
    if head[0] != 0x05 or head[1] != 0x00:
        raise RuntimeError(f"SOCKS UDP ASSOCIATE failed: rep=0x{head[1]:02x}")
    relay_host, relay_port = _read_socks_addr(ctrl, int(head[3]))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(float(timeout_s))
    udp.bind(("0.0.0.0", 0))
    return ctrl, udp, (str(relay_host), int(relay_port))


def _measure_udp_assoc_connect_latency(
    *,
    socks_host: str,
    socks_port: int,
    timeout_s: float,
    count: int,
    warmup: int,
) -> tuple[list[int], list[str]]:
    lat_us: list[int] = []
    errors: list[str] = []
    for _ in range(max(0, int(warmup))):
        ctrl: socket.socket | None = None
        udp: socket.socket | None = None
        try:
            ctrl, udp, _relay = _socks_udp_associate(
                socks_host=socks_host,
                socks_port=socks_port,
                timeout_s=timeout_s,
            )
        except Exception:
            pass
        finally:
            if udp is not None:
                try:
                    udp.close()
                except Exception:
                    pass
            if ctrl is not None:
                try:
                    ctrl.close()
                except Exception:
                    pass
    for i in range(max(0, int(count))):
        ctrl = None
        udp = None
        try:
            t0 = time.perf_counter_ns()
            ctrl, udp, _relay = _socks_udp_associate(
                socks_host=socks_host,
                socks_port=socks_port,
                timeout_s=timeout_s,
            )
            t1 = time.perf_counter_ns()
            lat_us.append(int(max(0, (t1 - t0) // 1000)))
        except Exception as exc:
            errors.append(f"udp_assoc_idx={i}:{exc}")
        finally:
            if udp is not None:
                try:
                    udp.close()
                except Exception:
                    pass
            if ctrl is not None:
                try:
                    ctrl.close()
                except Exception:
                    pass
    return lat_us, errors


def _measure_udp_rtt_latency_direct(
    *,
    target_host: str,
    target_port: int,
    timeout_s: float,
    payload: bytes,
    count: int,
    warmup: int,
) -> tuple[list[int], list[str]]:
    lat_us: list[int] = []
    errors: list[str] = []
    s: socket.socket | None = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(float(timeout_s))
        for _ in range(max(0, int(warmup))):
            s.sendto(payload, (target_host, int(target_port)))
            s.recvfrom(max(65535, len(payload) + 64))
        for i in range(max(0, int(count))):
            try:
                t0 = time.perf_counter_ns()
                s.sendto(payload, (target_host, int(target_port)))
                got, _ = s.recvfrom(max(65535, len(payload) + 64))
                t1 = time.perf_counter_ns()
                if got != payload:
                    raise RuntimeError("udp_echo_mismatch")
                lat_us.append(int(max(0, (t1 - t0) // 1000)))
            except Exception as exc:
                errors.append(f"udp_direct_rtt_idx={i}:{exc}")
    except Exception as exc:
        errors.append(f"udp_direct_setup:{exc}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return lat_us, errors


def _measure_udp_rtt_latency_socks(
    *,
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout_s: float,
    payload: bytes,
    count: int,
    warmup: int,
    per_message_assoc: bool,
) -> tuple[list[int], list[str]]:
    lat_us: list[int] = []
    errors: list[str] = []

    def _one_round(udp: socket.socket, relay: tuple[str, int]) -> int:
        pkt = _socks5_udp_wrap(payload=payload, dst_host=target_host, dst_port=int(target_port))
        t0 = time.perf_counter_ns()
        udp.sendto(pkt, relay)
        got, _ = udp.recvfrom(max(65535, len(payload) + 64))
        t1 = time.perf_counter_ns()
        frag, src_host, src_port, data = _socks5_udp_unwrap(got)
        if int(frag) != 0:
            raise RuntimeError("udp_frag_not_supported")
        if int(src_port) != int(target_port):
            raise RuntimeError(f"udp_source_port_mismatch:{src_port}")
        # Normalize localhost aliases.
        normalized_src = "127.0.0.1" if src_host in {"localhost", "::1"} else src_host
        normalized_dst = "127.0.0.1" if target_host in {"localhost", "::1"} else target_host
        if normalized_src != normalized_dst:
            raise RuntimeError(f"udp_source_host_mismatch:{src_host}")
        if data != payload:
            raise RuntimeError("udp_echo_mismatch")
        return int(max(0, (t1 - t0) // 1000))

    if bool(per_message_assoc):
        for _ in range(max(0, int(warmup))):
            ctrl = None
            udp = None
            try:
                ctrl, udp, relay = _socks_udp_associate(
                    socks_host=socks_host,
                    socks_port=socks_port,
                    timeout_s=timeout_s,
                )
                _one_round(udp, relay)
            except Exception:
                pass
            finally:
                if udp is not None:
                    try:
                        udp.close()
                    except Exception:
                        pass
                if ctrl is not None:
                    try:
                        ctrl.close()
                    except Exception:
                        pass
        for i in range(max(0, int(count))):
            ctrl = None
            udp = None
            try:
                ctrl, udp, relay = _socks_udp_associate(
                    socks_host=socks_host,
                    socks_port=socks_port,
                    timeout_s=timeout_s,
                )
                lat_us.append(_one_round(udp, relay))
            except Exception as exc:
                errors.append(f"udp_socks_rtt_idx={i}:{exc}")
            finally:
                if udp is not None:
                    try:
                        udp.close()
                    except Exception:
                        pass
                if ctrl is not None:
                    try:
                        ctrl.close()
                    except Exception:
                        pass
        return lat_us, errors

    ctrl = None
    udp = None
    try:
        ctrl, udp, relay = _socks_udp_associate(
            socks_host=socks_host,
            socks_port=socks_port,
            timeout_s=timeout_s,
        )
        for _ in range(max(0, int(warmup))):
            try:
                _one_round(udp, relay)
            except Exception:
                pass
        for i in range(max(0, int(count))):
            try:
                lat_us.append(_one_round(udp, relay))
            except Exception as exc:
                errors.append(f"udp_socks_rtt_idx={i}:{exc}")
    except Exception as exc:
        errors.append(f"udp_socks_setup:{exc}")
    finally:
        if udp is not None:
            try:
                udp.close()
            except Exception:
                pass
        if ctrl is not None:
            try:
                ctrl.close()
            except Exception:
                pass
    return lat_us, errors


def _measure_udp_bandwidth_direct(
    *,
    target_host: str,
    target_port: int,
    timeout_s: float,
    chunk_size: int,
    chunk_count: int,
    warmup_chunks: int,
) -> dict[str, Any]:
    payload = b"u" * max(1, int(chunk_size))
    bytes_total = 0
    ops_ok = 0
    ops_failed = 0
    errors: list[str] = []
    t0 = time.perf_counter()
    s: socket.socket | None = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(float(timeout_s))
        for _ in range(max(0, int(warmup_chunks))):
            s.sendto(payload, (target_host, int(target_port)))
            s.recvfrom(max(65535, len(payload) + 64))
        for i in range(max(0, int(chunk_count))):
            try:
                s.sendto(payload, (target_host, int(target_port)))
                got, _ = s.recvfrom(max(65535, len(payload) + 64))
                if got != payload:
                    raise RuntimeError("udp_echo_mismatch")
                ops_ok += 1
                bytes_total += len(payload)
            except Exception as exc:
                ops_failed += 1
                errors.append(f"chunk_idx={i}:{exc}")
                break
    except Exception as exc:
        ops_failed += max(1, int(chunk_count))
        errors.append(f"udp_stream_setup:{exc}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    t1 = time.perf_counter()
    out = _throughput_stats(bytes_total=bytes_total, duration_s=(t1 - t0), ops_ok=ops_ok, ops_failed=ops_failed)
    out["errors"] = errors[:10]
    out["chunk_size"] = int(chunk_size)
    out["chunk_count"] = int(chunk_count)
    return out


def _measure_udp_bandwidth_socks(
    *,
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout_s: float,
    chunk_size: int,
    chunk_count: int,
    warmup_chunks: int,
) -> dict[str, Any]:
    payload = b"u" * max(1, int(chunk_size))
    bytes_total = 0
    ops_ok = 0
    ops_failed = 0
    errors: list[str] = []
    t0 = time.perf_counter()
    ctrl = None
    udp = None
    try:
        ctrl, udp, relay = _socks_udp_associate(
            socks_host=socks_host,
            socks_port=socks_port,
            timeout_s=timeout_s,
        )
        for _ in range(max(0, int(warmup_chunks))):
            pkt = _socks5_udp_wrap(payload=payload, dst_host=target_host, dst_port=int(target_port))
            udp.sendto(pkt, relay)
            udp.recvfrom(max(65535, len(payload) + 64))
        for i in range(max(0, int(chunk_count))):
            try:
                pkt = _socks5_udp_wrap(payload=payload, dst_host=target_host, dst_port=int(target_port))
                udp.sendto(pkt, relay)
                got, _ = udp.recvfrom(max(65535, len(payload) + 64))
                frag, _src_host, src_port, data = _socks5_udp_unwrap(got)
                if int(frag) != 0 or int(src_port) != int(target_port) or data != payload:
                    raise RuntimeError("udp_echo_mismatch")
                ops_ok += 1
                bytes_total += len(payload)
            except Exception as exc:
                ops_failed += 1
                errors.append(f"chunk_idx={i}:{exc}")
                break
    except Exception as exc:
        ops_failed += max(1, int(chunk_count))
        errors.append(f"udp_stream_setup:{exc}")
    finally:
        if udp is not None:
            try:
                udp.close()
            except Exception:
                pass
        if ctrl is not None:
            try:
                ctrl.close()
            except Exception:
                pass
    t1 = time.perf_counter()
    out = _throughput_stats(bytes_total=bytes_total, duration_s=(t1 - t0), ops_ok=ops_ok, ops_failed=ops_failed)
    out["errors"] = errors[:10]
    out["chunk_size"] = int(chunk_size)
    out["chunk_count"] = int(chunk_count)
    return out


def _measure_connect_latency(
    *,
    connect_fn: Callable[[], socket.socket],
    count: int,
    warmup: int,
) -> tuple[list[int], list[str]]:
    lat_us: list[int] = []
    errors: list[str] = []

    for _ in range(max(0, int(warmup))):
        s: socket.socket | None = None
        try:
            s = connect_fn()
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    for i in range(max(0, int(count))):
        s: socket.socket | None = None
        try:
            t0 = time.perf_counter_ns()
            s = connect_fn()
            t1 = time.perf_counter_ns()
            lat_us.append(int(max(0, (t1 - t0) // 1000)))
        except Exception as exc:
            errors.append(f"connect_idx={i}:{exc}")
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return lat_us, errors


def _measure_rtt_latency(
    *,
    connect_fn: Callable[[], socket.socket],
    payload: bytes,
    count: int,
    warmup: int,
    per_message_conn: bool,
) -> tuple[list[int], list[str]]:
    lat_us: list[int] = []
    errors: list[str] = []
    payload = bytes(payload)

    def _one_round(sock: socket.socket) -> int:
        t0 = time.perf_counter_ns()
        sock.sendall(payload)
        got = _recv_until(sock, len(payload))
        t1 = time.perf_counter_ns()
        if got != payload:
            raise RuntimeError("echo_mismatch")
        return int(max(0, (t1 - t0) // 1000))

    if bool(per_message_conn):
        for _ in range(max(0, int(warmup))):
            s: socket.socket | None = None
            try:
                s = connect_fn()
                _one_round(s)
            except Exception:
                pass
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        for i in range(max(0, int(count))):
            s: socket.socket | None = None
            try:
                s = connect_fn()
                lat_us.append(_one_round(s))
            except Exception as exc:
                errors.append(f"rtt_idx={i}:{exc}")
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        return lat_us, errors

    s2: socket.socket | None = None
    try:
        s2 = connect_fn()
        for _ in range(max(0, int(warmup))):
            try:
                _one_round(s2)
            except Exception:
                # reconnect once during warmup path
                try:
                    s2.close()
                except Exception:
                    pass
                s2 = connect_fn()
        for i in range(max(0, int(count))):
            try:
                lat_us.append(_one_round(s2))
            except Exception as exc:
                errors.append(f"rtt_idx={i}:{exc}")
                break
    except Exception as exc:
        errors.append(f"rtt_setup:{exc}")
    finally:
        if s2 is not None:
            try:
                s2.close()
            except Exception:
                pass
    return lat_us, errors


def _measure_stream_bandwidth(
    *,
    connect_fn: Callable[[], socket.socket],
    chunk_size: int,
    chunk_count: int,
    warmup_chunks: int,
) -> dict[str, Any]:
    data = b"x" * max(1, int(chunk_size))
    bytes_total = 0
    ops_ok = 0
    ops_failed = 0
    errors: list[str] = []
    t0 = time.perf_counter()
    s: socket.socket | None = None
    try:
        s = connect_fn()
        for _ in range(max(0, int(warmup_chunks))):
            s.sendall(data)
            _recv_until(s, len(data))
        for i in range(max(0, int(chunk_count))):
            try:
                s.sendall(data)
                got = _recv_until(s, len(data))
                if got != data:
                    ops_failed += 1
                    errors.append(f"chunk_idx={i}:echo_mismatch")
                    continue
                ops_ok += 1
                bytes_total += len(data)
            except Exception as exc:
                ops_failed += 1
                errors.append(f"chunk_idx={i}:{exc}")
                break
    except Exception as exc:
        ops_failed += max(1, int(chunk_count))
        errors.append(f"stream_setup:{exc}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    t1 = time.perf_counter()
    out = _throughput_stats(bytes_total=bytes_total, duration_s=(t1 - t0), ops_ok=ops_ok, ops_failed=ops_failed)
    out["errors"] = errors[:10]
    out["chunk_size"] = int(chunk_size)
    out["chunk_count"] = int(chunk_count)
    return out


def _measure_concurrency_bandwidth(
    *,
    connect_fn: Callable[[], socket.socket],
    workers: int,
    chunk_size: int,
    chunks_per_worker: int,
    warmup_chunks: int,
) -> dict[str, Any]:
    worker_results: list[dict[str, Any] | None] = [None for _ in range(max(1, int(workers)))]

    def _worker(idx: int) -> None:
        worker_results[idx] = _measure_stream_bandwidth(
            connect_fn=connect_fn,
            chunk_size=int(chunk_size),
            chunk_count=int(chunks_per_worker),
            warmup_chunks=int(warmup_chunks),
        )

    threads: list[threading.Thread] = []
    t0 = time.perf_counter()
    for i in range(len(worker_results)):
        th = threading.Thread(target=_worker, args=(i,), daemon=True)
        threads.append(th)
        th.start()
    for th in threads:
        th.join()
    t1 = time.perf_counter()

    bytes_total = 0
    ops_ok = 0
    ops_failed = 0
    worker_errors: list[str] = []
    for i, res in enumerate(worker_results):
        if res is None:
            ops_failed += int(chunks_per_worker)
            worker_errors.append(f"worker={i}:missing_result")
            continue
        bytes_total += int(res.get("bytes_total", 0))
        ops_ok += int(res.get("ops_ok", 0))
        ops_failed += int(res.get("ops_failed", 0))
        for err in list(res.get("errors", []))[:2]:
            worker_errors.append(f"worker={i}:{err}")

    out = _throughput_stats(bytes_total=bytes_total, duration_s=(t1 - t0), ops_ok=ops_ok, ops_failed=ops_failed)
    out.update(
        {
            "workers": int(workers),
            "chunk_size": int(chunk_size),
            "chunks_per_worker": int(chunks_per_worker),
            "worker_errors": worker_errors[:20],
            "worker_result_count": len(worker_results),
        }
    )
    return out


def _configure_scenario(args: argparse.Namespace) -> argparse.Namespace:
    scenario = str(args.scenario).strip().lower()
    if scenario == "smoke":
        args.latency_connect_count = min(int(args.latency_connect_count), 12)
        args.latency_rtt_count = min(int(args.latency_rtt_count), 24)
        args.latency_sizes = "64,256"
        args.bandwidth_cases = "16384x32"
        args.concurrency_levels = "2"
        args.concurrency_chunk_size = min(int(args.concurrency_chunk_size), 16384)
        args.concurrency_chunks_per_worker = min(int(args.concurrency_chunks_per_worker), 24)
    elif scenario == "latency":
        args.latency_connect_count = max(int(args.latency_connect_count), 300)
        args.latency_rtt_count = max(int(args.latency_rtt_count), 500)
        args.latency_sizes = "32,64,256,1024"
        args.bandwidth_cases = "32768x32"
        args.concurrency_levels = "1,2"
    elif scenario == "bandwidth":
        args.latency_connect_count = min(int(args.latency_connect_count), 80)
        args.latency_rtt_count = min(int(args.latency_rtt_count), 120)
        args.latency_sizes = "128,1024"
        args.bandwidth_cases = "65536x128,262144x64,1048576x16"
        args.concurrency_levels = "1,2,4"
        args.concurrency_chunk_size = max(int(args.concurrency_chunk_size), 65536)
        args.concurrency_chunks_per_worker = max(int(args.concurrency_chunks_per_worker), 64)
    else:
        # full
        args.latency_sizes = str(args.latency_sizes)
    return args


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=["mock", "external", "managed-service"], default="mock")
    p.add_argument("--scenario", choices=["smoke", "latency", "bandwidth", "full"], default="full")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--target-host", default="127.0.0.1")
    p.add_argument("--target-port", type=int, default=0)
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--timeout-s", type=float, default=5.0)
    p.add_argument("--warmup-connect", type=int, default=5)
    p.add_argument("--warmup-rtt", type=int, default=5)
    p.add_argument("--warmup-bandwidth-chunks", type=int, default=2)

    # Latency battery
    p.add_argument("--latency-connect-count", type=int, default=200)
    p.add_argument("--latency-rtt-count", type=int, default=300)
    p.add_argument("--latency-sizes", default="64,256,1024")
    p.add_argument("--latency-per-message-conn", action="store_true")
    p.add_argument("--udp-enable", action="store_true")
    p.add_argument("--udp-target-host", default="")
    p.add_argument("--udp-target-port", type=int, default=0)
    p.add_argument("--udp-rtt-count", type=int, default=120)
    p.add_argument("--udp-warmup-rtt", type=int, default=3)
    p.add_argument("--udp-per-message-assoc", action="store_true")
    p.add_argument("--udp-bandwidth-cases", default="")
    p.add_argument("--udp-warmup-bandwidth-chunks", type=int, default=1)

    # Bandwidth battery
    p.add_argument("--bandwidth-cases", default="65536x64,262144x32")
    p.add_argument("--concurrency-levels", default="1,4")
    p.add_argument("--concurrency-chunk-size", type=int, default=65536)
    p.add_argument("--concurrency-chunks-per-worker", type=int, default=48)

    # Optional performance gates
    p.add_argument("--max-connect-p95-us", type=int, default=0)
    p.add_argument("--max-rtt-p95-us", type=int, default=0)
    p.add_argument("--min-socks-throughput-mbps", type=float, default=0.0)

    # managed-service options
    p.add_argument("--weaverssh-repo", default=str(Path.home() / "weaverssh"))
    p.add_argument("--agent-listen", default="localhost:6000")
    p.add_argument("--agent-endpoint", default="localhost:6000")

    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main() -> int:
    args = _configure_scenario(parse_args())

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    tmp_dir = Path(tempfile.gettempdir())
    echo_server: EchoServer | None = None
    udp_echo_server: UDPEchoServer | None = None
    socks_proxy: MiniSocks5Proxy | None = None
    managed_started = False

    target_host = str(args.target_host)
    target_port = int(args.target_port)
    udp_target_host = str(args.udp_target_host or args.target_host)
    udp_target_port = int(args.udp_target_port)
    socks_host = str(args.socks_host)
    socks_port = int(args.socks_port)

    service_script = REPO_ROOT / "tools" / "verification" / "sshx11_socks_fallback_service.py"

    latency_sizes = _parse_int_csv(str(args.latency_sizes), minimum=1)
    bw_cases = _parse_bw_cases(str(args.bandwidth_cases))
    udp_bw_cases = (
        _parse_bw_cases(str(args.udp_bandwidth_cases))
        if str(args.udp_bandwidth_cases).strip()
        else _derive_udp_bw_cases(bw_cases)
    )
    conc_levels = _parse_int_csv(str(args.concurrency_levels), minimum=1)

    if bool(args.dry_run):
        conn_acc = _build_connection_accounting(
            latency_connect_count=int(args.latency_connect_count),
            latency_per_message_conn=bool(args.latency_per_message_conn),
            rtt_cases_count=len(latency_sizes),
            rtt_count_each=int(args.latency_rtt_count),
            stream_cases_count=len(bw_cases),
            concurrency_levels=conc_levels,
        )
        dry = {
            "ok": True,
            "status": "dry_run",
            "mode": str(args.mode),
            "target": {"host": str(target_host), "port": int(target_port)},
            "udp_target": {"host": str(udp_target_host), "port": int(udp_target_port)},
            "socks": {"host": str(socks_host), "port": int(socks_port)},
            "battery_config": {
                "scenario": str(args.scenario),
                "latency_connect_count": int(args.latency_connect_count),
                "latency_rtt_count": int(args.latency_rtt_count),
                "latency_sizes": latency_sizes,
                "latency_per_message_conn": bool(args.latency_per_message_conn),
                "udp_enable": bool(args.udp_enable),
                "udp_target_host": str(udp_target_host),
                "udp_target_port": int(udp_target_port),
                "udp_rtt_count": int(args.udp_rtt_count),
                "udp_warmup_rtt": int(args.udp_warmup_rtt),
                "udp_per_message_assoc": bool(args.udp_per_message_assoc),
                "udp_bandwidth_cases": [{"chunk_size": int(a), "chunk_count": int(b)} for (a, b) in udp_bw_cases],
                "udp_warmup_bandwidth_chunks": int(args.udp_warmup_bandwidth_chunks),
                "bandwidth_cases": [{"chunk_size": int(a), "chunk_count": int(b)} for (a, b) in bw_cases],
                "concurrency_levels": conc_levels,
                "concurrency_chunk_size": int(args.concurrency_chunk_size),
                "concurrency_chunks_per_worker": int(args.concurrency_chunks_per_worker),
                "warmup_connect": int(args.warmup_connect),
                "warmup_rtt": int(args.warmup_rtt),
                "warmup_bandwidth_chunks": int(args.warmup_bandwidth_chunks),
            },
            "gates": {
                "max_connect_p95_us": int(args.max_connect_p95_us),
                "max_rtt_p95_us": int(args.max_rtt_p95_us),
                "min_socks_throughput_mbps": float(args.min_socks_throughput_mbps),
            },
            "connection_accounting": conn_acc,
        }
        output.write_text(json.dumps(dry, indent=2) + "\n", encoding="utf-8")
        print("ok=True")
        print("status=dry_run")
        print(f"output={output}")
        return 0

    try:
        if str(args.mode) == "mock":
            echo_server = EchoServer(host=str(args.host), port=target_port if target_port > 0 else 0)
            echo_server.start()
            target_host = str(args.host)
            target_port = int(echo_server.bound_port)
            if bool(args.udp_enable):
                udp_echo_server = UDPEchoServer(host=str(args.host), port=udp_target_port if udp_target_port > 0 else 0)
                udp_echo_server.start()
                udp_target_host = str(args.host)
                udp_target_port = int(udp_echo_server.bound_port)

            socks_proxy = MiniSocks5Proxy(host=str(args.host), port=socks_port if socks_port > 0 else 0)
            socks_proxy.start()
            socks_host = str(args.host)
            socks_port = int(socks_proxy.bound_port)
        elif str(args.mode) == "managed-service":
            if target_port <= 0:
                echo_server = EchoServer(host=target_host, port=0)
                echo_server.start()
                target_port = int(echo_server.bound_port)
            if bool(args.udp_enable) and udp_target_port <= 0:
                udp_echo_server = UDPEchoServer(host=udp_target_host, port=0)
                udp_echo_server.start()
                udp_target_port = int(udp_echo_server.bound_port)
            cmd = [
                sys.executable,
                str(service_script),
                "--weaverssh-repo",
                str(args.weaverssh_repo),
                "--socks-host",
                str(socks_host),
                "--socks-port",
                str(socks_port),
                "--agent-listen",
                str(args.agent_listen),
                "--agent-endpoint",
                str(args.agent_endpoint),
                "start",
            ]
            rc, out = _run_cmd(cmd)
            if rc != 0:
                raise RuntimeError(f"managed_service_start_failed:{out}")
            managed_started = True
            time.sleep(0.6)
        else:
            if target_port <= 0:
                raise ValueError("--target-port is required in external mode")
            if bool(args.udp_enable) and udp_target_port <= 0:
                raise ValueError("--udp-target-port is required in external mode when --udp-enable is set")

        direct_connect = lambda: _direct_connect(host=target_host, port=target_port, timeout_s=float(args.timeout_s))
        socks_connect = lambda: _socks_connect(
            socks_host=socks_host,
            socks_port=socks_port,
            target_host=target_host,
            target_port=target_port,
            timeout_s=float(args.timeout_s),
        )

        # Validate connectivity before running battery.
        s0 = direct_connect()
        s0.close()
        s1 = socks_connect()
        s1.close()

        udp_connect_direct_stats: dict[str, Any] | None = None
        udp_connect_socks_stats: dict[str, Any] | None = None
        udp_latency_cases: list[dict[str, Any]] = []
        udp_bw_stream_cases: list[dict[str, Any]] = []
        udp_enabled = bool(args.udp_enable)
        if udp_enabled:
            direct_udp_samples, direct_udp_errors = _measure_connect_latency(
                connect_fn=lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                count=int(max(1, min(64, int(args.latency_connect_count)))),
                warmup=int(max(0, min(8, int(args.warmup_connect)))),
            )
            socks_udp_samples, socks_udp_errors = _measure_udp_assoc_connect_latency(
                socks_host=socks_host,
                socks_port=socks_port,
                timeout_s=float(args.timeout_s),
                count=int(max(1, min(64, int(args.latency_connect_count)))),
                warmup=int(max(0, min(8, int(args.warmup_connect)))),
            )
            udp_connect_direct_stats = {**_latency_stats(direct_udp_samples), "errors": direct_udp_errors[:10]}
            udp_connect_socks_stats = {**_latency_stats(socks_udp_samples), "errors": socks_udp_errors[:10]}

            for sz in latency_sizes:
                payload = b"u" * int(sz)
                d_samples, d_errors = _measure_udp_rtt_latency_direct(
                    target_host=udp_target_host,
                    target_port=int(udp_target_port),
                    timeout_s=float(args.timeout_s),
                    payload=payload,
                    count=int(args.udp_rtt_count),
                    warmup=int(args.udp_warmup_rtt),
                )
                s_samples, s_errors = _measure_udp_rtt_latency_socks(
                    socks_host=socks_host,
                    socks_port=socks_port,
                    target_host=udp_target_host,
                    target_port=int(udp_target_port),
                    timeout_s=float(args.timeout_s),
                    payload=payload,
                    count=int(args.udp_rtt_count),
                    warmup=int(args.udp_warmup_rtt),
                    per_message_assoc=bool(args.udp_per_message_assoc),
                )
                d_stats = _latency_stats(d_samples)
                s_stats = _latency_stats(s_samples)
                udp_latency_cases.append(
                    {
                        "payload_bytes": int(sz),
                        "count": int(args.udp_rtt_count),
                        "direct": {**d_stats, "errors": d_errors[:10]},
                        "socks": {**s_stats, "errors": s_errors[:10]},
                        "socks_vs_direct_p95_overhead_pct": _ratio_pct(
                            float(s_stats["p95_us"]), float(d_stats["p95_us"])
                        ),
                    }
                )

            for chunk_size, chunk_count in udp_bw_cases:
                direct = _measure_udp_bandwidth_direct(
                    target_host=udp_target_host,
                    target_port=int(udp_target_port),
                    timeout_s=float(args.timeout_s),
                    chunk_size=int(chunk_size),
                    chunk_count=int(chunk_count),
                    warmup_chunks=int(args.udp_warmup_bandwidth_chunks),
                )
                socks = _measure_udp_bandwidth_socks(
                    socks_host=socks_host,
                    socks_port=socks_port,
                    target_host=udp_target_host,
                    target_port=int(udp_target_port),
                    timeout_s=float(args.timeout_s),
                    chunk_size=int(chunk_size),
                    chunk_count=int(chunk_count),
                    warmup_chunks=int(args.udp_warmup_bandwidth_chunks),
                )
                udp_bw_stream_cases.append(
                    {
                        "chunk_size": int(chunk_size),
                        "chunk_count": int(chunk_count),
                        "direct": direct,
                        "socks": socks,
                        "socks_vs_direct_mbps_delta_pct": _ratio_pct(
                            float(socks.get("mbps", 0.0)), float(direct.get("mbps", 0.0))
                        ),
                    }
                )

        # Latency: connect setup
        direct_conn_samples, direct_conn_errors = _measure_connect_latency(
            connect_fn=direct_connect,
            count=int(args.latency_connect_count),
            warmup=int(args.warmup_connect),
        )
        socks_conn_samples, socks_conn_errors = _measure_connect_latency(
            connect_fn=socks_connect,
            count=int(args.latency_connect_count),
            warmup=int(args.warmup_connect),
        )
        direct_conn_stats = _latency_stats(direct_conn_samples)
        socks_conn_stats = _latency_stats(socks_conn_samples)

        latency_cases: list[dict[str, Any]] = []
        for sz in latency_sizes:
            payload = b"l" * int(sz)
            direct_samples, direct_errors = _measure_rtt_latency(
                connect_fn=direct_connect,
                payload=payload,
                count=int(args.latency_rtt_count),
                warmup=int(args.warmup_rtt),
                per_message_conn=bool(args.latency_per_message_conn),
            )
            socks_samples, socks_errors = _measure_rtt_latency(
                connect_fn=socks_connect,
                payload=payload,
                count=int(args.latency_rtt_count),
                warmup=int(args.warmup_rtt),
                per_message_conn=bool(args.latency_per_message_conn),
            )
            direct_stats = _latency_stats(direct_samples)
            socks_stats = _latency_stats(socks_samples)
            latency_cases.append(
                {
                    "payload_bytes": int(sz),
                    "count": int(args.latency_rtt_count),
                    "direct": {**direct_stats, "errors": direct_errors[:10]},
                    "socks": {**socks_stats, "errors": socks_errors[:10]},
                    "socks_vs_direct_p95_overhead_pct": _ratio_pct(
                        float(socks_stats["p95_us"]),
                        float(direct_stats["p95_us"]),
                    ),
                }
            )

        # Bandwidth: single stream
        bw_stream_cases: list[dict[str, Any]] = []
        for chunk_size, chunk_count in bw_cases:
            direct = _measure_stream_bandwidth(
                connect_fn=direct_connect,
                chunk_size=int(chunk_size),
                chunk_count=int(chunk_count),
                warmup_chunks=int(args.warmup_bandwidth_chunks),
            )
            socks = _measure_stream_bandwidth(
                connect_fn=socks_connect,
                chunk_size=int(chunk_size),
                chunk_count=int(chunk_count),
                warmup_chunks=int(args.warmup_bandwidth_chunks),
            )
            bw_stream_cases.append(
                {
                    "chunk_size": int(chunk_size),
                    "chunk_count": int(chunk_count),
                    "direct": direct,
                    "socks": socks,
                    "socks_vs_direct_mbps_delta_pct": _ratio_pct(
                        float(socks.get("mbps", 0.0)),
                        float(direct.get("mbps", 0.0)),
                    ),
                }
            )

        # Bandwidth: concurrency
        bw_conc_cases: list[dict[str, Any]] = []
        for workers in conc_levels:
            direct = _measure_concurrency_bandwidth(
                connect_fn=direct_connect,
                workers=int(workers),
                chunk_size=int(args.concurrency_chunk_size),
                chunks_per_worker=int(args.concurrency_chunks_per_worker),
                warmup_chunks=int(args.warmup_bandwidth_chunks),
            )
            socks = _measure_concurrency_bandwidth(
                connect_fn=socks_connect,
                workers=int(workers),
                chunk_size=int(args.concurrency_chunk_size),
                chunks_per_worker=int(args.concurrency_chunks_per_worker),
                warmup_chunks=int(args.warmup_bandwidth_chunks),
            )
            bw_conc_cases.append(
                {
                    "workers": int(workers),
                    "chunk_size": int(args.concurrency_chunk_size),
                    "chunks_per_worker": int(args.concurrency_chunks_per_worker),
                    "direct": direct,
                    "socks": socks,
                    "socks_vs_direct_mbps_delta_pct": _ratio_pct(
                        float(socks.get("mbps", 0.0)),
                        float(direct.get("mbps", 0.0)),
                    ),
                }
            )

        # Optional gates
        gate_failures: list[str] = []
        if int(args.max_connect_p95_us) > 0 and int(socks_conn_stats["p95_us"]) > int(args.max_connect_p95_us):
            gate_failures.append(
                f"connect_p95_exceeded:{socks_conn_stats['p95_us']} > {int(args.max_connect_p95_us)}"
            )
        if int(args.max_rtt_p95_us) > 0:
            for case in latency_cases:
                p95 = int(case["socks"]["p95_us"])
                if p95 > int(args.max_rtt_p95_us):
                    gate_failures.append(
                        f"rtt_p95_exceeded:size={case['payload_bytes']}:{p95} > {int(args.max_rtt_p95_us)}"
                    )
        if float(args.min_socks_throughput_mbps) > 0.0:
            for case in bw_stream_cases:
                mbps = float(case["socks"].get("mbps", 0.0))
                if mbps < float(args.min_socks_throughput_mbps):
                    gate_failures.append(
                        f"socks_throughput_below_min:chunk={case['chunk_size']}x{case['chunk_count']}:{mbps:.3f} < {float(args.min_socks_throughput_mbps):.3f}"
                    )

        latency_ok = (len(direct_conn_errors) == 0) and (len(socks_conn_errors) == 0) and all(
            len(c["direct"]["errors"]) == 0 and len(c["socks"]["errors"]) == 0 for c in latency_cases
        )
        bandwidth_ok = all(bool(c["direct"].get("ok")) and bool(c["socks"].get("ok")) for c in bw_stream_cases) and all(
            bool(c["direct"].get("ok")) and bool(c["socks"].get("ok")) for c in bw_conc_cases
        )
        udp_ok = True
        if udp_enabled:
            udp_ok = (
                bool(udp_connect_direct_stats)
                and bool(udp_connect_socks_stats)
                and len(list(udp_connect_direct_stats.get("errors", []))) == 0
                and len(list(udp_connect_socks_stats.get("errors", []))) == 0
                and all(len(c["direct"]["errors"]) == 0 and len(c["socks"]["errors"]) == 0 for c in udp_latency_cases)
                and all(bool(c["direct"].get("ok")) and bool(c["socks"].get("ok")) for c in udp_bw_stream_cases)
            )
        gates_ok = len(gate_failures) == 0
        ok = bool(latency_ok and bandwidth_ok and udp_ok and gates_ok)
        conn_acc = _build_connection_accounting(
            latency_connect_count=int(args.latency_connect_count),
            latency_per_message_conn=bool(args.latency_per_message_conn),
            rtt_cases_count=len(latency_cases),
            rtt_count_each=int(args.latency_rtt_count),
            stream_cases_count=len(bw_stream_cases),
            concurrency_levels=conc_levels,
        )

        out = {
            "ok": ok,
            "mode": str(args.mode),
            "status": "pass" if ok else "fail",
            "paths": {
                "tempdir": str(tmp_dir),
                "repo_root": str(REPO_ROOT),
            },
            "target": {
                "host": str(target_host),
                "port": int(target_port),
            },
            "udp_target": {
                "host": str(udp_target_host),
                "port": int(udp_target_port),
            },
            "socks": {
                "host": str(socks_host),
                "port": int(socks_port),
            },
            "battery_config": {
                "scenario": str(args.scenario),
                "latency_connect_count": int(args.latency_connect_count),
                "latency_rtt_count": int(args.latency_rtt_count),
                "latency_sizes": latency_sizes,
                "latency_per_message_conn": bool(args.latency_per_message_conn),
                "udp_enable": bool(args.udp_enable),
                "udp_target_host": str(udp_target_host),
                "udp_target_port": int(udp_target_port),
                "udp_rtt_count": int(args.udp_rtt_count),
                "udp_warmup_rtt": int(args.udp_warmup_rtt),
                "udp_per_message_assoc": bool(args.udp_per_message_assoc),
                "udp_bandwidth_cases": [{"chunk_size": int(a), "chunk_count": int(b)} for (a, b) in udp_bw_cases],
                "udp_warmup_bandwidth_chunks": int(args.udp_warmup_bandwidth_chunks),
                "bandwidth_cases": [{"chunk_size": int(a), "chunk_count": int(b)} for (a, b) in bw_cases],
                "concurrency_levels": conc_levels,
                "concurrency_chunk_size": int(args.concurrency_chunk_size),
                "concurrency_chunks_per_worker": int(args.concurrency_chunks_per_worker),
                "warmup_connect": int(args.warmup_connect),
                "warmup_rtt": int(args.warmup_rtt),
                "warmup_bandwidth_chunks": int(args.warmup_bandwidth_chunks),
            },
            "latency": {
                "connect_direct": {**direct_conn_stats, "errors": direct_conn_errors[:10]},
                "connect_socks": {**socks_conn_stats, "errors": socks_conn_errors[:10]},
                "connect_socks_vs_direct_p95_overhead_pct": _ratio_pct(
                    float(socks_conn_stats["p95_us"]),
                    float(direct_conn_stats["p95_us"]),
                ),
                "rtt_cases": latency_cases,
            },
            "bandwidth": {
                "stream_cases": bw_stream_cases,
                "concurrency_cases": bw_conc_cases,
            },
            "udp": (
                {
                    "enabled": True,
                    "connect_direct": udp_connect_direct_stats,
                    "connect_socks_assoc": udp_connect_socks_stats,
                    "rtt_cases": udp_latency_cases,
                    "stream_cases": udp_bw_stream_cases,
                }
                if udp_enabled
                else {"enabled": False}
            ),
            "gates": {
                "ok": gates_ok,
                "failures": gate_failures,
                "thresholds": {
                    "max_connect_p95_us": int(args.max_connect_p95_us),
                    "max_rtt_p95_us": int(args.max_rtt_p95_us),
                    "min_socks_throughput_mbps": float(args.min_socks_throughput_mbps),
                },
            },
            "connection_accounting": conn_acc,
        }
        output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"ok={out['ok']}")
        print(f"status={out['status']}")
        print(f"output={output}")
        return 0 if ok else 1

    except Exception as exc:
        fail = {
            "ok": False,
            "status": "fail",
            "mode": str(args.mode),
            "error": str(exc),
            "target": {"host": str(target_host), "port": int(target_port)},
            "socks": {"host": str(socks_host), "port": int(socks_port)},
        }
        output.write_text(json.dumps(fail, indent=2) + "\n", encoding="utf-8")
        print("ok=False")
        print(f"error={exc}")
        print(f"output={output}")
        return 1
    finally:
        if socks_proxy is not None:
            socks_proxy.stop()
        if echo_server is not None:
            echo_server.stop()
        if udp_echo_server is not None:
            udp_echo_server.stop()
        if managed_started:
            stop_cmd = [
                sys.executable,
                str(service_script),
                "--weaverssh-repo",
                str(args.weaverssh_repo),
                "--socks-host",
                str(socks_host),
                "--socks-port",
                str(socks_port),
                "--agent-listen",
                str(args.agent_listen),
                "--agent-endpoint",
                str(args.agent_endpoint),
                "stop",
            ]
            _run_cmd(stop_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
