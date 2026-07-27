#!/usr/bin/env python3
from __future__ import annotations

"""Probe SOCKS-over-SSHX11 fallback path with echo or 9P checks."""

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError(f"socket closed while reading {n} bytes")
        out.extend(chunk)
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
        raise ValueError("domain name too long")
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
        raise RuntimeError(f"SOCKS response ATYP not supported: {atyp}")
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


def _socks_connect(
    *,
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout_s: float = 5.0,
) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect((socks_host, int(socks_port)))
    s.sendall(b"\x05\x01\x00")
    if _read_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed (expected NOAUTH)")

    target_ip = socket.inet_aton(target_host)
    req = b"\x05\x01\x00\x01" + target_ip + struct.pack("!H", int(target_port))
    s.sendall(req)

    head = _read_exact(s, 4)
    if head[0] != 0x05:
        raise RuntimeError(f"SOCKS response version mismatch: {head[0]}")
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS CONNECT failed: rep=0x{head[1]:02x}")
    atyp = head[3]
    _read_socks_addr(s, int(atyp))
    return s


def _socks_udp_associate(
    *,
    socks_host: str,
    socks_port: int,
    timeout_s: float = 5.0,
) -> tuple[socket.socket, socket.socket, tuple[str, int]]:
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(timeout_s)
    ctrl.connect((socks_host, int(socks_port)))
    ctrl.sendall(b"\x05\x01\x00")
    if _read_exact(ctrl, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed (expected NOAUTH)")
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = _read_exact(ctrl, 4)
    if head[0] != 0x05:
        raise RuntimeError(f"SOCKS response version mismatch: {head[0]}")
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS UDP ASSOCIATE failed: rep=0x{head[1]:02x}")
    relay_host, relay_port = _read_socks_addr(ctrl, int(head[3]))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout_s)
    udp.bind(("0.0.0.0", 0))
    return ctrl, udp, (str(relay_host), int(relay_port))


def _run_echo_probe(sock: socket.socket, payload: bytes) -> tuple[bool, str]:
    sock.sendall(payload)
    got = _read_exact(sock, len(payload))
    if got == payload:
        return True, "echo_ok"
    return False, f"echo_mismatch:{got[:64]!r}"


def _run_9p_probe(sock: socket.socket, msize: int = 8192, version: bytes = b"9P2000.L") -> tuple[bool, str]:
    tag = 1
    tversion_type = 100
    rversion_type = 101
    payload = struct.pack("<I", int(msize)) + struct.pack("<H", len(version)) + version
    msg_size = 4 + 1 + 2 + len(payload)
    req = struct.pack("<IBH", msg_size, tversion_type, tag) + payload
    sock.sendall(req)

    hdr = _read_exact(sock, 7)
    r_size, r_type, r_tag = struct.unpack("<IBH", hdr)
    if r_type != rversion_type:
        return False, f"unexpected_reply_type:{r_type}"
    if r_tag != tag:
        return False, f"unexpected_reply_tag:{r_tag}"
    if r_size < 7:
        return False, f"invalid_reply_size:{r_size}"
    body = _read_exact(sock, r_size - 7)
    if len(body) < 6:
        return False, "short_rversion_body"
    r_msize = struct.unpack("<I", body[:4])[0]
    vlen = struct.unpack("<H", body[4:6])[0]
    if len(body) < 6 + vlen:
        return False, "short_rversion_string"
    r_ver = body[6 : 6 + vlen]
    if not r_ver:
        return False, "empty_rversion"
    return True, f"rversion_ok:msize={r_msize}:version={r_ver.decode('utf-8', errors='replace')}"


def _start_echo_server(host: str) -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(8)
    port = int(srv.getsockname()[1])

    def _worker() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            t = threading.Thread(target=_handle, args=(conn,), daemon=True)
            t.start()

    def _handle(conn: socket.socket) -> None:
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

    threading.Thread(target=_worker, daemon=True).start()
    return srv, port


def _start_udp_echo_server(host: str) -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    port = int(srv.getsockname()[1])

    def _worker() -> None:
        while True:
            try:
                data, addr = srv.recvfrom(65535)
            except OSError:
                return
            if not data:
                continue
            try:
                srv.sendto(data, addr)
            except OSError:
                return

    threading.Thread(target=_worker, daemon=True).start()
    return srv, port


def _run_udp_echo_probe(
    *,
    ctrl_sock: socket.socket,
    udp_sock: socket.socket,
    relay_addr: tuple[str, int],
    target_host: str,
    target_port: int,
    payload: bytes,
) -> tuple[bool, str]:
    del ctrl_sock
    pkt = _socks5_udp_wrap(payload=payload, dst_host=target_host, dst_port=int(target_port))
    udp_sock.sendto(pkt, relay_addr)
    got, _ = udp_sock.recvfrom(max(65535, len(payload) + 64))
    frag, src_host, src_port, data = _socks5_udp_unwrap(got)
    if int(frag) != 0:
        return False, "udp_frag_not_supported"
    if int(src_port) != int(target_port):
        return False, f"udp_source_port_mismatch:{src_port}"
    src_norm = "127.0.0.1" if src_host in {"localhost", "::1"} else src_host
    dst_norm = "127.0.0.1" if target_host in {"localhost", "::1"} else target_host
    if src_norm != dst_norm:
        return False, f"udp_source_host_mismatch:{src_host}"
    if data != payload:
        return False, f"udp_echo_mismatch:{data[:64]!r}"
    return True, "udp_echo_ok"


def _run_service_cmd(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(args, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return int(proc.returncode), (proc.stdout + proc.stderr).strip()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--mode", choices=["echo", "9p", "udp-echo"], default="echo")
    p.add_argument("--target-host", default="127.0.0.1")
    p.add_argument("--target-port", type=int, default=0)
    p.add_argument("--payload", default="sshx11-socks-fallback-probe")
    p.add_argument("--managed-service", action="store_true")
    p.add_argument("--weaverssh-repo", default=str(Path.home() / "weaverssh"))
    p.add_argument("--agent-listen", default="localhost:6000")
    p.add_argument("--agent-endpoint", default="localhost:6000")
    p.add_argument("--output", type=Path, default=Path("verification_results/stack_audits/sshx11_socks_fallback_probe.json"))
    args = p.parse_args()

    service_script = REPO_ROOT / "tools" / "verification" / "sshx11_socks_fallback_service.py"
    managed_started = False
    local_echo_server: socket.socket | None = None
    local_udp_echo_server: socket.socket | None = None
    target_port = int(args.target_port)
    target_host = str(args.target_host)

    if args.mode == "echo" and target_port <= 0:
        local_echo_server, target_port = _start_echo_server(target_host)
    elif args.mode == "9p" and target_port <= 0:
        target_port = 5640
    elif args.mode == "udp-echo" and target_port <= 0:
        local_udp_echo_server, target_port = _start_udp_echo_server(target_host)

    t0 = time.perf_counter_ns()
    result: dict[str, object] = {
        "ok": False,
        "mode": str(args.mode),
        "socks_host": str(args.socks_host),
        "socks_port": int(args.socks_port),
        "target_host": target_host,
        "target_port": int(target_port),
        "managed_service": bool(args.managed_service),
    }

    try:
        if args.managed_service:
            start_cmd = [
                sys.executable,
                str(service_script),
                "--weaverssh-repo",
                str(args.weaverssh_repo),
                "--socks-host",
                str(args.socks_host),
                "--socks-port",
                str(args.socks_port),
                "--agent-listen",
                str(args.agent_listen),
                "--agent-endpoint",
                str(args.agent_endpoint),
                "start",
            ]
            rc, out = _run_service_cmd(start_cmd)
            if rc != 0:
                result["error"] = f"managed_service_start_failed:{out}"
                return 2
            managed_started = True
            time.sleep(0.5)

        if args.mode == "udp-echo":
            ctrl, udp, relay_addr = _socks_udp_associate(
                socks_host=str(args.socks_host),
                socks_port=int(args.socks_port),
            )
            with ctrl, udp:
                ok, reason = _run_udp_echo_probe(
                    ctrl_sock=ctrl,
                    udp_sock=udp,
                    relay_addr=relay_addr,
                    target_host=target_host,
                    target_port=int(target_port),
                    payload=str(args.payload).encode("utf-8"),
                )
                result["udp_relay_addr"] = [relay_addr[0], int(relay_addr[1])]
        else:
            sock = _socks_connect(
                socks_host=str(args.socks_host),
                socks_port=int(args.socks_port),
                target_host=target_host,
                target_port=int(target_port),
            )
            with sock:
                if args.mode == "echo":
                    ok, reason = _run_echo_probe(sock, str(args.payload).encode("utf-8"))
                else:
                    ok, reason = _run_9p_probe(sock)
        t1 = time.perf_counter_ns()
        result.update(
            {
                "ok": bool(ok),
                "reason": str(reason),
                "latency_us": int(max(0, (t1 - t0) // 1000)),
            }
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"ok={result['ok']}")
        print(f"reason={result.get('reason', '')}")
        print(f"output={args.output}")
        return 0 if bool(ok) else 1
    finally:
        if local_echo_server is not None:
            try:
                local_echo_server.close()
            except Exception:
                pass
        if local_udp_echo_server is not None:
            try:
                local_udp_echo_server.close()
            except Exception:
                pass
        if managed_started:
            stop_cmd = [
                sys.executable,
                str(service_script),
                "--weaverssh-repo",
                str(args.weaverssh_repo),
                "--socks-host",
                str(args.socks_host),
                "--socks-port",
                str(args.socks_port),
                "--agent-listen",
                str(args.agent_listen),
                "--agent-endpoint",
                str(args.agent_endpoint),
                "stop",
            ]
            _run_service_cmd(stop_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
