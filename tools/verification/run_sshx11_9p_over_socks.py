#!/usr/bin/env python3
from __future__ import annotations

"""Dedicated 9P-over-SOCKS runner for SSHX11 fallback transport.

Default backend is `native` (embedded 9P server). `qemu` is optional.
"""

import argparse
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]

TVERSION = 100
RVERSION = 101
RERROR = 107
TATTACH = 104
RATTACH = 105
TWALK = 110
RWALK = 111
TOPEN = 112
ROPEN = 113
TREAD = 116
RREAD = 117
TCLUNK = 120
RCLUNK = 121

KNOWN_9P_VERSIONS: tuple[str, ...] = ("9P2000.L", "9P2000.u", "9P2000")
NINEP_FAMILY_RE = re.compile(r"^9P2000(?:[._-][A-Za-z0-9]+)?$")
INTEROP_PROFILES: dict[str, dict[str, Any]] = {
    "auto": {
        "protocol_versions": list(KNOWN_9P_VERSIONS),
        "description": "Generic negotiation preferring Linux extensions then base protocol.",
    },
    "native": {
        "protocol_versions": list(KNOWN_9P_VERSIONS),
        "description": "Embedded native runner supporting core 9P path used by this repo.",
    },
    "linux_v9fs": {
        "protocol_versions": ["9P2000.L", "9P2000.u", "9P2000"],
        "description": "Linux kernel v9fs client/server interop preference order.",
    },
    "qemu_virtfs": {
        "protocol_versions": ["9P2000.L", "9P2000.u"],
        "description": "QEMU VirtFS commonly negotiates .L or .u dialects.",
    },
    "diod": {
        "protocol_versions": ["9P2000.L"],
        "description": "diod server targets 9P2000.L.",
    },
    "ganesha_9p": {
        "protocol_versions": ["9P2000.L"],
        "description": "NFS-Ganesha 9P endpoint interop profile.",
    },
    "plan9port": {
        "protocol_versions": ["9P2000"],
        "description": "Plan9port/legacy base 9P profile.",
    },
    "go9p": {
        "protocol_versions": ["9P2000", "9P2000.u", "9P2000.L"],
        "description": "Generic Go 9P libraries; accept base first.",
    },
    "docker_go_p9p": {
        "protocol_versions": ["9P2000.L", "9P2000"],
        "description": "Docker go-p9p integration profile.",
    },
    "hugelgupf_p9": {
        "protocol_versions": ["9P2000.L", "9P2000"],
        "description": "hugelgupf/p9 transport profile.",
    },
    "wsl_host_bridge": {
        "protocol_versions": ["9P2000.L", "9P2000"],
        "description": "WSL-host bridge profile (Linux extension preferred).",
    },
}


def _read_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise RuntimeError(f"socket closed while reading {n} bytes")
        out.extend(part)
    return bytes(out)


def _pack_string(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return struct.pack("<H", len(raw)) + raw


def _unpack_string(buf: bytes, offset: int) -> tuple[str, int]:
    if offset + 2 > len(buf):
        raise ValueError("short string length")
    ln = struct.unpack("<H", buf[offset : offset + 2])[0]
    offset += 2
    if offset + ln > len(buf):
        raise ValueError("short string content")
    s = buf[offset : offset + ln].decode("utf-8", errors="replace")
    return s, offset + ln


def _pack_msg(msg_type: int, tag: int, payload: bytes) -> bytes:
    size = 7 + len(payload)
    return struct.pack("<IBH", size, msg_type, tag) + payload


def _recv_msg(sock: socket.socket) -> tuple[int, int, bytes]:
    hdr = _read_exact(sock, 7)
    size, msg_type, tag = struct.unpack("<IBH", hdr)
    if size < 7:
        raise RuntimeError(f"invalid 9P message size: {size}")
    payload = _read_exact(sock, size - 7)
    return msg_type, tag, payload


def _qid(qtype: int, version: int, path: int) -> bytes:
    return struct.pack("<BIQ", qtype & 0xFF, int(version), int(path))


def _is_9p2000_family(version: str) -> bool:
    return bool(NINEP_FAMILY_RE.fullmatch(str(version).strip()))


def _normalize_protocol_versions(
    raw: str | list[str] | tuple[str, ...],
    *,
    allow_9p2000_family: bool = False,
) -> list[str]:
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        parts = [str(p).strip() for p in raw if str(p).strip()]
    out: list[str] = []
    for p in parts:
        if p not in KNOWN_9P_VERSIONS and not (allow_9p2000_family and _is_9p2000_family(p)):
            raise ValueError(f"unsupported protocol version '{p}'")
        if p not in out:
            out.append(p)
    if not out:
        return list(KNOWN_9P_VERSIONS)
    return out


def _resolve_protocol_versions(*, interop_profile: str, protocol_versions_csv: str) -> list[str]:
    csv_raw = str(protocol_versions_csv).strip()
    if csv_raw:
        # CLI override accepts known dialects and compatible 9P2000-family labels.
        return _normalize_protocol_versions(csv_raw, allow_9p2000_family=True)
    profile = INTEROP_PROFILES.get(str(interop_profile), INTEROP_PROFILES["auto"])
    return _normalize_protocol_versions(profile.get("protocol_versions", list(KNOWN_9P_VERSIONS)))


class Native9PServer:
    """Minimal 9P server supporting version/attach/walk/open/read/clunk."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        file_name: str = "hello.txt",
        file_data: bytes | None = None,
        supported_versions: list[str] | tuple[str, ...] | None = None,
    ):
        self.host = host
        self.port = int(port)
        self.file_name = file_name
        self.file_data = file_data if file_data is not None else b"sshx11-9p-native-server\n"
        self.supported_versions = _normalize_protocol_versions(
            list(supported_versions) if supported_versions is not None else list(KNOWN_9P_VERSIONS)
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._srv: socket.socket | None = None
        self.bound_port = 0

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, int(self.port)))
        srv.listen(8)
        self.bound_port = int(srv.getsockname()[1])
        self._srv = srv

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
                t.start()

        self._thread = threading.Thread(target=_loop, daemon=True)
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

    def _send_error(self, conn: socket.socket, tag: int, message: str, *, negotiated_version: str = "9P2000") -> None:
        payload = _pack_string(message)
        # 9P2000.u adds errnum to Rerror payload.
        if negotiated_version == "9P2000.u":
            payload += struct.pack("<I", 5)
        conn.sendall(_pack_msg(RERROR, tag, payload))

    def _select_version(self, requested: str) -> str:
        if requested in self.supported_versions:
            return requested
        # Unknown extension for known base => reject so client can retry another candidate.
        if requested.startswith("9P2000"):
            return "unknown"
        return "unknown"

    def _handle_conn(self, conn: socket.socket) -> None:
        fids: dict[int, str] = {}
        negotiated_version = self.supported_versions[0]
        root_qid = _qid(0x80, 0, 1)
        file_qid = _qid(0x00, 0, 2)
        with conn:
            while not self._stop.is_set():
                try:
                    msg_type, tag, payload = _recv_msg(conn)
                except Exception:
                    return
                try:
                    if msg_type == TVERSION:
                        if len(payload) < 6:
                            self._send_error(conn, tag, "short_tversion", negotiated_version=negotiated_version)
                            continue
                        msize = struct.unpack("<I", payload[:4])[0]
                        version, _ = _unpack_string(payload, 4)
                        out_ver = self._select_version(version)
                        if out_ver != "unknown":
                            negotiated_version = out_ver
                        out_payload = struct.pack("<I", min(msize, 8192)) + _pack_string(out_ver)
                        conn.sendall(_pack_msg(RVERSION, tag, out_payload))
                    elif msg_type == TATTACH:
                        if len(payload) < 8:
                            self._send_error(conn, tag, "short_tattach", negotiated_version=negotiated_version)
                            continue
                        fid = struct.unpack("<I", payload[:4])[0]
                        # accept any attach metadata
                        fids[fid] = "/"
                        conn.sendall(_pack_msg(RATTACH, tag, root_qid))
                    elif msg_type == TWALK:
                        if len(payload) < 10:
                            self._send_error(conn, tag, "short_twalk", negotiated_version=negotiated_version)
                            continue
                        fid, newfid = struct.unpack("<II", payload[:8])
                        nwname = struct.unpack("<H", payload[8:10])[0]
                        off = 10
                        names: list[str] = []
                        for _ in range(nwname):
                            n, off = _unpack_string(payload, off)
                            names.append(n)
                        src = fids.get(fid)
                        if src is None:
                            self._send_error(conn, tag, "unknown_fid", negotiated_version=negotiated_version)
                            continue
                        if nwname == 0:
                            fids[newfid] = src
                            conn.sendall(_pack_msg(RWALK, tag, struct.pack("<H", 0)))
                            continue
                        if src == "/" and names == [self.file_name]:
                            fids[newfid] = f"/{self.file_name}"
                            out = struct.pack("<H", 1) + file_qid
                            conn.sendall(_pack_msg(RWALK, tag, out))
                        else:
                            self._send_error(conn, tag, "walk_not_found", negotiated_version=negotiated_version)
                    elif msg_type == TOPEN:
                        if len(payload) < 5:
                            self._send_error(conn, tag, "short_topen", negotiated_version=negotiated_version)
                            continue
                        fid = struct.unpack("<I", payload[:4])[0]
                        path = fids.get(fid)
                        if path is None:
                            self._send_error(conn, tag, "unknown_fid", negotiated_version=negotiated_version)
                            continue
                        q = root_qid if path == "/" else file_qid
                        conn.sendall(_pack_msg(ROPEN, tag, q + struct.pack("<I", 0)))
                    elif msg_type == TREAD:
                        if len(payload) < 16:
                            self._send_error(conn, tag, "short_tread", negotiated_version=negotiated_version)
                            continue
                        fid = struct.unpack("<I", payload[:4])[0]
                        offset = struct.unpack("<Q", payload[4:12])[0]
                        count = struct.unpack("<I", payload[12:16])[0]
                        path = fids.get(fid)
                        if path is None:
                            self._send_error(conn, tag, "unknown_fid", negotiated_version=negotiated_version)
                            continue
                        if path == "/":
                            data = b""
                        elif path == f"/{self.file_name}":
                            data = self.file_data[offset : offset + count]
                        else:
                            self._send_error(conn, tag, "read_invalid_fid", negotiated_version=negotiated_version)
                            continue
                        out = struct.pack("<I", len(data)) + data
                        conn.sendall(_pack_msg(RREAD, tag, out))
                    elif msg_type == TCLUNK:
                        if len(payload) < 4:
                            self._send_error(conn, tag, "short_tclunk", negotiated_version=negotiated_version)
                            continue
                        fid = struct.unpack("<I", payload[:4])[0]
                        fids.pop(fid, None)
                        conn.sendall(_pack_msg(RCLUNK, tag, b""))
                    else:
                        self._send_error(conn, tag, f"unsupported_msg_{msg_type}", negotiated_version=negotiated_version)
                except Exception as exc:
                    self._send_error(conn, tag, f"server_error:{exc}", negotiated_version=negotiated_version)


def _socks_connect(*, socks_host: str, socks_port: int, target_host: str, target_port: int, timeout_s: float = 5.0) -> socket.socket:
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
        raise RuntimeError(f"SOCKS CONNECT failed: head={head!r}")
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


def _send_and_expect(sock: socket.socket, req_type: int, expect_type: int, tag: int, payload: bytes) -> bytes:
    sock.sendall(_pack_msg(req_type, tag, payload))
    msg_type, rtag, rpayload = _recv_msg(sock)
    if msg_type == RERROR:
        err, _ = _unpack_string(rpayload, 0)
        raise RuntimeError(f"9P Rerror(tag={rtag}): {err}")
    if rtag != tag:
        raise RuntimeError(f"tag mismatch: expected {tag}, got {rtag}")
    if msg_type != expect_type:
        raise RuntimeError(f"type mismatch: expected {expect_type}, got {msg_type}")
    return rpayload


def _negotiate_protocol_version(sock: socket.socket, *, candidates: list[str], msize: int = 8192) -> dict[str, Any]:
    errors: list[str] = []
    tag = 1
    for candidate in candidates:
        payload = struct.pack("<I", int(msize)) + _pack_string(candidate)
        try:
            rp = _send_and_expect(sock, TVERSION, RVERSION, tag, payload)
        except Exception as exc:
            errors.append(f"{candidate}:exception:{exc}")
            tag += 1
            continue
        got_msize = struct.unpack("<I", rp[:4])[0]
        got_version, _ = _unpack_string(rp, 4)
        if got_version == "unknown":
            errors.append(f"{candidate}:unknown")
            tag += 1
            continue
        if not _is_9p2000_family(got_version):
            errors.append(f"{candidate}:unexpected_version:{got_version}")
            tag += 1
            continue
        return {
            "requested_version": candidate,
            "negotiated_version": got_version,
            "negotiated_known": bool(got_version in KNOWN_9P_VERSIONS),
            "msize": int(got_msize),
            "tag_used": int(tag),
            "attempt_errors": errors,
        }
    raise RuntimeError(f"protocol negotiation failed for candidates={candidates} errors={errors}")


def _run_9p_session(
    sock: socket.socket,
    *,
    file_name: str,
    expect_data: bytes,
    protocol_candidates: list[str],
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    t0 = time.perf_counter_ns()

    negotiation = _negotiate_protocol_version(sock, candidates=protocol_candidates, msize=8192)
    steps.append(
        {
            "name": "version",
            "ok": True,
            "msize": int(negotiation["msize"]),
            "requested_version": negotiation["requested_version"],
            "version": negotiation["negotiated_version"],
            "known_dialect": bool(negotiation.get("negotiated_known", False)),
            "attempt_errors": negotiation["attempt_errors"],
        }
    )
    tag = int(negotiation["tag_used"]) + 1

    # TATTACH/RATTACH fid=1
    p = struct.pack("<II", 1, 0xFFFFFFFF) + _pack_string("sshx11") + _pack_string("") + struct.pack("<I", 0)
    _send_and_expect(sock, TATTACH, RATTACH, tag, p)
    steps.append({"name": "attach", "ok": True, "fid": 1})
    tag += 1

    # TWALK/RWALK to file fid=2
    p = struct.pack("<IIH", 1, 2, 1) + _pack_string(file_name)
    rp = _send_and_expect(sock, TWALK, RWALK, tag, p)
    nwqid = struct.unpack("<H", rp[:2])[0]
    if nwqid != 1:
        raise RuntimeError(f"unexpected nwqid={nwqid} for walk")
    steps.append({"name": "walk", "ok": True, "file": file_name})
    tag += 1

    # TOPEN/ROPEN read-only
    p = struct.pack("<IB", 2, 0)
    _send_and_expect(sock, TOPEN, ROPEN, tag, p)
    steps.append({"name": "open", "ok": True, "fid": 2})
    tag += 1

    # TREAD/RREAD
    p = struct.pack("<IQI", 2, 0, 65535)
    rp = _send_and_expect(sock, TREAD, RREAD, tag, p)
    n = struct.unpack("<I", rp[:4])[0]
    data = rp[4 : 4 + n]
    steps.append({"name": "read", "ok": True, "bytes": int(n), "preview": data[:80].decode("utf-8", errors="replace")})
    if data != expect_data:
        raise RuntimeError(f"read data mismatch ({len(data)} bytes)")
    tag += 1

    # TCLUNK on file and root
    _send_and_expect(sock, TCLUNK, RCLUNK, tag, struct.pack("<I", 2))
    tag += 1
    _send_and_expect(sock, TCLUNK, RCLUNK, tag, struct.pack("<I", 1))
    steps.append({"name": "clunk", "ok": True})

    t1 = time.perf_counter_ns()
    return {
        "ok": True,
        "steps": steps,
        "session_latency_us": int(max(0, (t1 - t0) // 1000)),
        "negotiated_version": str(negotiation["negotiated_version"]),
        "negotiated_known": bool(negotiation.get("negotiated_known", False)),
        "requested_version": str(negotiation["requested_version"]),
        "protocol_candidates": list(protocol_candidates),
    }


def _run_cmd(argv: list[str]) -> tuple[int, str]:
    proc = subprocess.run(argv, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _wait_port(host: str, port: int, timeout_s: float = 8.0) -> bool:
    deadline = time.time() + max(0.1, timeout_s)
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, int(port)))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def _find_free_port(host: str = "127.0.0.1") -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    p = int(s.getsockname()[1])
    s.close()
    return p


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--backend", choices=["native", "external", "qemu"], default="native")
    p.add_argument(
        "--interop-profile",
        choices=sorted(INTEROP_PROFILES.keys()),
        default="auto",
        help="Protocol/app profile used to select 9P dialect preference.",
    )
    p.add_argument(
        "--protocol-versions",
        default="",
        help="Comma-separated protocol preference override (known or 9P2000-family labels).",
    )
    p.add_argument("--target-host", default="127.0.0.1")
    p.add_argument("--target-port", type=int, default=0)
    p.add_argument("--file-name", default="hello.txt")
    p.add_argument("--file-content", default="sshx11-9p-native-server\n")
    p.add_argument("--managed-service", action="store_true")
    p.add_argument("--weaverssh-repo", default=str(Path.home() / "weaverssh"))
    p.add_argument("--agent-listen", default="localhost:6000")
    p.add_argument("--agent-endpoint", default="localhost:6000")
    p.add_argument("--qemu-cmd", default="", help="Optional command to launch qemu-backed 9P endpoint")
    p.add_argument("--qemu-port", type=int, default=0, help="Port exposed by qemu-backed 9P endpoint")
    p.add_argument("--output", type=Path, default=Path("verification_results/stack_audits/sshx11_9p_over_socks_runner.json"))
    p.add_argument("--dry-run", action="store_true")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    protocol_candidates = _resolve_protocol_versions(
        interop_profile=str(args.interop_profile),
        protocol_versions_csv=str(args.protocol_versions),
    )

    target_host = str(args.target_host)
    target_port = int(args.target_port)
    file_data = str(args.file_content).encode("utf-8")

    result: dict[str, Any] = {
        "ok": False,
        "backend": str(args.backend),
        "interop_profile": str(args.interop_profile),
        "protocol_candidates": list(protocol_candidates),
        "qemu_optional": True,
        "socks_host": str(args.socks_host),
        "socks_port": int(args.socks_port),
        "managed_service": bool(args.managed_service),
    }
    if args.dry_run:
        result.update(
            {
                "ok": True,
                "status": "dry_run",
                "target_host": target_host,
                "target_port": int(target_port),
                "x11ws_repo": str(args.weaverssh_repo),
                "interop_profile_description": INTEROP_PROFILES.get(str(args.interop_profile), {}).get("description", ""),
            }
        )
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"ok={result['ok']}")
        print(f"output={output}")
        return 0

    service_script = REPO_ROOT / "tools" / "verification" / "sshx11_socks_fallback_service.py"
    managed_started = False
    native_server: Native9PServer | None = None
    qemu_proc: subprocess.Popen[str] | None = None

    try:
        if args.backend == "native":
            if target_port <= 0:
                target_port = _find_free_port(target_host)
            native_server = Native9PServer(
                host=target_host,
                port=target_port,
                file_name=str(args.file_name),
                file_data=file_data,
                supported_versions=protocol_candidates,
            )
            native_server.start()
            target_port = int(native_server.bound_port)
            if not _wait_port(target_host, target_port, timeout_s=5.0):
                raise RuntimeError("native 9P server failed to open port")
        elif args.backend == "qemu":
            if str(args.qemu_cmd).strip():
                qemu_proc = subprocess.Popen(
                    shlex.split(str(args.qemu_cmd)),
                    cwd=str(REPO_ROOT),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            qport = int(args.qemu_port or target_port)
            if qport <= 0:
                raise RuntimeError("qemu backend requires --qemu-port or --target-port")
            target_port = qport
            if not _wait_port(target_host, target_port, timeout_s=10.0):
                raise RuntimeError("qemu 9P endpoint not reachable")
        else:
            if target_port <= 0:
                raise RuntimeError("external backend requires --target-port")
            if not _wait_port(target_host, target_port, timeout_s=2.0):
                raise RuntimeError("external 9P endpoint not reachable")

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
            rc, out = _run_cmd(start_cmd)
            if rc != 0:
                raise RuntimeError(f"managed_service_start_failed:{out}")
            managed_started = True
            time.sleep(0.5)

        with _socks_connect(
            socks_host=str(args.socks_host),
            socks_port=int(args.socks_port),
            target_host=target_host,
            target_port=int(target_port),
        ) as sock:
            session = _run_9p_session(
                sock,
                file_name=str(args.file_name),
                expect_data=file_data,
                protocol_candidates=protocol_candidates,
            )

        result.update(
            {
                "ok": True,
                "target_host": target_host,
                "target_port": int(target_port),
                "session": session,
                "status": "pass",
            }
        )
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("ok=True")
        print(f"output={output}")
        return 0
    except Exception as exc:
        result.update(
            {
                "ok": False,
                "status": "fail",
                "error": str(exc),
                "target_host": target_host,
                "target_port": int(target_port),
            }
        )
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("ok=False")
        print(f"error={exc}")
        print(f"output={output}")
        return 1
    finally:
        if native_server is not None:
            native_server.stop()
        if qemu_proc is not None:
            qemu_proc.terminate()
            try:
                qemu_proc.wait(timeout=2.0)
            except Exception:
                qemu_proc.kill()
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
            _run_cmd(stop_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
