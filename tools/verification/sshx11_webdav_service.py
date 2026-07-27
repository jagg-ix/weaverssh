#!/usr/bin/env python3
from __future__ import annotations

"""Manage a lightweight local WebDAV service for SSHX11 workflows."""

import argparse
import email.utils
import html
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = Path(tempfile.gettempdir())
DEFAULT_PID = TMP_DIR / "sshx11_webdav.pid"
DEFAULT_LOG = TMP_DIR / "sshx11_webdav.log"
DEFAULT_STATE = REPO_ROOT / "verification_results" / "runtime" / "sshx11_webdav_state.json"


def _is_windows(platform_name: str | None = None) -> bool:
    return str(platform_name or os.name).lower() == "nt"


def _session_spawn_kwargs(platform_name: str | None = None) -> dict[str, object]:
    if _is_windows(platform_name):
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if flags > 0:
            return {"creationflags": flags}
        return {}
    return {"start_new_session": True}


def _resolve_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def _read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _is_pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _terminate_pid(pid: int) -> None:
    if _is_windows():
        os.kill(pid, signal.SIGTERM)
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        os.kill(pid, signal.SIGTERM)


def _force_kill_pid(pid: int) -> None:
    if _is_windows():
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except Exception:
            pass
    try:
        os.killpg(pid, signal.SIGKILL)
        return
    except Exception:
        pass
    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))


def _stop_pid(pid_file: Path, timeout_s: float) -> int:
    pid = _read_pid(pid_file)
    if not pid:
        return 0
    if not _is_pid_alive(pid):
        pid_file.unlink(missing_ok=True)
        return pid
    try:
        _terminate_pid(pid)
    except OSError:
        pid_file.unlink(missing_ok=True)
        return pid
    deadline = time.time() + max(0.5, float(timeout_s))
    while time.time() < deadline:
        if not _is_pid_alive(pid):
            pid_file.unlink(missing_ok=True)
            return pid
        time.sleep(0.1)
    if _is_pid_alive(pid):
        _force_kill_pid(pid)
    pid_file.unlink(missing_ok=True)
    return pid


def _wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + max(0.1, float(timeout_s))
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((host, int(port)))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return False


def _probe_bind(host: str, port: int) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((str(host), int(port)))
        return True, "bind_ok"
    except OSError as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _find_open_port(host: str, start_port: int, attempts: int) -> int:
    for offset in range(1, max(1, int(attempts)) + 1):
        candidate = int(start_port) + offset
        ok, _ = _probe_bind(host, candidate)
        if ok:
            return candidate
    return 0


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_join(root: Path, req_path: str) -> Path | None:
    decoded = unquote(urlparse(req_path).path)
    rel = decoded.lstrip("/")
    target = (root / rel).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved in target.parents:
        return target
    return None


def _dav_href(path: Path, root: Path) -> str:
    root_resolved = root.resolve()
    p = path.resolve()
    if p == root_resolved:
        return "/"
    rel = p.relative_to(root_resolved).as_posix()
    href = "/" + quote(rel)
    if path.is_dir() and not href.endswith("/"):
        href += "/"
    return href


def _dav_response_xml(path: Path, root: Path) -> str:
    st = path.stat()
    href = html.escape(_dav_href(path, root), quote=True)
    modified = html.escape(email.utils.formatdate(st.st_mtime, usegmt=True), quote=True)
    if path.is_dir():
        resourcetype = "<D:resourcetype><D:collection/></D:resourcetype>"
        content_len = "0"
    else:
        resourcetype = "<D:resourcetype/>"
        content_len = str(int(st.st_size))
    return (
        "<D:response>"
        f"<D:href>{href}</D:href>"
        "<D:propstat>"
        "<D:prop>"
        f"{resourcetype}"
        f"<D:getlastmodified>{modified}</D:getlastmodified>"
        f"<D:getcontentlength>{content_len}</D:getcontentlength>"
        "</D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status>"
        "</D:propstat>"
        "</D:response>"
    )


class MiniWebDAVHandler(SimpleHTTPRequestHandler):
    root_dir: Path = REPO_ROOT
    read_only: bool = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(self.root_dir), **kwargs)

    def _target(self) -> Path | None:
        return _safe_join(self.root_dir, self.path)

    def _reject_write_if_readonly(self) -> bool:
        if not self.read_only:
            return False
        self.send_error(HTTPStatus.FORBIDDEN, "WebDAV service is running in read-only mode")
        return True

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND")
        self.send_header("DAV", "1,2")
        self.send_header("MS-Author-Via", "DAV")
        self.end_headers()

    def do_PROPFIND(self) -> None:  # noqa: N802
        target = self._target()
        if target is None:
            self.send_error(HTTPStatus.FORBIDDEN, "path outside root")
            return
        if not target.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "path not found")
            return

        depth = str(self.headers.get("Depth", "1")).strip().lower()
        nodes: list[Path] = [target]
        if target.is_dir() and depth != "0":
            try:
                nodes.extend(sorted(target.iterdir(), key=lambda p: p.name.lower()))
            except Exception:
                pass
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            + "".join(_dav_response_xml(node, self.root_dir) for node in nodes)
            + "</D:multistatus>"
        ).encode("utf-8")
        self.send_response(HTTPStatus.MULTI_STATUS)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("DAV", "1,2")
        self.end_headers()
        self.wfile.write(body)

    def do_MKCOL(self) -> None:  # noqa: N802
        if self._reject_write_if_readonly():
            return
        target = self._target()
        if target is None:
            self.send_error(HTTPStatus.FORBIDDEN, "path outside root")
            return
        if target.exists():
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "resource already exists")
            return
        parent = target.parent
        if not parent.exists():
            self.send_error(HTTPStatus.CONFLICT, "parent does not exist")
            return
        try:
            target.mkdir()
        except Exception as exc:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"mkcol failed: {exc}")
            return
        self.send_response(HTTPStatus.CREATED)
        self.end_headers()

    def do_PUT(self) -> None:  # noqa: N802
        if self._reject_write_if_readonly():
            return
        target = self._target()
        if target is None:
            self.send_error(HTTPStatus.FORBIDDEN, "path outside root")
            return
        if target.is_dir():
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "cannot overwrite directory")
            return
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        payload = self.rfile.read(max(content_length, 0))
        existed = target.exists()
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(payload)
        except Exception as exc:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"put failed: {exc}")
            return
        self.send_response(HTTPStatus.NO_CONTENT if existed else HTTPStatus.CREATED)
        self.end_headers()

    def do_DELETE(self) -> None:  # noqa: N802
        if self._reject_write_if_readonly():
            return
        target = self._target()
        if target is None:
            self.send_error(HTTPStatus.FORBIDDEN, "path outside root")
            return
        if not target.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "path not found")
            return
        try:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        except Exception as exc:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"delete failed: {exc}")
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()


def _serve(host: str, port: int, root: Path, read_only: bool) -> int:
    if not root.exists():
        raise FileNotFoundError(f"webdav root does not exist: {root}")
    MiniWebDAVHandler.root_dir = root.resolve()
    MiniWebDAVHandler.read_only = bool(read_only)
    server = ThreadingHTTPServer((host, int(port)), MiniWebDAVHandler)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _state(args: argparse.Namespace) -> dict[str, Any]:
    pid = _read_pid(Path(args.pid_file))
    alive = bool(pid and _is_pid_alive(pid))
    port_open = _wait_for_port(str(args.host), int(args.port), 0.5)
    status = "running" if alive and port_open else "degraded"
    if not alive and not port_open:
        status = "stopped"
    return {
        "ok": bool(status == "running"),
        "status": status,
        "mode": "webdav",
        "timestamp_unix": int(time.time()),
        "host": str(args.host),
        "port": int(args.port),
        "url": f"http://{args.host}:{int(args.port)}/",
        "root": str(Path(args.root).resolve()),
        "read_only": bool(args.read_only),
        "pid": int(pid or 0),
        "pid_alive": bool(alive),
        "port_open": bool(port_open),
        "pid_file": str(args.pid_file),
        "log_file": str(args.log_file),
        "state_file": str(args.state_file),
    }


def _cmd_start(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        print(
            json.dumps(
                {"ok": False, "status": "failed", "reason": "root_missing", "root": str(root)},
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    requested_port = int(args.port)
    fallback_from_port = 0
    bind_ok, bind_reason = _probe_bind(str(args.host), requested_port)
    if not bind_ok:
        if bool(args.auto_port_fallback):
            fallback_port = _find_open_port(str(args.host), requested_port, int(args.fallback_port_attempts))
            if fallback_port > 0:
                fallback_from_port = int(requested_port)
                args.port = int(fallback_port)
            else:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "status": "failed",
                            "reason": "bind_failed_no_fallback_port",
                            "host": str(args.host),
                            "port": int(requested_port),
                            "bind_error": bind_reason,
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 2
        else:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "status": "failed",
                        "reason": "bind_failed",
                        "host": str(args.host),
                        "port": int(requested_port),
                        "bind_error": bind_reason,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 2

    pid_file = Path(args.pid_file)
    existing = _read_pid(pid_file)
    if existing and _is_pid_alive(existing):
        state = _state(args)
        state["status"] = "already_running"
        _write_state(Path(args.state_file), state)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    log_file = Path(args.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    child_cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--host",
        str(args.host),
        "--port",
        str(int(args.port)),
        "--root",
        str(root),
        "--pid-file",
        str(args.pid_file),
        "--log-file",
        str(args.log_file),
        "--state-file",
        str(args.state_file),
        "--startup-timeout-s",
        str(float(args.startup_timeout_s)),
        "--shutdown-timeout-s",
        str(float(args.shutdown_timeout_s)),
    ]
    if bool(args.read_only):
        child_cmd.append("--read-only")
    else:
        child_cmd.append("--read-write")
    child_cmd.append("serve")

    with log_file.open("ab") as logh:
        proc = subprocess.Popen(
            child_cmd,
            stdout=logh,
            stderr=subprocess.STDOUT,
            **_session_spawn_kwargs(),
        )
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")

    if not _wait_for_port(str(args.host), int(args.port), float(args.startup_timeout_s)):
        _stop_pid(pid_file, timeout_s=float(args.shutdown_timeout_s))
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "port_not_ready",
                    "host": str(args.host),
                    "port": int(args.port),
                    "log_file": str(log_file),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    state = _state(args)
    _write_state(Path(args.state_file), state)
    payload = {"ok": True, "status": "started", **state}
    if fallback_from_port > 0:
        payload["fallback_from_port"] = int(fallback_from_port)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    pid = _stop_pid(Path(args.pid_file), timeout_s=float(args.shutdown_timeout_s))
    Path(args.state_file).unlink(missing_ok=True)
    print(
        json.dumps(
            {"ok": True, "status": "stopped", "pid": int(pid), "state_file": str(args.state_file)},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    state = _state(args)
    _write_state(Path(args.state_file), state)
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0 if state.get("status") == "running" else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("SSHX11_WEBDAV_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11_WEBDAV_PORT", "8780")))
    p.add_argument("--root", type=Path, default=REPO_ROOT)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--read-only", action="store_true", default=True)
    mode.add_argument("--read-write", action="store_false", dest="read_only")
    p.add_argument("--pid-file", type=Path, default=DEFAULT_PID)
    p.add_argument("--log-file", type=Path, default=DEFAULT_LOG)
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE)
    p.add_argument("--startup-timeout-s", type=float, default=8.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=5.0)
    p.add_argument("--auto-port-fallback", action="store_true", default=True)
    p.add_argument("--no-auto-port-fallback", action="store_false", dest="auto_port_fallback")
    p.add_argument("--fallback-port-attempts", type=int, default=20)
    p.add_argument("command", choices=["start", "stop", "status", "serve"])
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.pid_file = _resolve_path(args.pid_file)
    args.log_file = _resolve_path(args.log_file)
    args.state_file = _resolve_path(args.state_file)
    args.root = _resolve_path(args.root)
    if args.command == "serve":
        return _serve(str(args.host), int(args.port), Path(args.root), bool(args.read_only))
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "stop":
        return _cmd_stop(args)
    return _cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())
