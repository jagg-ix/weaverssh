#!/usr/bin/env python3
from __future__ import annotations

"""Manage SSHX11 control-plane + data-plane local daemons."""

import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = Path(tempfile.gettempdir())
DEFAULT_CONTROL_PID = TMP_DIR / "sshx11_control_plane.pid"
DEFAULT_DATA_PID = TMP_DIR / "sshx11_data_plane.pid"
DEFAULT_CONTROL_LOG = TMP_DIR / "sshx11_control_plane.log"
DEFAULT_DATA_LOG = TMP_DIR / "sshx11_data_plane.log"


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


def _is_windows(platform_name: str | None = None) -> bool:
    return str(platform_name or os.name).lower() == "nt"


def _session_spawn_kwargs(platform_name: str | None = None) -> dict[str, object]:
    if _is_windows(platform_name):
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if flags > 0:
            return {"creationflags": flags}
        return {}
    return {"start_new_session": True}


def _read_pid(path: Path) -> Optional[int]:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + max(timeout_s, 0.5)
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, int(port)))
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def _tail_log(path: Path, n_lines: int = 40) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = lines[-max(1, int(n_lines)) :]
    return "\n".join(tail).strip()


def _start_proc(cmd: list[str], cwd: Path, log_file: Path, pid_file: Path) -> int:
    existing = _read_pid(pid_file)
    if existing and _is_pid_alive(existing):
        return existing
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as h:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=h,
            stderr=subprocess.STDOUT,
            **_session_spawn_kwargs(),
        )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    return proc.pid


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
    sigkill = getattr(signal, "SIGKILL", None)
    if sigkill is None:
        os.kill(pid, signal.SIGTERM)
        return
    os.kill(pid, sigkill)


def _stop_proc(pid_file: Path, timeout_s: float) -> int:
    pid = _read_pid(pid_file)
    if not pid:
        return 0
    if not _is_pid_alive(pid):
        pid_file.unlink(missing_ok=True)
        return 0
    try:
        _terminate_pid(pid)
    except OSError:
        pid_file.unlink(missing_ok=True)
        return 0
    deadline = time.time() + max(timeout_s, 0.5)
    while time.time() < deadline:
        if not _is_pid_alive(pid):
            break
        time.sleep(0.1)
    if _is_pid_alive(pid):
        try:
            _force_kill_pid(pid)
        except OSError:
            pass
    pid_file.unlink(missing_ok=True)
    return pid


def _cmd_start(args: argparse.Namespace) -> int:
    state_file = Path(args.state_file)
    control_pid_file = Path(args.control_pid_file)
    data_pid_file = Path(args.data_pid_file)
    control_log_file = Path(args.control_log_file)
    data_log_file = Path(args.data_log_file)
    realtime_port = int(args.realtime_port if int(args.realtime_port) > 0 else (int(args.data_port) + 1))
    control_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "verification" / "sshx11_control_plane_daemon.py"),
        "--host",
        str(args.host),
        "--port",
        str(args.control_port),
        "--bulk-port",
        str(args.data_port),
        "--realtime-port",
        str(realtime_port),
        "--state-file",
        str(state_file),
        "--log-file",
        str(args.control_event_log),
    ]
    data_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "verification" / "sshx11_data_plane_daemon.py"),
        "--host",
        str(args.host),
        "--bulk-port",
        str(args.data_port),
        "--realtime-port",
        str(realtime_port),
        "--state-file",
        str(state_file),
        "--log-file",
        str(args.data_event_log),
    ]

    cp_pid = _start_proc(control_cmd, REPO_ROOT, control_log_file, control_pid_file)
    if not _wait_for_port(str(args.host), int(args.control_port), float(args.startup_timeout_s)):
        _stop_proc(control_pid_file, float(args.shutdown_timeout_s))
        print(f"status=failed reason=control_plane_not_ready pid={cp_pid}")
        tail = _tail_log(control_log_file)
        if tail:
            print("control_log_tail_begin")
            print(tail)
            print("control_log_tail_end")
        return 2
    dp_pid = _start_proc(data_cmd, REPO_ROOT, data_log_file, data_pid_file)
    if not _wait_for_port(str(args.host), int(args.data_port), float(args.startup_timeout_s)):
        _stop_proc(data_pid_file, float(args.shutdown_timeout_s))
        _stop_proc(control_pid_file, float(args.shutdown_timeout_s))
        print(f"status=failed reason=data_plane_not_ready pid={dp_pid}")
        tail = _tail_log(data_log_file)
        if tail:
            print("data_log_tail_begin")
            print(tail)
            print("data_log_tail_end")
        return 2
    if int(realtime_port) != int(args.data_port):
        if not _wait_for_port(str(args.host), int(realtime_port), float(args.startup_timeout_s)):
            _stop_proc(data_pid_file, float(args.shutdown_timeout_s))
            _stop_proc(control_pid_file, float(args.shutdown_timeout_s))
            print(f"status=failed reason=realtime_data_plane_not_ready pid={dp_pid}")
            tail = _tail_log(data_log_file)
            if tail:
                print("data_log_tail_begin")
                print(tail)
                print("data_log_tail_end")
            return 2
    print(f"status=started control_pid={cp_pid} data_pid={dp_pid}")
    print(f"control_endpoint=http://{args.host}:{args.control_port}")
    print(f"data_bulk_endpoint=tcp://{args.host}:{args.data_port}")
    print(f"data_realtime_endpoint=tcp://{args.host}:{realtime_port}")
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    dpid = _stop_proc(Path(args.data_pid_file), float(args.shutdown_timeout_s))
    cpid = _stop_proc(Path(args.control_pid_file), float(args.shutdown_timeout_s))
    print(f"status=stopped control_pid={cpid} data_pid={dpid}")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    realtime_port = int(args.realtime_port if int(args.realtime_port) > 0 else (int(args.data_port) + 1))
    cpid = _read_pid(Path(args.control_pid_file))
    dpid = _read_pid(Path(args.data_pid_file))
    calive = bool(cpid and _is_pid_alive(cpid))
    dalive = bool(dpid and _is_pid_alive(dpid))
    cport = _wait_for_port(str(args.host), int(args.control_port), 0.5)
    dport_bulk = _wait_for_port(str(args.host), int(args.data_port), 0.5)
    dport_rt = True
    if int(realtime_port) != int(args.data_port):
        dport_rt = _wait_for_port(str(args.host), int(realtime_port), 0.5)
    print(
        "status="
        + ("running" if calive and dalive and cport and dport_bulk and dport_rt else "degraded")
        + f" control_pid={cpid} control_alive={calive} control_port={cport}"
        + f" data_pid={dpid} data_alive={dalive} data_bulk_port={dport_bulk} data_realtime_port={dport_rt}"
    )
    return 0 if calive and dalive and cport and dport_bulk and dport_rt else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--control-port", type=int, default=8101)
    p.add_argument("--data-port", type=int, default=19090)
    p.add_argument("--realtime-port", type=int, default=-1)
    p.add_argument("--state-file", default="verification_results/runtime/sshx11_plane_state.json")
    p.add_argument("--control-pid-file", default=str(DEFAULT_CONTROL_PID))
    p.add_argument("--data-pid-file", default=str(DEFAULT_DATA_PID))
    p.add_argument("--control-log-file", default=str(DEFAULT_CONTROL_LOG))
    p.add_argument("--data-log-file", default=str(DEFAULT_DATA_LOG))
    p.add_argument(
        "--control-event-log",
        default="verification_results/stack_audits/sshx11_control_plane_events.ndjson",
    )
    p.add_argument(
        "--data-event-log",
        default="verification_results/stack_audits/sshx11_data_plane_events.ndjson",
    )
    p.add_argument("--startup-timeout-s", type=float, default=8.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=5.0)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("start").set_defaults(func=_cmd_start)
    sub.add_parser("stop").set_defaults(func=_cmd_stop)
    sub.add_parser("status").set_defaults(func=_cmd_status)
    sub.add_parser("restart").set_defaults(func=None)
    return p


def main(argv: list[str] | None = None) -> int:
    p = _build_parser()
    args = p.parse_args(argv)
    if args.cmd == "restart":
        _cmd_stop(args)
        return _cmd_start(args)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
