#!/usr/bin/env python3
from __future__ import annotations

"""Manage weaverssh SOCKS-over-SSHX11 fallback service processes."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = Path(tempfile.gettempdir())
DEFAULT_X11WS_REPO = Path.home() / "weaverssh"
DEFAULT_AGENT_PID = TMP_DIR / "sshx11_x11ws_agentproxy.pid"
DEFAULT_CLIENT_PID = TMP_DIR / "sshx11_x11ws_clientproxy.pid"
DEFAULT_AGENT_LOG = TMP_DIR / "sshx11_x11ws_agentproxy.log"
DEFAULT_CLIENT_LOG = TMP_DIR / "sshx11_x11ws_clientproxy.log"
AGENT_RUN_PACKAGE = "./cmd/wv-agent"


def _is_windows(platform_name: str | None = None) -> bool:
    return str(platform_name or os.name).lower() == "nt"


def _session_spawn_kwargs(platform_name: str | None = None) -> dict[str, object]:
    if _is_windows(platform_name):
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if flags > 0:
            return {"creationflags": flags}
        return {}
    return {"start_new_session": True}


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


def _read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + max(0.1, float(timeout_s))
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


def _parse_host_port(value: str) -> tuple[str, int]:
    raw = str(value).strip()
    if ":" not in raw:
        raise ValueError(f"invalid host:port value '{raw}'")
    host, p = raw.rsplit(":", 1)
    port = int(p)
    if not host:
        host = "127.0.0.1"
    return host, port


def _listener_pid(port: int) -> int | None:
    try:
        proc = subprocess.run(
            ["lsof", "-tiTCP:%d" % int(port), "-sTCP:LISTEN"],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    if proc.returncode not in (0, 1):
        return None
    for line in str(proc.stdout or "").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            return int(text)
        except ValueError:
            continue
    return None


def _start_proc(cmd: list[str], cwd: Path, log_file: Path, pid_file: Path) -> int:
    existing = _read_pid(pid_file)
    if existing and _is_pid_alive(existing):
        return existing
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as logh:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=logh,
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
    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))


def _stop_proc(pid_file: Path, timeout_s: float) -> int:
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
    deadline = time.time() + max(0.5, timeout_s)
    while time.time() < deadline:
        if not _is_pid_alive(pid):
            pid_file.unlink(missing_ok=True)
            return pid
        time.sleep(0.1)
    if _is_pid_alive(pid):
        _force_kill_pid(pid)
    pid_file.unlink(missing_ok=True)
    return pid


def _validate_repo(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"weaverssh repo path does not exist: {path}")
    for name in ("cmd/wv-agent/main.go", "cmd/wv-socks/main.go", "internal/app/agent.go", "internal/app/socks.go", "go.mod"):
        if not (path / name).exists():
            raise FileNotFoundError(f"weaverssh repo missing required file: {path / name}")


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _build_state(args: argparse.Namespace) -> dict[str, Any]:
    agent_host, agent_port = _parse_host_port(args.agent_listen)
    now = int(time.time())
    agent_pid = _read_pid(Path(args.agent_pid_file))
    client_pid = _read_pid(Path(args.client_pid_file))
    agent_alive = bool(agent_pid and _is_pid_alive(agent_pid))
    client_alive = bool(client_pid and _is_pid_alive(client_pid))
    return {
        "ok": bool(agent_alive and client_alive),
        "mode": "socks_over_sshx11",
        "timestamp_unix": now,
        "x11ws_repo": str(Path(args.weaverssh_repo).expanduser()),
        "agent_listen": str(args.agent_listen),
        "agent_endpoint": str(args.agent_endpoint),
        "agent_host": agent_host,
        "agent_port": int(agent_port),
        "socks_host": str(args.socks_host),
        "socks_port": int(args.socks_port),
        "socks_uri": f"socks5://{args.socks_host}:{int(args.socks_port)}",
        "x11_mode": bool(args.x11_mode),
        "agent_pid": int(agent_pid or 0),
        "agent_alive": bool(agent_alive),
        "client_pid": int(client_pid or 0),
        "client_alive": bool(client_alive),
        "agent_log_file": str(args.agent_log_file),
        "client_log_file": str(args.client_log_file),
        "state_file": str(args.state_file),
    }


def _cmd_start(args: argparse.Namespace) -> int:
    repo = Path(args.weaverssh_repo).expanduser()
    _validate_repo(repo)
    agent_host, agent_port = _parse_host_port(args.agent_listen)
    Path(args.state_file).parent.mkdir(parents=True, exist_ok=True)

    agent_cmd = [
        str(args.go_bin),
        "run",
        AGENT_RUN_PACKAGE,
        "-listen",
        str(args.agent_listen),
        "-loglevel",
        str(args.loglevel),
    ]
    client_cmd = [
        str(args.go_bin),
        "run",
        "./cmd/wv-socks",
        "-port",
        str(int(args.socks_port)),
        "-agent",
        str(args.agent_endpoint),
        "-loglevel",
        str(args.loglevel),
    ]
    if bool(args.x11_mode):
        client_cmd.append("-X")

    agent_pid = _start_proc(agent_cmd, repo, Path(args.agent_log_file), Path(args.agent_pid_file))
    if not _wait_for_port(agent_host, int(agent_port), float(args.startup_timeout_s)):
        _stop_proc(Path(args.agent_pid_file), float(args.shutdown_timeout_s))
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "agent_not_ready",
                    "agent_pid": int(agent_pid),
                    "agent_listen": str(args.agent_listen),
                },
                indent=2,
            )
        )
        return 2

    client_pid = _start_proc(client_cmd, repo, Path(args.client_log_file), Path(args.client_pid_file))
    if not _wait_for_port(str(args.socks_host), int(args.socks_port), float(args.startup_timeout_s)):
        _stop_proc(Path(args.client_pid_file), float(args.shutdown_timeout_s))
        _stop_proc(Path(args.agent_pid_file), float(args.shutdown_timeout_s))
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "socks_not_ready",
                    "client_pid": int(client_pid),
                    "socks_host": str(args.socks_host),
                    "socks_port": int(args.socks_port),
                },
                indent=2,
            )
        )
        return 2

    state = _build_state(args)
    _write_state(Path(args.state_file), state)
    print(json.dumps({"ok": True, "status": "started", **state}, indent=2))
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    client_pid = _stop_proc(Path(args.client_pid_file), float(args.shutdown_timeout_s))
    agent_pid = _stop_proc(Path(args.agent_pid_file), float(args.shutdown_timeout_s))
    Path(args.state_file).unlink(missing_ok=True)
    print(
        json.dumps(
            {"ok": True, "status": "stopped", "agent_pid": int(agent_pid), "client_pid": int(client_pid)},
            indent=2,
        )
    )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    state = _build_state(args)
    socks_up = _wait_for_port(str(args.socks_host), int(args.socks_port), 0.5)
    agent_host, agent_port = _parse_host_port(args.agent_listen)
    agent_up = _wait_for_port(agent_host, int(agent_port), 0.5)

    # Recover from stale/missing pid files by discovering live listener pids.
    if agent_up and not state["agent_alive"]:
        pid = _listener_pid(int(agent_port))
        if pid and _is_pid_alive(pid):
            state["agent_pid"] = int(pid)
            state["agent_alive"] = True
    if socks_up and not state["client_alive"]:
        pid = _listener_pid(int(args.socks_port))
        if pid and _is_pid_alive(pid):
            state["client_pid"] = int(pid)
            state["client_alive"] = True

    state["ok"] = bool(state["agent_alive"] and state["client_alive"])
    state.update(
        {
            "socks_port_open": bool(socks_up),
            "agent_port_open": bool(agent_up),
            "status": "running" if state["ok"] and socks_up and agent_up else "degraded",
        }
    )
    _write_state(Path(args.state_file), state)
    print(json.dumps(state, indent=2))
    return 0 if state["status"] == "running" else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--weaverssh-repo", default=str(DEFAULT_X11WS_REPO))
    p.add_argument("--go-bin", default=os.environ.get("GO_BIN", "go"))
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--agent-listen", default="localhost:6000")
    p.add_argument("--agent-endpoint", default="localhost:6000")
    p.add_argument("--no-x11-mode", action="store_false", dest="x11_mode", default=True)
    p.add_argument("--loglevel", default="info")
    p.add_argument(
        "--state-file",
        default="verification_results/runtime/sshx11_socks_fallback_state.json",
    )
    p.add_argument("--agent-pid-file", default=str(DEFAULT_AGENT_PID))
    p.add_argument("--client-pid-file", default=str(DEFAULT_CLIENT_PID))
    p.add_argument("--agent-log-file", default=str(DEFAULT_AGENT_LOG))
    p.add_argument("--client-log-file", default=str(DEFAULT_CLIENT_LOG))
    p.add_argument("--startup-timeout-s", type=float, default=15.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=5.0)
    p.add_argument("command", choices=["start", "stop", "status"])
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "stop":
        return _cmd_stop(args)
    return _cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())
