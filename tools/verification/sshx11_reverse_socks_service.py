#!/usr/bin/env python3
from __future__ import annotations

"""Manage reverse SOCKS (remote dynamic forward) sessions over SSH."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

try:
    from tools.verification import sshx11_remote_compat as remote_compat
except Exception:  # pragma: no cover - script execution path
    import sshx11_remote_compat as remote_compat


REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = Path(tempfile.gettempdir())
DEFAULT_PID = TMP_DIR / "sshx11_reverse_socks.pid"
DEFAULT_LOG = TMP_DIR / "sshx11_reverse_socks.log"
DEFAULT_STATE = REPO_ROOT / "verification_results" / "runtime" / "sshx11_reverse_socks_state.json"


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


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _as_bool(value: Any) -> bool:
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _ssh_verbosity(args: argparse.Namespace) -> int:
    raw = _as_int(getattr(args, "ssh_verbosity", 0), 0)
    return max(0, min(3, int(raw)))


def _agent_mode(args: argparse.Namespace) -> str:
    mode = str(getattr(args, "agent_mode", "auto") or "auto").strip().lower()
    if mode in {"auto", "require", "disable"}:
        return mode
    return "auto"


def _resolve_identity_agent(args: argparse.Namespace) -> str:
    raw = str(getattr(args, "identity_agent", "") or "").strip()
    if raw.startswith("env:"):
        env_key = raw.split(":", 1)[1].strip()
        raw = os.environ.get(env_key, "")
    if not raw:
        raw = os.environ.get("SSH_AUTH_SOCK", "")
    raw = str(raw or "").strip()
    if not raw:
        return ""
    if raw.startswith("\\\\.\\pipe\\") or raw.startswith("pageant:"):
        return raw
    return str(Path(raw).expanduser())


def _agent_precheck(args: argparse.Namespace) -> str:
    if _agent_mode(args) != "require":
        return ""
    if _resolve_identity_agent(args):
        return ""
    return "agent_required_but_not_available"


def _ssh_base(args: argparse.Namespace) -> list[str]:
    target = f"{args.user}@{args.host}"
    cmd = [
        str(args.ssh_bin),
        "-p",
        str(int(args.port)),
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
    ]
    ssh_config = str(args.ssh_config or "").strip()
    if ssh_config:
        cmd.extend(["-F", ssh_config])
    identity = str(args.identity_file or "").strip()
    if identity:
        cmd.extend(["-i", identity])
    proxy_jump = str(args.proxy_jump or "").strip()
    if proxy_jump:
        cmd.extend(["-o", f"ProxyJump={proxy_jump}"])
    proxy_command = str(args.proxy_command or "").strip()
    if proxy_command:
        cmd.extend(["-o", f"ProxyCommand={proxy_command}"])
    ssh_log_level = str(getattr(args, "ssh_log_level", "") or "").strip()
    if ssh_log_level:
        cmd.extend(["-o", f"LogLevel={ssh_log_level}"])
    ssh_log_file = str(getattr(args, "ssh_log_file", "") or "").strip()
    if ssh_log_file:
        cmd.extend(["-E", ssh_log_file])
    for _ in range(_ssh_verbosity(args)):
        cmd.append("-v")
    mode = _agent_mode(args)
    identity_agent = _resolve_identity_agent(args)
    if mode == "disable":
        cmd.extend(["-o", "IdentityAgent=none"])
    elif identity_agent:
        cmd.extend(["-o", f"IdentityAgent={identity_agent}"])
    if bool(args.forward_agent):
        cmd.append("-A")
    else:
        cmd.append("-a")
    if bool(args.insecure_hostkey):
        cmd.extend(
            [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        )
    cmd.append(target)
    return cmd


def _build_tunnel_command(args: argparse.Namespace) -> list[str]:
    remote_spec = f"{args.remote_bind_host}:{int(args.remote_socks_port)}"
    cmd = _ssh_base(args)
    cmd[1:1] = [
        "-N",
        "-R",
        remote_spec,
        "-o",
        "ExitOnForwardFailure=yes",
    ]
    return cmd


def _probe_remote_listener(args: argparse.Namespace, timeout_s: float) -> tuple[bool | None, str]:
    # Use platform-aware remote probe fallbacks (python/perl/netcat/ksh).
    host = str(args.remote_bind_host).strip() or "127.0.0.1"
    port = int(args.remote_socks_port)
    probe = remote_compat.build_tcp_probe_command(
        host=host,
        port=port,
        timeout_s=timeout_s,
        platform=str(args.remote_platform),
        preferred_python=str(args.remote_python_bin or ""),
    )
    cmd = _ssh_base(args)
    cmd.extend(
        [
            *remote_compat.remote_shell_argv(
                shell_bin=str(args.remote_shell_bin or "sh"),
                login_shell=bool(args.remote_shell_login),
            ),
            probe,
        ]
    )
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(2.0, float(timeout_s) + 1.0),
        )
    except subprocess.TimeoutExpired:
        return None, "probe_timeout"
    except Exception:
        return None, "probe_unavailable"

    if int(proc.returncode) == 0:
        return True, "open"
    if remote_compat.probe_tooling_missing(str(proc.stdout or ""), str(proc.stderr or "")):
        return None, "probe_tooling_missing"
    return False, "closed_or_unreachable"


def _state(args: argparse.Namespace) -> dict[str, Any]:
    pid = _read_pid(Path(args.pid_file))
    alive = bool(pid and _is_pid_alive(pid))
    mode = _agent_mode(args)
    identity_agent = _resolve_identity_agent(args)
    agent_error = _agent_precheck(args)
    probe_ok: bool | None = None
    probe_reason = "skipped"
    if alive and str(args.host).strip() and not agent_error:
        probe_ok, probe_reason = _probe_remote_listener(args, timeout_s=1.2)
    elif alive and agent_error:
        probe_ok = False
        probe_reason = agent_error
    status = "running" if alive and (probe_ok is True or probe_ok is None) else "degraded"
    if not alive:
        status = "stopped"
    return {
        "ok": bool(status == "running"),
        "status": status,
        "mode": "reverse_socks",
        "timestamp_unix": int(time.time()),
        "host": str(args.host),
        "user": str(args.user),
        "port": int(args.port),
        "ssh_bin": str(args.ssh_bin),
        "agent_mode": mode,
        "forward_agent": bool(args.forward_agent),
        "identity_agent": identity_agent,
        "agent_error": agent_error,
        "identity_file": str(args.identity_file or ""),
        "ssh_config": str(args.ssh_config or ""),
        "proxy_jump": str(args.proxy_jump or ""),
        "proxy_command": str(args.proxy_command or ""),
        "ssh_verbosity": int(_ssh_verbosity(args)),
        "ssh_log_level": str(args.ssh_log_level or ""),
        "ssh_log_file": str(args.ssh_log_file or ""),
        "remote_platform": str(args.remote_platform),
        "remote_shell_bin": str(args.remote_shell_bin),
        "remote_shell_login": bool(args.remote_shell_login),
        "remote_python_bin": str(args.remote_python_bin or ""),
        "remote_bind_host": str(args.remote_bind_host),
        "remote_socks_port": int(args.remote_socks_port),
        "remote_socks_uri": f"socks5h://{args.remote_bind_host}:{int(args.remote_socks_port)}",
        "pid": int(pid or 0),
        "pid_alive": bool(alive),
        "probe_ok": probe_ok,
        "probe_reason": probe_reason,
        "pid_file": str(args.pid_file),
        "log_file": str(args.log_file),
        "state_file": str(args.state_file),
    }


def _cmd_start(args: argparse.Namespace) -> int:
    host = str(args.host or "").strip()
    if not host:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "missing_host",
                    "hint": "pass --host or set SSHX11_REVERSE_SOCKS_REMOTE_HOST/SSHX11_REMOTE_HOST",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    agent_error = _agent_precheck(args)
    if agent_error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": agent_error,
                    "hint": "set --identity-agent (or SSH_AUTH_SOCK) or change --agent-mode",
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

    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = _build_tunnel_command(args)
    with log_path.open("ab") as logh:
        proc = subprocess.Popen(
            cmd,
            stdout=logh,
            stderr=subprocess.STDOUT,
            **_session_spawn_kwargs(),
        )
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")

    time.sleep(min(max(0.1, float(args.startup_timeout_s) / 4.0), 0.3))
    if not _is_pid_alive(proc.pid):
        _stop_pid(pid_file, timeout_s=float(args.shutdown_timeout_s))
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "ssh_process_exited",
                    "pid": int(proc.pid),
                    "command": cmd,
                    "log_file": str(log_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    state = _state(args)
    _write_state(Path(args.state_file), state)
    print(json.dumps({"ok": True, "status": "started", **state}, indent=2, sort_keys=True))
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
    p.add_argument("--host", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_HOST", os.environ.get("SSHX11_REMOTE_HOST", "")))
    p.add_argument("--user", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_USER", os.environ.get("SSHX11_REMOTE_USER", "root")))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PORT", os.environ.get("SSHX11_REMOTE_PORT", "22"))))
    p.add_argument("--identity-file", default=os.environ.get("SSHX11_REVERSE_SOCKS_IDENTITY_FILE", os.environ.get("SSHX11_REMOTE_IDENTITY_FILE", "")))
    p.add_argument(
        "--agent-mode",
        choices=["auto", "require", "disable"],
        default=os.environ.get("SSHX11_REVERSE_SOCKS_AGENT_MODE", os.environ.get("SSHX11_AGENT_MODE", "auto")),
        help="ssh-agent mode: auto|require|disable",
    )
    p.add_argument(
        "--forward-agent",
        action="store_true",
        default=_as_bool(os.environ.get("SSHX11_REVERSE_SOCKS_FORWARD_AGENT", os.environ.get("SSHX11_FORWARD_AGENT", "0"))),
        help="Enable agent forwarding (-A).",
    )
    p.add_argument(
        "--identity-agent",
        default=os.environ.get(
            "SSHX11_REVERSE_SOCKS_IDENTITY_AGENT",
            os.environ.get("SSHX11_IDENTITY_AGENT", os.environ.get("SSHX11_AGENT_SOCKET", os.environ.get("SSH_AUTH_SOCK", ""))),
        ),
        help="IdentityAgent socket/path (supports env:VAR and PuTTY/Pageant/antagent-compatible bridges).",
    )
    p.add_argument(
        "--ssh-config",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_CONFIG", os.environ.get("SSHX11_SSH_CONFIG", "")),
        help="Path to OpenSSH client config file used with -F.",
    )
    p.add_argument(
        "--proxy-jump",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_JUMP", os.environ.get("SSHX11_PROXY_JUMP", "")),
        help="ProxyJump target(s), equivalent to -o ProxyJump=...",
    )
    p.add_argument(
        "--proxy-command",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_COMMAND", os.environ.get("SSHX11_PROXY_COMMAND", "")),
        help="ProxyCommand string, equivalent to -o ProxyCommand=...",
    )
    p.add_argument(
        "--ssh-verbosity",
        type=int,
        default=_as_int(os.environ.get("SSHX11_REVERSE_SOCKS_SSH_VERBOSITY", os.environ.get("SSHX11_SSH_VERBOSITY", "0")), 0),
        help="SSH verbose flag count (0..3 -> -v/-vv/-vvv).",
    )
    p.add_argument(
        "--ssh-log-level",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_LEVEL", os.environ.get("SSHX11_SSH_LOG_LEVEL", "")),
        help="SSH LogLevel value (for example INFO, VERBOSE, DEBUG3).",
    )
    p.add_argument(
        "--ssh-log-file",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_FILE", os.environ.get("SSHX11_SSH_LOG_FILE", "")),
        help="SSH client log file path passed via -E.",
    )
    p.add_argument(
        "--remote-platform",
        choices=list(remote_compat.SUPPORTED_REMOTE_PLATFORMS),
        default=remote_compat.normalize_remote_platform(
            os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PLATFORM", os.environ.get("SSHX11_REMOTE_PLATFORM", "auto"))
        ),
        help="Remote host platform profile for probe fallback selection.",
    )
    p.add_argument(
        "--remote-shell-bin",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_SHELL_BIN", os.environ.get("SSHX11_REMOTE_SHELL_BIN", "sh")),
        help="Remote shell binary used for probe execution (for example sh, ksh, /bin/sh).",
    )
    p.add_argument(
        "--remote-shell-login",
        action="store_true",
        default=_as_bool(
            os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_SHELL_LOGIN", os.environ.get("SSHX11_REMOTE_SHELL_LOGIN", "1"))
        ),
        help="Use login shell mode (-lc) for remote probe shell.",
    )
    p.add_argument(
        "--no-remote-shell-login",
        dest="remote_shell_login",
        action="store_false",
        help="Use non-login shell mode (-c) for remote probe shell.",
    )
    p.add_argument(
        "--remote-python-bin",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PYTHON_BIN", os.environ.get("SSHX11_REMOTE_PYTHON_BIN", "")),
        help="Preferred remote Python executable for probe (falls back to platform defaults).",
    )
    p.add_argument(
        "--insecure-hostkey",
        action="store_true",
        default=_as_bool(os.environ.get("SSHX11_REVERSE_SOCKS_INSECURE_HOSTKEY", os.environ.get("SSHX11_REMOTE_INSECURE_HOSTKEY", "0"))),
        help="Use StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null (development only).",
    )
    p.add_argument("--ssh-bin", default=os.environ.get("SSH_BIN", "ssh"))
    p.add_argument("--remote-bind-host", default=os.environ.get("SSHX11_REVERSE_SOCKS_BIND_HOST", "127.0.0.1"))
    p.add_argument("--remote-socks-port", type=int, default=int(os.environ.get("SSHX11_REVERSE_SOCKS_PORT", "19080")))
    p.add_argument("--pid-file", type=Path, default=DEFAULT_PID)
    p.add_argument("--log-file", type=Path, default=DEFAULT_LOG)
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE)
    p.add_argument("--startup-timeout-s", type=float, default=4.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=5.0)
    p.add_argument("command", choices=["start", "stop", "status"])
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.pid_file = _resolve_path(args.pid_file)
    args.log_file = _resolve_path(args.log_file)
    args.state_file = _resolve_path(args.state_file)
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "stop":
        return _cmd_stop(args)
    return _cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())
