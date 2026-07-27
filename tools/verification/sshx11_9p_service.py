#!/usr/bin/env python3
"""Manage the repo-native read-only wv-9p service for VFS workflows."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = Path(tempfile.gettempdir())
DEFAULT_BINARY = REPO_ROOT / "build" / "bin" / "wv-9p"
DEFAULT_ROOT = REPO_ROOT / "verification_results" / "runtime" / "sshx11_vfs_namespace"
DEFAULT_PID = TMP_DIR / "sshx11_9p.pid"
DEFAULT_LOG = TMP_DIR / "sshx11_9p.log"
DEFAULT_STATE = REPO_ROOT / "verification_results" / "runtime" / "sshx11_9p_state.json"
DEFAULT_CONTAINER_IMAGE = "weaverssh/wv-9p:local"
DEFAULT_CONTAINERFILE = REPO_ROOT / "tools" / "containers" / "wv-9p.Containerfile"
CONTAINER_ROOT = "/srv/weaverssh-9p-root"
CONTAINER_PORT = 5640
CONTAINER_RUNTIMES = ("docker", "podman", "nerdctl")


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


def _split_listen(value: str) -> tuple[str, int]:
    if ":" not in str(value):
        raise argparse.ArgumentTypeError("listen must be HOST:PORT")
    host, port_text = str(value).rsplit(":", 1)
    if not host:
        host = "127.0.0.1"
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("listen port must be an integer") from exc
    if port <= 0 or port > 65535:
        raise argparse.ArgumentTypeError("listen port must be in 1..65535")
    return host, port


def _listen_value(host: str, port: int) -> str:
    return f"{host}:{int(port)}"


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


def _tail_text(path: Path, lines: int) -> str:
    if not path.exists():
        return ""
    rows = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if lines <= 0:
        return "\n".join(rows)
    return "\n".join(rows[-int(lines) :])



def _container_name(args: argparse.Namespace) -> str:
    raw = str(getattr(args, "container_name", "") or "").strip()
    if raw:
        return raw
    return f"weaverssh-wv-9p-{int(args.port)}"


def _container_runtime_order(args: argparse.Namespace) -> list[str]:
    raw = str(getattr(args, "container_runtime_order", "") or "").strip()
    values = [item.strip() for item in raw.split(",") if item.strip()] if raw else list(CONTAINER_RUNTIMES)
    return values or list(CONTAINER_RUNTIMES)


def _select_container_runtime(args: argparse.Namespace) -> dict[str, Any]:
    requested = str(getattr(args, "runtime", "host") or "host").strip().lower()
    override = str(getattr(args, "container_runtime_bin", "") or "").strip()
    if requested == "host":
        return {"runtime": "host", "requested": requested, "binary": "", "available": True, "reason": "host_runtime"}
    if override:
        return {
            "runtime": requested if requested != "auto" else Path(override).name,
            "requested": requested,
            "binary": override,
            "available": Path(override).exists() or shutil.which(override) is not None,
            "reason": "explicit_runtime_binary",
        }
    if requested == "auto":
        for candidate in _container_runtime_order(args):
            found = shutil.which(candidate)
            if found:
                return {"runtime": candidate, "requested": requested, "binary": found, "available": True, "reason": "auto_selected"}
        return {"runtime": "host", "requested": requested, "binary": "", "available": True, "reason": "auto_fell_back_to_host"}
    if requested not in CONTAINER_RUNTIMES:
        return {"runtime": requested, "requested": requested, "binary": "", "available": False, "reason": "unsupported_container_runtime"}
    found = shutil.which(requested)
    return {
        "runtime": requested,
        "requested": requested,
        "binary": found or requested,
        "available": bool(found),
        "reason": "runtime_found" if found else "runtime_not_found",
    }


def _is_container_mode(args: argparse.Namespace) -> bool:
    selected = _select_container_runtime(args)
    return str(selected["runtime"]) != "host"


def _container_listen(args: argparse.Namespace) -> str:
    return f"0.0.0.0:{int(getattr(args, 'container_port', CONTAINER_PORT))}"


def _container_port_publish(args: argparse.Namespace) -> str:
    return f"{args.host}:{int(args.port)}:{int(getattr(args, 'container_port', CONTAINER_PORT))}"


def _container_build_command(args: argparse.Namespace, runtime_bin: str) -> list[str]:
    cmd = [runtime_bin, "build", "-f", str(Path(args.containerfile)), "-t", str(args.container_image)]
    platform = str(getattr(args, "container_platform", "") or "").strip()
    if platform:
        cmd.extend(["--platform", platform])
    cmd.append(str(REPO_ROOT))
    return cmd


def _container_run_command(args: argparse.Namespace, runtime_bin: str) -> list[str]:
    root = Path(args.root)
    cmd = [
        runtime_bin,
        "run",
        "-d",
        "--name",
        _container_name(args),
        "-p",
        _container_port_publish(args),
        "-v",
        f"{root.resolve()}:{CONTAINER_ROOT}:ro",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ]
    if str(_select_container_runtime(args)["runtime"]) != "nerdctl":
        cmd.extend(["--pids-limit", str(int(args.container_pids_limit))])
        if str(args.container_memory).strip():
            cmd.extend(["--memory", str(args.container_memory).strip()])
    cmd.extend([
        str(args.container_image),
        "-root",
        CONTAINER_ROOT,
        "-listen",
        _container_listen(args),
        "-json",
    ])
    return cmd


def _container_inspect(args: argparse.Namespace, selected: dict[str, Any] | None = None) -> dict[str, Any]:
    selected = selected or _select_container_runtime(args)
    if not selected.get("available") or not selected.get("binary"):
        return {"ok": False, "exists": False, "running": False, "reason": selected.get("reason", "runtime_unavailable")}
    proc = subprocess.run(
        [str(selected["binary"]), "inspect", _container_name(args)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {"ok": True, "exists": False, "running": False, "stderr": (proc.stderr or "").strip()}
    try:
        data = json.loads(proc.stdout or "[]")
        obj = data[0] if isinstance(data, list) and data else data if isinstance(data, dict) else {}
    except Exception:
        obj = {}
    state = obj.get("State", {}) if isinstance(obj, dict) else {}
    return {
        "ok": True,
        "exists": True,
        "running": bool(state.get("Running")),
        "pid": int(state.get("Pid") or 0) if isinstance(state, dict) else 0,
        "id": str(obj.get("Id", "")) if isinstance(obj, dict) else "",
        "raw_state": state if isinstance(state, dict) else {},
    }


def _service_state_container(args: argparse.Namespace) -> dict[str, Any]:
    selected = _select_container_runtime(args)
    inspect = _container_inspect(args, selected) if selected.get("runtime") != "host" else {"running": False, "exists": False}
    port_open = _wait_for_port(str(args.host), int(args.port), 0.5)
    running = bool(inspect.get("running"))
    status = "running" if running and port_open else "degraded"
    if not running and not port_open:
        status = "stopped"
    root = Path(args.root)
    return {
        "ok": bool(status == "running"),
        "status": status,
        "mode": "9p",
        "service": "wv-9p",
        "service_runtime": "container",
        "timestamp_unix": int(time.time()),
        "host": str(args.host),
        "port": int(args.port),
        "listen": _listen_value(str(args.host), int(args.port)),
        "container_listen": _container_listen(args),
        "container_port": int(args.container_port),
        "root": str(root.resolve()),
        "root_exists": bool(root.exists()),
        "read_only": True,
        "container_runtime": selected.get("runtime"),
        "container_runtime_requested": selected.get("requested"),
        "container_runtime_binary": selected.get("binary"),
        "container_runtime_available": bool(selected.get("available")),
        "container_runtime_reason": selected.get("reason"),
        "container_image": str(args.container_image),
        "container_name": _container_name(args),
        "container_exists": bool(inspect.get("exists")),
        "container_running": running,
        "container_id": inspect.get("id", ""),
        "container_pid": int(inspect.get("pid") or 0),
        "port_open": bool(port_open),
        "state_file": str(args.state_file),
        "logs_command": [str(selected.get("binary") or selected.get("runtime")), "logs", _container_name(args)] if selected.get("runtime") != "host" else [],
    }

def _service_state(args: argparse.Namespace) -> dict[str, Any]:
    pid = _read_pid(Path(args.pid_file))
    alive = bool(pid and _is_pid_alive(pid))
    port_open = _wait_for_port(str(args.host), int(args.port), 0.5)
    status = "running" if alive and port_open else "degraded"
    if not alive and not port_open:
        status = "stopped"
    binary = Path(args.binary)
    root = Path(args.root)
    return {
        "ok": bool(status == "running"),
        "status": status,
        "mode": "9p",
        "service": "wv-9p",
        "service_runtime": "host",
        "timestamp_unix": int(time.time()),
        "host": str(args.host),
        "port": int(args.port),
        "listen": _listen_value(str(args.host), int(args.port)),
        "root": str(root.resolve()),
        "root_exists": bool(root.exists()),
        "binary": str(binary.resolve()),
        "binary_exists": bool(binary.exists()),
        "pid": int(pid or 0),
        "pid_alive": bool(alive),
        "port_open": bool(port_open),
        "pid_file": str(args.pid_file),
        "log_file": str(args.log_file),
        "state_file": str(args.state_file),
        "read_only": True,
    }


def _cmd_plan(args: argparse.Namespace) -> int:
    root = Path(args.root)
    selected = _select_container_runtime(args)
    if selected.get("runtime") != "host":
        runtime_bin = str(selected.get("binary") or selected.get("runtime"))
        payload = {
            "ok": bool(root.exists() and selected.get("available")),
            "status": "planned",
            "mode": "9p",
            "service": "wv-9p",
            "service_runtime": "container",
            "root": str(root.resolve()),
            "root_exists": bool(root.exists()),
            "read_only": True,
            "container_runtime": selected.get("runtime"),
            "container_runtime_requested": selected.get("requested"),
            "container_runtime_binary": selected.get("binary"),
            "container_runtime_available": bool(selected.get("available")),
            "container_runtime_reason": selected.get("reason"),
            "container_image": str(args.container_image),
            "container_name": _container_name(args),
            "containerfile": str(Path(args.containerfile).resolve()),
            "containerfile_exists": bool(Path(args.containerfile).exists()),
            "container_port": int(args.container_port),
            "listen": _listen_value(str(args.host), int(args.port)),
            "container_listen": _container_listen(args),
            "command": _container_run_command(args, runtime_bin),
            "build_command": _container_build_command(args, runtime_bin),
            "build_enabled": bool(args.container_build),
            "namespace_command": "tools/verification/sshx11_ops.sh vfs-mesh-build",
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["ok"] else 1

    binary = Path(args.binary)
    payload = {
        "ok": bool(binary.exists() and root.exists()),
        "status": "planned",
        "mode": "9p",
        "service": "wv-9p",
        "service_runtime": "host",
        "command": [
            str(binary),
            "-root",
            str(root),
            "-listen",
            _listen_value(str(args.host), int(args.port)),
            "-json",
        ],
        "binary_exists": bool(binary.exists()),
        "root_exists": bool(root.exists()),
        "build_command": "make build-9p",
        "namespace_command": "tools/verification/sshx11_ops.sh vfs-mesh-build",
    }
    _write_state(Path(args.state_file), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


def _cmd_image_build(args: argparse.Namespace) -> int:
    selected = _select_container_runtime(args)
    if selected.get("runtime") == "host":
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "container_runtime_required",
            "message": "image-build requires --runtime docker|podman|nerdctl|auto with an available container runtime",
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    runtime_bin = str(selected.get("binary") or selected.get("runtime"))
    if not selected.get("available") or not runtime_bin:
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "container_runtime_unavailable",
            "container_runtime": selected.get("runtime"),
            "container_runtime_requested": selected.get("requested"),
            "container_runtime_binary": selected.get("binary"),
            "container_runtime_reason": selected.get("reason"),
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    cmd = _container_build_command(args, runtime_bin)
    payload = {
        "ok": True,
        "status": "would_build" if bool(args.dry_run) else "building",
        "mode": "9p",
        "service": "wv-9p",
        "service_runtime": "container",
        "command": cmd,
        "container_runtime": selected.get("runtime"),
        "container_runtime_binary": runtime_bin,
        "container_image": str(args.container_image),
        "containerfile": str(Path(args.containerfile).resolve()),
        "containerfile_exists": bool(Path(args.containerfile).exists()),
    }
    if bool(args.dry_run):
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    payload.update(
        {
            "ok": proc.returncode == 0,
            "status": "built" if proc.returncode == 0 else "failed",
            "exit_code": int(proc.returncode),
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        }
    )
    if proc.returncode != 0:
        payload["reason"] = "container_build_failed"
    _write_state(Path(args.state_file), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if proc.returncode == 0 else 2


def _cmd_logs(args: argparse.Namespace) -> int:
    if _is_container_mode(args):
        selected = _select_container_runtime(args)
        runtime_bin = str(selected.get("binary") or selected.get("runtime"))
        if not selected.get("available") or not runtime_bin:
            payload = {
                "ok": False,
                "status": "failed",
                "reason": "container_runtime_unavailable",
                "container_runtime": selected.get("runtime"),
                "container_runtime_binary": selected.get("binary"),
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 2
        cmd = [runtime_bin, "logs"]
        if int(args.logs_tail) > 0:
            cmd.extend(["--tail", str(int(args.logs_tail))])
        cmd.append(_container_name(args))
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        payload = {
            "ok": proc.returncode == 0,
            "status": "logs" if proc.returncode == 0 else "failed",
            "mode": "9p",
            "service": "wv-9p",
            "service_runtime": "container",
            "command": cmd,
            "container_runtime": selected.get("runtime"),
            "container_name": _container_name(args),
            "exit_code": int(proc.returncode),
            "text": proc.stdout or "",
            "stderr": (proc.stderr or "").strip(),
        }
        if proc.returncode != 0:
            payload["reason"] = "container_logs_failed"
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if proc.returncode == 0 else 2

    log_file = Path(args.log_file)
    payload = {
        "ok": True,
        "status": "logs",
        "mode": "9p",
        "service": "wv-9p",
        "service_runtime": "host",
        "log_file": str(log_file),
        "exists": bool(log_file.exists()),
        "lines": int(args.logs_tail),
        "text": _tail_text(log_file, int(args.logs_tail)),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_start_container(args: argparse.Namespace) -> int:
    root = Path(args.root)
    selected = _select_container_runtime(args)
    runtime_bin = str(selected.get("binary") or selected.get("runtime"))
    if not selected.get("available") or not runtime_bin:
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "container_runtime_unavailable",
            "container_runtime": selected.get("runtime"),
            "container_runtime_requested": selected.get("requested"),
            "container_runtime_binary": selected.get("binary"),
            "container_runtime_reason": selected.get("reason"),
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    if not root.exists():
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "root_missing",
            "root": str(root),
            "namespace_command": "tools/verification/sshx11_ops.sh vfs-mesh-build",
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    if not root.is_dir():
        payload = {"ok": False, "status": "failed", "reason": "root_not_directory", "root": str(root)}
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
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
                payload = {"ok": False, "status": "failed", "reason": "bind_failed_no_fallback_port", "host": str(args.host), "port": int(requested_port), "bind_error": bind_reason}
                _write_state(Path(args.state_file), payload)
                print(json.dumps(payload, indent=2, sort_keys=True))
                return 2
        else:
            payload = {"ok": False, "status": "failed", "reason": "bind_failed", "host": str(args.host), "port": int(requested_port), "bind_error": bind_reason}
            _write_state(Path(args.state_file), payload)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 2

    inspect = _container_inspect(args, selected)
    if inspect.get("running"):
        state = _service_state_container(args)
        state["status"] = "already_running"
        state["ok"] = True
        _write_state(Path(args.state_file), state)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    build_cmd = _container_build_command(args, runtime_bin)
    run_cmd = _container_run_command(args, runtime_bin)
    if bool(args.dry_run):
        payload = {
            "ok": True,
            "status": "would_start",
            "mode": "9p",
            "service": "wv-9p",
            "service_runtime": "container",
            "command": run_cmd,
            "build_command": build_cmd,
            "build_enabled": bool(args.container_build),
            "container_runtime": selected.get("runtime"),
            "container_image": str(args.container_image),
            "container_name": _container_name(args),
            "root": str(root.resolve()),
            "listen": _listen_value(str(args.host), int(args.port)),
            "container_listen": _container_listen(args),
        }
        if fallback_from_port > 0:
            payload["fallback_from_port"] = int(fallback_from_port)
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if bool(args.container_build):
        build = subprocess.run(build_cmd, capture_output=True, text=True, check=False)
        if build.returncode != 0:
            payload = {"ok": False, "status": "failed", "reason": "container_build_failed", "command": build_cmd, "stdout": (build.stdout or "").strip(), "stderr": (build.stderr or "").strip()}
            _write_state(Path(args.state_file), payload)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 2

    if inspect.get("exists") and not inspect.get("running"):
        subprocess.run([runtime_bin, "rm", "-f", _container_name(args)], capture_output=True, text=True, check=False)

    proc = subprocess.run(run_cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        payload = {"ok": False, "status": "failed", "reason": "container_start_failed", "command": run_cmd, "stdout": (proc.stdout or "").strip(), "stderr": (proc.stderr or "").strip()}
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2

    if not _wait_for_port(str(args.host), int(args.port), float(args.startup_timeout_s)):
        subprocess.run([runtime_bin, "rm", "-f", _container_name(args)], capture_output=True, text=True, check=False)
        payload = {"ok": False, "status": "failed", "reason": "port_not_ready", "host": str(args.host), "port": int(args.port), "container_name": _container_name(args), "container_id": (proc.stdout or "").strip(), "logs_command": [runtime_bin, "logs", _container_name(args)]}
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2

    state = _service_state_container(args)
    payload = {"ok": True, "status": "started", **state}
    payload["status"] = "started"
    payload["container_id"] = (proc.stdout or "").strip() or payload.get("container_id", "")
    if fallback_from_port > 0:
        payload["fallback_from_port"] = int(fallback_from_port)
    _write_state(Path(args.state_file), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0

def _cmd_start(args: argparse.Namespace) -> int:
    if _is_container_mode(args):
        return _cmd_start_container(args)
    binary = Path(args.binary)
    root = Path(args.root)
    if not binary.exists():
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "binary_missing",
            "binary": str(binary),
            "build_command": "make build-9p",
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    if not os.access(binary, os.X_OK):
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "binary_not_executable",
            "binary": str(binary),
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    if not root.exists():
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "root_missing",
            "root": str(root),
            "namespace_command": "tools/verification/sshx11_ops.sh vfs-mesh-build",
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2
    if not root.is_dir():
        payload = {"ok": False, "status": "failed", "reason": "root_not_directory", "root": str(root)}
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
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
                payload = {
                    "ok": False,
                    "status": "failed",
                    "reason": "bind_failed_no_fallback_port",
                    "host": str(args.host),
                    "port": int(requested_port),
                    "bind_error": bind_reason,
                }
                _write_state(Path(args.state_file), payload)
                print(json.dumps(payload, indent=2, sort_keys=True))
                return 2
        else:
            payload = {
                "ok": False,
                "status": "failed",
                "reason": "bind_failed",
                "host": str(args.host),
                "port": int(requested_port),
                "bind_error": bind_reason,
            }
            _write_state(Path(args.state_file), payload)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 2

    pid_file = Path(args.pid_file)
    existing = _read_pid(pid_file)
    if existing and _is_pid_alive(existing):
        state = _service_state(args)
        state["status"] = "already_running"
        state["ok"] = True
        _write_state(Path(args.state_file), state)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    log_file = Path(args.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    child_cmd = [
        str(binary),
        "-root",
        str(root),
        "-listen",
        _listen_value(str(args.host), int(args.port)),
        "-json",
    ]
    if bool(args.dry_run):
        payload = {
            "ok": True,
            "status": "would_start",
            "mode": "9p",
            "service": "wv-9p",
            "service_runtime": "host",
            "command": child_cmd,
            "root": str(root.resolve()),
            "listen": _listen_value(str(args.host), int(args.port)),
            "log_file": str(log_file),
            "pid_file": str(pid_file),
        }
        if fallback_from_port > 0:
            payload["fallback_from_port"] = int(fallback_from_port)
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
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
        payload = {
            "ok": False,
            "status": "failed",
            "reason": "port_not_ready",
            "host": str(args.host),
            "port": int(args.port),
            "log_file": str(log_file),
        }
        _write_state(Path(args.state_file), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2

    state = _service_state(args)
    payload = {"ok": True, "status": "started", **state}
    payload["status"] = "started"
    if fallback_from_port > 0:
        payload["fallback_from_port"] = int(fallback_from_port)
    _write_state(Path(args.state_file), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    if _is_container_mode(args):
        selected = _select_container_runtime(args)
        runtime_bin = str(selected.get("binary") or selected.get("runtime"))
        rc = 0
        stderr = ""
        if selected.get("available") and runtime_bin:
            proc = subprocess.run([runtime_bin, "rm", "-f", _container_name(args)], capture_output=True, text=True, check=False)
            rc = int(proc.returncode)
            stderr = (proc.stderr or "").strip()
        Path(args.state_file).unlink(missing_ok=True)
        payload = {
            "ok": bool(rc == 0),
            "status": "stopped" if rc == 0 else "failed",
            "service_runtime": "container",
            "container_runtime": selected.get("runtime"),
            "container_name": _container_name(args),
            "state_file": str(args.state_file),
        }
        if stderr:
            payload["stderr"] = stderr
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if rc == 0 else 2

    pid = _stop_pid(Path(args.pid_file), timeout_s=float(args.shutdown_timeout_s))
    Path(args.state_file).unlink(missing_ok=True)
    payload = {"ok": True, "status": "stopped", "service_runtime": "host", "pid": int(pid), "state_file": str(args.state_file)}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    state = _service_state_container(args) if _is_container_mode(args) else _service_state(args)
    _write_state(Path(args.state_file), state)
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0 if state.get("status") == "running" else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("SSHX11_9P_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11_9P_PORT", "5640")))
    p.add_argument("--listen", help="Override host/port with HOST:PORT")
    p.add_argument("--root", type=Path, default=Path(os.environ.get("SSHX11_9P_ROOT", str(DEFAULT_ROOT))))
    p.add_argument("--binary", type=Path, default=Path(os.environ.get("SSHX11_9P_BINARY", str(DEFAULT_BINARY))))
    p.add_argument("--pid-file", type=Path, default=Path(os.environ.get("SSHX11_9P_PID_FILE", str(DEFAULT_PID))))
    p.add_argument("--log-file", type=Path, default=Path(os.environ.get("SSHX11_9P_LOG_FILE", str(DEFAULT_LOG))))
    p.add_argument("--state-file", type=Path, default=Path(os.environ.get("SSHX11_9P_STATE_FILE", str(DEFAULT_STATE))))
    p.add_argument("--runtime", choices=["host", "docker", "podman", "nerdctl", "auto"], default=os.environ.get("SSHX11_9P_RUNTIME", "host"), help="Run wv-9p on the host or inside a container runtime")
    p.add_argument("--container-runtime-bin", default=os.environ.get("SSHX11_9P_CONTAINER_RUNTIME_BIN", ""), help="Explicit docker/podman/nerdctl binary path")
    p.add_argument("--container-runtime-order", default=os.environ.get("SSHX11_9P_CONTAINER_RUNTIME_ORDER", ",".join(CONTAINER_RUNTIMES)))
    p.add_argument("--container-image", default=os.environ.get("SSHX11_9P_CONTAINER_IMAGE", DEFAULT_CONTAINER_IMAGE))
    p.add_argument("--container-name", default=os.environ.get("SSHX11_9P_CONTAINER_NAME", ""), help="Container name; default includes the selected host port")
    p.add_argument("--containerfile", type=Path, default=Path(os.environ.get("SSHX11_9P_CONTAINERFILE", str(DEFAULT_CONTAINERFILE))))
    p.add_argument("--container-port", type=int, default=int(os.environ.get("SSHX11_9P_CONTAINER_PORT", str(CONTAINER_PORT))))
    p.add_argument("--container-platform", default=os.environ.get("SSHX11_9P_CONTAINER_PLATFORM", ""))
    p.add_argument("--container-build", action="store_true", default=os.environ.get("SSHX11_9P_CONTAINER_BUILD", "0").lower() in {"1", "true", "yes", "on"})
    p.add_argument("--container-memory", default=os.environ.get("SSHX11_9P_CONTAINER_MEMORY", "128m"))
    p.add_argument("--container-pids-limit", type=int, default=int(os.environ.get("SSHX11_9P_CONTAINER_PIDS_LIMIT", "128")))
    p.add_argument("--dry-run", action="store_true", help="For start/image-build, print the launch/build command without running it")
    p.add_argument("--logs-tail", type=int, default=int(os.environ.get("SSHX11_9P_LOGS_TAIL", "120")))
    p.add_argument("--startup-timeout-s", type=float, default=8.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=5.0)
    p.add_argument("--auto-port-fallback", action="store_true", default=True)
    p.add_argument("--no-auto-port-fallback", action="store_false", dest="auto_port_fallback")
    p.add_argument("--fallback-port-attempts", type=int, default=20)
    p.add_argument("command", choices=["start", "stop", "status", "plan", "image-build", "logs"])
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.listen:
        args.host, args.port = _split_listen(args.listen)
    args.binary = _resolve_path(args.binary)
    args.root = _resolve_path(args.root)
    args.pid_file = _resolve_path(args.pid_file)
    args.log_file = _resolve_path(args.log_file)
    args.state_file = _resolve_path(args.state_file)
    args.containerfile = _resolve_path(args.containerfile)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "image-build":
        return _cmd_image_build(args)
    if args.command == "logs":
        return _cmd_logs(args)
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "stop":
        return _cmd_stop(args)
    if args.command == "status":
        return _cmd_status(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
