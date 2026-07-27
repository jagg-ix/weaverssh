#!/usr/bin/env python3
from __future__ import annotations

"""Per-host VFS agent for SSHX11 mesh namespace (phase 1).

Phase-1 scope:
- Host export/import declaration
- Capability token provisioning (hash published, raw token local only)
- Heartbeat updates
- Local host registry update for mesh discovery
"""

import argparse
import hashlib
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
DEFAULT_PID_FILE = TMP_DIR / "sshx11_vfs_agent.pid"
DEFAULT_LOG_FILE = TMP_DIR / "sshx11_vfs_agent.log"
DEFAULT_STATE_FILE = Path("verification_results/runtime/sshx11_vfs_agent_state.json")
DEFAULT_REGISTRY_FILE = Path("verification_results/runtime/sshx11_vfs_registry.json")
DEFAULT_TOKEN_FILE = Path("verification_results/runtime/sshx11_vfs_agent.token")

STATE_SCHEMA = "sshx11_vfs_agent_state.v1"
REGISTRY_SCHEMA = "sshx11_vfs_registry.v1"


def _now_unix() -> int:
    return int(time.time())


def _json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _json_read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _is_windows() -> bool:
    return str(os.name).lower() == "nt"


def _session_spawn_kwargs() -> dict[str, Any]:
    if _is_windows():
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        return {"creationflags": flags} if flags > 0 else {}
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


def _write_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{int(pid)}\n", encoding="utf-8")


def _token_sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _resolve_token(*, explicit_token: str, token_file: Path) -> str:
    token = str(explicit_token or "").strip()
    if token:
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token + "\n", encoding="utf-8")
        return token
    if token_file.exists():
        existing = token_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    token = os.urandom(24).hex()
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token + "\n", encoding="utf-8")
    return token


def _parse_export_specs(values: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in values:
        token = str(raw).strip()
        if not token:
            continue
        # format: name=path[:mode]
        if "=" not in token:
            raise ValueError(f"invalid export spec '{token}', expected name=path[:mode]")
        name, rhs = token.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid export spec '{token}', empty name")
        mode = "rw"
        path = rhs.strip()
        if ":" in path:
            p, m = path.rsplit(":", 1)
            path = p.strip()
            mode = m.strip().lower()
        if mode not in {"ro", "rw"}:
            raise ValueError(f"invalid export mode '{mode}' in '{token}'")
        if not path:
            raise ValueError(f"invalid export path in '{token}'")
        out.append({"name": name, "path": path, "mode": mode})
    return out


def _parse_import_specs(values: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in values:
        token = str(raw).strip()
        if not token:
            continue
        # format: source_host:source_export=mount_path[:mode]
        if "=" not in token:
            raise ValueError(f"invalid import spec '{token}', expected source_host:source_export=mount_path[:mode]")
        left, right = token.split("=", 1)
        left = left.strip()
        right = right.strip()
        if ":" not in left:
            raise ValueError(f"invalid import source '{left}', expected source_host:source_export")
        source_host, source_export = left.split(":", 1)
        source_host = source_host.strip()
        source_export = source_export.strip()
        if not source_host or not source_export:
            raise ValueError(f"invalid import source in '{token}'")
        mode = "ro"
        mount_path = right
        if ":" in mount_path:
            p, m = mount_path.rsplit(":", 1)
            mount_path = p.strip()
            mode = m.strip().lower()
        if mode not in {"ro", "rw"}:
            raise ValueError(f"invalid import mode '{mode}' in '{token}'")
        if not mount_path:
            raise ValueError(f"invalid import mount path in '{token}'")
        out.append(
            {
                "source_host": source_host,
                "source_export": source_export,
                "mount_path": mount_path,
                "mode": mode,
            }
        )
    return out


def _load_registry(path: Path) -> dict[str, Any]:
    data = _json_read(path)
    hosts = data.get("hosts")
    if not isinstance(hosts, dict):
        hosts = {}
    return {
        "schema_version": str(data.get("schema_version", REGISTRY_SCHEMA)),
        "updated_unix": int(data.get("updated_unix", 0)),
        "hosts": hosts,
    }


def _save_registry(path: Path, payload: dict[str, Any]) -> None:
    payload["schema_version"] = REGISTRY_SCHEMA
    payload["updated_unix"] = _now_unix()
    _json_write(path, payload)


def _build_state(
    *,
    host_id: str,
    pid: int,
    node_endpoint: str,
    state_file: Path,
    registry_file: Path,
    token_file: Path,
    token_sha256: str,
    exports: list[dict[str, str]],
    imports: list[dict[str, str]],
    heartbeat_unix: int,
    status: str,
    namespace_root: str,
) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA,
        "ok": bool(status == "running"),
        "status": str(status),
        "host_id": str(host_id),
        "pid": int(pid),
        "node_endpoint": str(node_endpoint),
        "namespace_view": {
            "namespace_root": str(namespace_root),
            "local_prefix": f"{namespace_root.rstrip('/')}/{host_id}",
        },
        "exports": exports,
        "imports": imports,
        "capability": {
            "token_sha256": token_sha256,
            "token_file": str(token_file),
        },
        "heartbeat_unix": int(heartbeat_unix),
        "registry_file": str(registry_file),
        "state_file": str(state_file),
    }


def _sync_registry(
    *,
    registry_file: Path,
    host_id: str,
    node_endpoint: str,
    token_sha256: str,
    exports: list[dict[str, str]],
    imports: list[dict[str, str]],
    heartbeat_unix: int,
    namespace_root: str,
    status: str,
) -> dict[str, Any]:
    reg = _load_registry(registry_file)
    hosts = reg.get("hosts", {})
    hosts[str(host_id)] = {
        "host_id": str(host_id),
        "node_endpoint": str(node_endpoint),
        "namespace_prefix": f"{namespace_root.rstrip('/')}/{host_id}",
        "status": str(status),
        "last_heartbeat_unix": int(heartbeat_unix),
        "capability_token_sha256": str(token_sha256),
        "exports": exports,
        "imports": imports,
    }
    reg["hosts"] = hosts
    _save_registry(registry_file, reg)
    return reg


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host-id", default=socket.gethostname())
    p.add_argument("--node-endpoint", default="ssh://127.0.0.1:22")
    p.add_argument("--namespace-root", default="/mesh")
    p.add_argument("--export", dest="exports", action="append", default=[], help="name=path[:ro|rw]")
    p.add_argument(
        "--import",
        dest="imports",
        action="append",
        default=[],
        help="source_host:source_export=mount_path[:ro|rw]",
    )
    p.add_argument("--capability-token", default="", help="raw token; if omitted token file is used/generated")
    p.add_argument("--token-file", type=Path, default=DEFAULT_TOKEN_FILE)
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    p.add_argument("--registry-file", type=Path, default=DEFAULT_REGISTRY_FILE)
    p.add_argument("--pid-file", type=Path, default=DEFAULT_PID_FILE)
    p.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    p.add_argument("--heartbeat-interval-s", type=float, default=2.0)
    p.add_argument("--startup-timeout-s", type=float, default=3.0)
    p.add_argument("--shutdown-timeout-s", type=float, default=3.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("command", choices=["start", "serve", "stop", "status", "sync-once", "list-registry"])
    return p


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
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except Exception:
        os.kill(pid, signal.SIGKILL)


def _cmd_start(args: argparse.Namespace) -> int:
    exports = _parse_export_specs(list(args.exports))
    imports = _parse_import_specs(list(args.imports))
    host_id = str(args.host_id).strip()
    if not host_id:
        raise ValueError("host-id cannot be empty")

    existing = _read_pid(Path(args.pid_file))
    if existing and _is_pid_alive(existing):
        print(
            json.dumps(
                {
                    "ok": True,
                    "status": "already_running",
                    "host_id": host_id,
                    "pid": int(existing),
                    "pid_file": str(args.pid_file),
                },
                indent=2,
            )
        )
        return 0

    token_file = Path(args.token_file)
    token = _resolve_token(explicit_token=str(args.capability_token), token_file=token_file)
    token_hash = _token_sha256(token)

    payload = {
        "ok": True,
        "status": "dry_run" if bool(args.dry_run) else "starting",
        "host_id": host_id,
        "node_endpoint": str(args.node_endpoint),
        "exports": exports,
        "imports": imports,
        "token_sha256": token_hash,
        "state_file": str(args.state_file),
        "registry_file": str(args.registry_file),
        "pid_file": str(args.pid_file),
        "log_file": str(args.log_file),
    }
    if bool(args.dry_run):
        print(json.dumps(payload, indent=2))
        return 0

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--host-id",
        host_id,
        "--node-endpoint",
        str(args.node_endpoint),
        "--namespace-root",
        str(args.namespace_root),
        "--token-file",
        str(args.token_file),
        "--state-file",
        str(args.state_file),
        "--registry-file",
        str(args.registry_file),
        "--pid-file",
        str(args.pid_file),
        "--log-file",
        str(args.log_file),
        "--heartbeat-interval-s",
        str(float(args.heartbeat_interval_s)),
        "serve",
    ]
    for ex in list(args.exports):
        cmd += ["--export", str(ex)]
    for im in list(args.imports):
        cmd += ["--import", str(im)]
    if str(args.capability_token).strip():
        cmd += ["--capability-token", str(args.capability_token)]

    log_file = Path(args.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as logh:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=logh,
            stderr=subprocess.STDOUT,
            text=False,
            **_session_spawn_kwargs(),
        )
    _write_pid(Path(args.pid_file), int(proc.pid))

    deadline = time.time() + max(0.5, float(args.startup_timeout_s))
    started = False
    while time.time() < deadline:
        if _is_pid_alive(int(proc.pid)):
            state = _json_read(Path(args.state_file))
            if str(state.get("status", "")) == "running":
                started = True
                break
        time.sleep(0.1)

    if not started:
        try:
            _terminate_pid(int(proc.pid))
        except Exception:
            pass
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "agent_not_ready",
                    "host_id": host_id,
                    "pid": int(proc.pid),
                },
                indent=2,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "ok": True,
                "status": "started",
                "host_id": host_id,
                "pid": int(proc.pid),
                "state_file": str(args.state_file),
                "registry_file": str(args.registry_file),
            },
            indent=2,
        )
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    host_id = str(args.host_id).strip()
    if not host_id:
        raise ValueError("host-id cannot be empty")
    exports = _parse_export_specs(list(args.exports))
    imports = _parse_import_specs(list(args.imports))
    token = _resolve_token(explicit_token=str(args.capability_token), token_file=Path(args.token_file))
    token_hash = _token_sha256(token)

    running = True

    def _sig_handler(signum, frame):  # type: ignore[no-untyped-def]
        del signum, frame
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    pid = int(os.getpid())
    _write_pid(Path(args.pid_file), pid)
    interval = max(0.2, float(args.heartbeat_interval_s))

    while running:
        heartbeat = _now_unix()
        state = _build_state(
            host_id=host_id,
            pid=pid,
            node_endpoint=str(args.node_endpoint),
            state_file=Path(args.state_file),
            registry_file=Path(args.registry_file),
            token_file=Path(args.token_file),
            token_sha256=token_hash,
            exports=exports,
            imports=imports,
            heartbeat_unix=heartbeat,
            status="running",
            namespace_root=str(args.namespace_root),
        )
        _json_write(Path(args.state_file), state)
        _sync_registry(
            registry_file=Path(args.registry_file),
            host_id=host_id,
            node_endpoint=str(args.node_endpoint),
            token_sha256=token_hash,
            exports=exports,
            imports=imports,
            heartbeat_unix=heartbeat,
            namespace_root=str(args.namespace_root),
            status="online",
        )
        time.sleep(interval)

    stop_ts = _now_unix()
    state = _build_state(
        host_id=host_id,
        pid=pid,
        node_endpoint=str(args.node_endpoint),
        state_file=Path(args.state_file),
        registry_file=Path(args.registry_file),
        token_file=Path(args.token_file),
        token_sha256=token_hash,
        exports=exports,
        imports=imports,
        heartbeat_unix=stop_ts,
        status="stopped",
        namespace_root=str(args.namespace_root),
    )
    state["ok"] = False
    _json_write(Path(args.state_file), state)
    _sync_registry(
        registry_file=Path(args.registry_file),
        host_id=host_id,
        node_endpoint=str(args.node_endpoint),
        token_sha256=token_hash,
        exports=exports,
        imports=imports,
        heartbeat_unix=stop_ts,
        namespace_root=str(args.namespace_root),
        status="offline",
    )
    Path(args.pid_file).unlink(missing_ok=True)
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    pid_file = Path(args.pid_file)
    pid = _read_pid(pid_file)
    if not pid:
        print(json.dumps({"ok": True, "status": "already_stopped", "pid": 0}, indent=2))
        return 0
    if not _is_pid_alive(pid):
        pid_file.unlink(missing_ok=True)
        print(json.dumps({"ok": True, "status": "already_stopped", "pid": int(pid)}, indent=2))
        return 0

    _terminate_pid(pid)
    deadline = time.time() + max(0.5, float(args.shutdown_timeout_s))
    while time.time() < deadline:
        if not _is_pid_alive(pid):
            break
        time.sleep(0.1)
    if _is_pid_alive(pid):
        _force_kill_pid(pid)
    pid_file.unlink(missing_ok=True)

    state = _json_read(Path(args.state_file))
    if state:
        state["ok"] = False
        state["status"] = "stopped"
        state["heartbeat_unix"] = _now_unix()
        _json_write(Path(args.state_file), state)
        host_id = str(state.get("host_id", "")).strip()
        if host_id:
            reg = _load_registry(Path(args.registry_file))
            hosts = reg.get("hosts", {})
            if isinstance(hosts, dict) and host_id in hosts and isinstance(hosts[host_id], dict):
                hosts[host_id]["status"] = "offline"
                hosts[host_id]["last_heartbeat_unix"] = _now_unix()
                reg["hosts"] = hosts
                _save_registry(Path(args.registry_file), reg)

    print(json.dumps({"ok": True, "status": "stopped", "pid": int(pid)}, indent=2))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    pid = _read_pid(Path(args.pid_file)) or 0
    alive = _is_pid_alive(int(pid))
    state = _json_read(Path(args.state_file))
    host_id = str(state.get("host_id", args.host_id))
    status = "running" if alive else "degraded"
    payload = {
        "ok": bool(alive),
        "status": status,
        "host_id": host_id,
        "pid": int(pid),
        "pid_alive": bool(alive),
        "state_file": str(args.state_file),
        "registry_file": str(args.registry_file),
    }
    if state:
        payload["state"] = state
    print(json.dumps(payload, indent=2))
    return 0 if alive else 1


def _cmd_sync_once(args: argparse.Namespace) -> int:
    host_id = str(args.host_id).strip()
    if not host_id:
        raise ValueError("host-id cannot be empty")
    exports = _parse_export_specs(list(args.exports))
    imports = _parse_import_specs(list(args.imports))
    token = _resolve_token(explicit_token=str(args.capability_token), token_file=Path(args.token_file))
    token_hash = _token_sha256(token)
    ts = _now_unix()
    state = _build_state(
        host_id=host_id,
        pid=int(os.getpid()),
        node_endpoint=str(args.node_endpoint),
        state_file=Path(args.state_file),
        registry_file=Path(args.registry_file),
        token_file=Path(args.token_file),
        token_sha256=token_hash,
        exports=exports,
        imports=imports,
        heartbeat_unix=ts,
        status="running",
        namespace_root=str(args.namespace_root),
    )
    _json_write(Path(args.state_file), state)
    reg = _sync_registry(
        registry_file=Path(args.registry_file),
        host_id=host_id,
        node_endpoint=str(args.node_endpoint),
        token_sha256=token_hash,
        exports=exports,
        imports=imports,
        heartbeat_unix=ts,
        namespace_root=str(args.namespace_root),
        status="online",
    )
    print(
        json.dumps(
            {
                "ok": True,
                "status": "synced",
                "host_id": host_id,
                "state_file": str(args.state_file),
                "registry_file": str(args.registry_file),
                "registry_hosts": sorted(list((reg.get("hosts") or {}).keys())),
            },
            indent=2,
        )
    )
    return 0


def _cmd_list_registry(args: argparse.Namespace) -> int:
    reg = _load_registry(Path(args.registry_file))
    hosts = reg.get("hosts", {})
    payload = {
        "ok": True,
        "schema_version": REGISTRY_SCHEMA,
        "registry_file": str(args.registry_file),
        "host_count": int(len(hosts) if isinstance(hosts, dict) else 0),
        "hosts": hosts if isinstance(hosts, dict) else {},
    }
    print(json.dumps(payload, indent=2))
    return 0


def main() -> int:
    args = _build_parser().parse_args()
    cmd = str(args.command)
    if cmd == "start":
        return _cmd_start(args)
    if cmd == "serve":
        return _cmd_serve(args)
    if cmd == "stop":
        return _cmd_stop(args)
    if cmd == "status":
        return _cmd_status(args)
    if cmd == "sync-once":
        return _cmd_sync_once(args)
    return _cmd_list_registry(args)


if __name__ == "__main__":
    raise SystemExit(main())
