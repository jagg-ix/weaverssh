#!/usr/bin/env python3
from __future__ import annotations

"""Dependency preflight for SSHX11 WebDAV/SOCKS/backhaul workflows."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_X11WS_REPO = Path(os.environ.get("SSHX11_X11WS_REPO", str(Path.home() / "weaverssh")))
REQUIRED_X11WS_FILES = (
    "cmd/wv-agent/main.go",
    "internal/app/x11_server_fsm.go",
    "internal/app/x11_protocol_types.go",
    "cmd/wv-socks/main.go",
    "go.mod",
)


def _which(name: str) -> str:
    path = shutil.which(name)
    return str(path or "")


def _bool_text(value: bool) -> str:
    return "yes" if bool(value) else "no"


def _probe_bind(host: str, port: int) -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((str(host), int(port)))
        return {"ok": True, "reason": "bind_ok"}
    except OSError as exc:
        return {"ok": False, "reason": f"bind_failed:{exc}"}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _find_fallback_port(host: str, start_port: int, max_attempts: int = 20) -> int:
    for offset in range(1, max(1, int(max_attempts)) + 1):
        probe = _probe_bind(host, int(start_port) + offset)
        if bool(probe.get("ok")):
            return int(start_port) + offset
    return 0


def _build_ssh_probe_cmd(args: argparse.Namespace) -> list[str]:
    cmd = [
        "ssh",
        "-p",
        str(int(args.port)),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
    ]
    if str(args.identity_file).strip():
        cmd.extend(["-i", str(args.identity_file)])
    if bool(args.insecure_hostkey):
        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
    else:
        cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
    script = (
        "if command -v python3 >/dev/null 2>&1; then echo python3=1; else echo python3=0; fi; "
        "if command -v ip >/dev/null 2>&1; then echo ip=1; else echo ip=0; fi; "
        "if command -v sh >/dev/null 2>&1; then echo sh=1; else echo sh=0; fi; "
        "if command -v scp >/dev/null 2>&1; then echo scp=1; else echo scp=0; fi; "
        "if command -v id >/dev/null 2>&1; then echo uid=$(id -u); else echo uid=; fi"
    )
    target = f"{args.user}@{args.host}" if str(args.user).strip() else str(args.host)
    cmd.extend([target, "sh", "-lc", script])
    return cmd


def _parse_kv_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _remote_probe(args: argparse.Namespace) -> dict[str, Any]:
    host = str(args.host).strip()
    if not host:
        return {"ok": None, "status": "skipped", "reason": "remote_host_not_set"}
    cmd = _build_ssh_probe_cmd(args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(6.0, float(args.timeout_s)),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": "failed", "reason": "ssh_probe_timeout", "cmd": cmd}
    except Exception as exc:
        return {"ok": False, "status": "failed", "reason": f"ssh_probe_error:{exc}", "cmd": cmd}

    kv = _parse_kv_lines(proc.stdout)
    uid_text = str(kv.get("uid", "")).strip()
    is_root = uid_text == "0"
    payload = {
        "ok": bool(proc.returncode == 0),
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": int(proc.returncode),
        "python3": str(kv.get("python3", "0")) == "1",
        "ip": str(kv.get("ip", "0")) == "1",
        "sh": str(kv.get("sh", "0")) == "1",
        "scp": str(kv.get("scp", "0")) == "1",
        "uid": uid_text,
        "is_root": bool(is_root),
        "stderr_excerpt": str(proc.stderr or "")[-400:],
    }
    return payload


def _x11ws_repo_state(path: Path) -> dict[str, Any]:
    root = Path(path).expanduser().resolve()
    missing = [name for name in REQUIRED_X11WS_FILES if not (root / name).exists()]
    return {
        "path": str(root),
        "exists": bool(root.exists()),
        "missing_files": missing,
        "ready": bool(root.exists() and not missing),
    }


def run_check(args: argparse.Namespace) -> dict[str, Any]:
    local_bins = {
        "python3": _which("python3"),
        "ssh": _which("ssh"),
        "scp": _which("scp"),
        "ip": _which("ip"),
        "ifconfig": _which("ifconfig"),
        "go": _which("go"),
        "lsof": _which("lsof"),
        "curl": _which("curl"),
    }
    local_has = {name: bool(path) for name, path in local_bins.items()}
    webdav_probe = _probe_bind(str(args.webdav_host), int(args.webdav_port))
    fallback_port = 0 if bool(webdav_probe.get("ok")) else _find_fallback_port(str(args.webdav_host), int(args.webdav_port))
    remote = _remote_probe(args)
    weaverssh = _x11ws_repo_state(Path(args.weaverssh_repo))

    scenario1_webdav_ready = bool(local_has["python3"] and webdav_probe.get("ok"))
    scenario1_webdav_fallback = bool(local_has["python3"] and not webdav_probe.get("ok") and fallback_port > 0)

    scenario3_socks_ready = bool(local_has["python3"] and local_has["go"] and bool(weaverssh.get("ready")))

    recommended_transport = "blocked"
    if scenario3_socks_ready:
        recommended_transport = "socks"

    actions: list[str] = []
    if not scenario1_webdav_ready:
        if scenario1_webdav_fallback:
            actions.append(f"webdav: use fallback port {fallback_port}")
        elif not local_has["python3"]:
            actions.append("webdav: install/enable python3")
        else:
            actions.append("webdav: allow local port bind or change host/port policy")

    if str(args.host).strip() and not bool(remote.get("ok")):
        actions.append("remote: fix SSH connectivity/auth to remote host")
    elif str(args.host).strip() and bool(remote.get("ok")) and not bool(remote.get("python3")):
        actions.append("remote: install python3 on remote host for backhaul probes")

    if not scenario3_socks_ready:
        if not local_has["go"]:
            actions.append("socks: install Go toolchain")
        if not bool(weaverssh.get("ready")):
            actions.append("socks: set SSHX11_X11WS_REPO to a valid weaverssh checkout")

    return {
        "ok": True,
        "checked_at_unix": int(time.time()),
        "local": {
            "tools": local_bins,
            "tool_present": local_has,
            "ip_missing_but_ifconfig_present": bool((not local_has["ip"]) and local_has["ifconfig"]),
        },
        "remote": remote,
        "x11ws_repo": weaverssh,
        "scenarios": {
            "scenario_1_webdav": {
                "ready": bool(scenario1_webdav_ready),
                "fallback_available": bool(scenario1_webdav_fallback),
                "host": str(args.webdav_host),
                "port": int(args.webdav_port),
                "bind_probe": webdav_probe,
                "fallback_port": int(fallback_port),
            },
            "scenario_3_socks_fallback": {
                "ready": bool(scenario3_socks_ready),
                "requires": {
                    "python3": bool(local_has["python3"]),
                    "go": bool(local_has["go"]),
                    "x11ws_repo_ready": bool(weaverssh.get("ready")),
                },
            },
        },
        "recommendation": {
            "transport": recommended_transport,
            "actions": actions,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("SSHX11_REMOTE_HOST", ""))
    p.add_argument("--user", default=os.environ.get("SSHX11_REMOTE_USER", "root"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11_REMOTE_PORT", "22")))
    p.add_argument("--identity-file", default=os.environ.get("SSHX11_REMOTE_IDENTITY_FILE", ""))
    p.add_argument("--insecure-hostkey", action="store_true", default=str(os.environ.get("SSHX11_REMOTE_INSECURE_HOSTKEY", "0")).lower() in {"1", "true", "yes", "on"})
    p.add_argument("--webdav-host", default=os.environ.get("SSHX11_WEBDAV_HOST", "127.0.0.1"))
    p.add_argument("--webdav-port", type=int, default=int(os.environ.get("SSHX11_WEBDAV_PORT", "8780")))
    p.add_argument("--weaverssh-repo", type=Path, default=DEFAULT_X11WS_REPO)
    p.add_argument("--timeout-s", type=float, default=6.0)
    p.add_argument("--require-scenario", choices=["scenario_1_webdav", "scenario_3_socks_fallback", "none"], default="none")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    payload = run_check(args)
    print(json.dumps(payload, indent=2, sort_keys=True))

    required = str(args.require_scenario)
    if required != "none":
        ready = bool(((payload.get("scenarios") or {}).get(required) or {}).get("ready"))
        return 0 if ready else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
