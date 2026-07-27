#!/usr/bin/env python3
from __future__ import annotations

"""Verify VS Code extension-host routing profiles (local/remote/reverse-socks)."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any

try:
    from tools.verification import sshx11_remote_compat as remote_compat
except Exception:  # pragma: no cover - script execution path
    import sshx11_remote_compat as remote_compat


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "verification_results" / "stack_audits" / "sshx11_extension_host_paths_smoke.json"
DEFAULT_PROFILE_DIR = REPO_ROOT / ".vscode" / "sshx11"
DEFAULT_PROFILE_GENERATOR = REPO_ROOT / "tools" / "verification" / "generate_sshx11_vscode_profile.py"


def _resolve_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def _port_open(host: str, port: int, timeout_s: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(0.1, float(timeout_s)))
    try:
        sock.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _agent_mode(args: argparse.Namespace) -> str:
    mode = str(getattr(args, "agent_mode", "auto") or "auto").strip().lower()
    if mode in {"auto", "require", "disable"}:
        return mode
    return "auto"


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _ssh_verbosity(args: argparse.Namespace) -> int:
    raw = _as_int(getattr(args, "ssh_verbosity", 0), 0)
    return max(0, min(3, int(raw)))


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


def _parse_env_file(path: Path) -> dict[str, Any]:
    exports: dict[str, str] = {}
    unsets: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            body = line[len("export ") :]
            if "=" not in body:
                continue
            key, value = body.split("=", 1)
            key = key.strip()
            value = value.strip()
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            exports[key] = value
        elif line.startswith("unset "):
            key = line[len("unset ") :].strip()
            if key:
                unsets.append(key)
    return {"exports": exports, "unsets": unsets}


def _proxy_chain_matches(exports: dict[str, str], expected_uri: str) -> bool:
    all_proxy = str(exports.get("ALL_PROXY", "")).strip()
    http_proxy = str(exports.get("HTTP_PROXY", "")).strip()
    https_proxy = str(exports.get("HTTPS_PROXY", "")).strip()
    if all_proxy != expected_uri:
        return False
    ok_http = http_proxy in {expected_uri, "$ALL_PROXY", "${ALL_PROXY}"}
    ok_https = https_proxy in {expected_uri, "$ALL_PROXY", "${ALL_PROXY}"}
    return bool(ok_http and ok_https)


def _ssh_base(args: argparse.Namespace) -> list[str]:
    cmd = [str(args.ssh_bin), "-p", str(int(args.remote_port))]
    ssh_config = str(args.ssh_config or "").strip()
    if ssh_config:
        cmd.extend(["-F", str(_resolve_path(ssh_config))])
    if str(args.identity_file or "").strip():
        cmd.extend(["-i", str(args.identity_file)])
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
    if bool(args.insecure_hostkey):
        cmd.extend(
            [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        )
    cmd.append(f"{args.remote_user}@{args.remote_host}")
    return cmd


def _probe_remote_socks(args: argparse.Namespace) -> dict[str, Any]:
    if not str(args.remote_host).strip():
        return {"ok": None, "status": "skipped", "reason": "remote_host_not_set"}
    if _agent_mode(args) == "require" and not _resolve_identity_agent(args):
        return {
            "ok": False,
            "status": "failed",
            "reason": "agent_required_but_not_available",
            "returncode": 255,
            "stderr_excerpt": "agent_required_but_not_available",
        }
    host = str(args.reverse_socks_host).strip() or "127.0.0.1"
    port = int(args.reverse_socks_port)
    probe = remote_compat.build_tcp_probe_command(
        host=host,
        port=port,
        timeout_s=float(args.timeout_s),
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
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=max(float(args.timeout_s) + 1.0, 3.0),
    )  # noqa: S603
    merged = f"{proc.stdout or ''}\n{proc.stderr or ''}".strip()
    reason = ""
    if remote_compat.probe_tooling_missing(str(proc.stdout or ""), str(proc.stderr or "")):
        reason = "probe_tooling_missing"
    return {
        "ok": bool(proc.returncode == 0),
        "status": "ok" if proc.returncode == 0 else "failed",
        "reason": reason or ("closed_or_unreachable" if proc.returncode != 0 else "open"),
        "returncode": int(proc.returncode),
        "stderr_excerpt": merged[-300:],
    }


def _run_generator(args: argparse.Namespace) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(_resolve_path(args.profile_generator)),
        "--profile",
        "all",
        "--output-dir",
        str(_resolve_path(args.profile_dir)),
        "--local-socks-host",
        str(args.local_socks_host),
        "--local-socks-port",
        str(int(args.local_socks_port)),
        "--reverse-socks-host",
        str(args.reverse_socks_host),
        "--reverse-socks-port",
        str(int(args.reverse_socks_port)),
    ]
    if bool(args.write_mcp):
        cmd.append("--overwrite-mcp")
    else:
        cmd.append("--no-write-mcp")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    parsed: dict[str, Any] = {}
    if proc.stdout.strip():
        try:
            maybe = json.loads(proc.stdout)
            if isinstance(maybe, dict):
                parsed = maybe
        except Exception:
            parsed = {}
    return {
        "ok": bool(proc.returncode == 0),
        "returncode": int(proc.returncode),
        "stdout_excerpt": (proc.stdout or "")[-500:],
        "stderr_excerpt": (proc.stderr or "")[-500:],
        "report": parsed,
    }


def run_verify(args: argparse.Namespace) -> dict[str, Any]:
    profile_dir = _resolve_path(args.profile_dir)
    local_uri = f"socks5h://{args.local_socks_host}:{int(args.local_socks_port)}"
    reverse_uri = f"socks5h://{args.reverse_socks_host}:{int(args.reverse_socks_port)}"

    report: dict[str, Any] = {
        "ok": False,
        "checked_at_unix": int(time.time()),
        "profile_dir": str(profile_dir),
        "checks": {},
    }
    mode = _agent_mode(args)
    identity_agent = _resolve_identity_agent(args)
    report["checks"]["agent_transport"] = {
        "mode": mode,
        "forward_agent": bool(args.forward_agent),
        "identity_agent": identity_agent,
        "ssh_verbosity": int(_ssh_verbosity(args)),
        "ssh_log_level": str(args.ssh_log_level or ""),
        "ssh_log_file": str(args.ssh_log_file or ""),
    }
    report["checks"]["remote_runtime_profile"] = {
        "platform": str(args.remote_platform),
        "shell_bin": str(args.remote_shell_bin),
        "shell_login": bool(args.remote_shell_login),
        "python_bin": str(args.remote_python_bin or ""),
    }
    if mode == "require" and not identity_agent:
        raise RuntimeError("agent_required_but_not_available")

    if bool(args.generate_profiles):
        report["checks"]["profile_generate"] = _run_generator(args)
        if not report["checks"]["profile_generate"]["ok"]:
            raise RuntimeError("profile_generator_failed")

    profile_paths = {
        "local": profile_dir / "local.env.sh",
        "remote": profile_dir / "remote.env.sh",
        "reverse-socks": profile_dir / "reverse-socks.env.sh",
    }
    missing = [name for name, path in profile_paths.items() if not path.exists()]
    report["checks"]["profile_files"] = {"ok": not bool(missing), "missing": missing}
    if missing:
        raise RuntimeError(f"missing_profile_files:{','.join(missing)}")

    parsed_profiles = {name: _parse_env_file(path) for name, path in profile_paths.items()}
    report["checks"]["parsed_profiles"] = parsed_profiles

    local_exports = parsed_profiles["local"]["exports"]
    local_ok = _proxy_chain_matches(local_exports, local_uri)
    local_ok = local_ok and ("NO_PROXY" in local_exports)
    report["checks"]["local_profile_shape"] = {"ok": bool(local_ok), "expected_proxy": local_uri}
    if not local_ok:
        raise RuntimeError("invalid_local_profile")

    remote_profile = parsed_profiles["remote"]
    remote_unsets = set(str(x) for x in remote_profile["unsets"])
    remote_ok = {"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"}.issubset(remote_unsets)
    remote_ok = remote_ok and ("NO_PROXY" in remote_profile["exports"])
    report["checks"]["remote_profile_shape"] = {"ok": bool(remote_ok), "required_unset": sorted(remote_unsets)}
    if not remote_ok:
        raise RuntimeError("invalid_remote_profile")

    reverse_exports = parsed_profiles["reverse-socks"]["exports"]
    reverse_ok = _proxy_chain_matches(reverse_exports, reverse_uri)
    reverse_ok = reverse_ok and ("NO_PROXY" in reverse_exports)
    report["checks"]["reverse_profile_shape"] = {"ok": bool(reverse_ok), "expected_proxy": reverse_uri}
    if not reverse_ok:
        raise RuntimeError("invalid_reverse_profile")

    local_live = _port_open(str(args.local_socks_host), int(args.local_socks_port), float(args.timeout_s))
    report["checks"]["local_socks_live"] = {
        "ok": bool(local_live),
        "required": bool(args.require_live_local_socks),
        "host": str(args.local_socks_host),
        "port": int(args.local_socks_port),
    }
    if bool(args.require_live_local_socks) and not local_live:
        raise RuntimeError("local_socks_not_reachable")

    remote_probe = _probe_remote_socks(args)
    report["checks"]["reverse_remote_probe"] = remote_probe
    if bool(args.require_remote) and remote_probe.get("status") == "skipped":
        raise RuntimeError("remote_probe_required_but_not_configured")
    if str(args.remote_host).strip() and not bool(remote_probe.get("ok")):
        raise RuntimeError("reverse_socks_remote_probe_failed")

    report["ok"] = True
    return report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile-dir", type=Path, default=DEFAULT_PROFILE_DIR)
    p.add_argument("--profile-generator", type=Path, default=DEFAULT_PROFILE_GENERATOR)
    p.add_argument("--generate-profiles", action="store_true", default=True)
    p.add_argument("--no-generate-profiles", action="store_false", dest="generate_profiles")
    p.add_argument("--write-mcp", action="store_true", default=False, help="Overwrite .vscode/mcp.json while generating profiles.")
    p.add_argument("--local-socks-host", default="127.0.0.1")
    p.add_argument("--local-socks-port", type=int, default=1080)
    p.add_argument("--reverse-socks-host", default="127.0.0.1")
    p.add_argument("--reverse-socks-port", type=int, default=19080)
    p.add_argument("--remote-host", default="")
    p.add_argument("--remote-user", default="root")
    p.add_argument("--remote-port", type=int, default=22)
    p.add_argument(
        "--remote-platform",
        choices=list(remote_compat.SUPPORTED_REMOTE_PLATFORMS),
        default=remote_compat.normalize_remote_platform(
            os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PLATFORM", os.environ.get("SSHX11_REMOTE_PLATFORM", "auto"))
        ),
    )
    p.add_argument(
        "--remote-shell-bin",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_SHELL_BIN", os.environ.get("SSHX11_REMOTE_SHELL_BIN", "sh")),
    )
    p.add_argument(
        "--remote-shell-login",
        action="store_true",
        default=str(
            os.environ.get(
                "SSHX11_REVERSE_SOCKS_REMOTE_SHELL_LOGIN",
                os.environ.get("SSHX11_REMOTE_SHELL_LOGIN", "1"),
            )
        ).lower()
        in {"1", "true", "yes", "on"},
    )
    p.add_argument("--no-remote-shell-login", dest="remote_shell_login", action="store_false")
    p.add_argument(
        "--remote-python-bin",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PYTHON_BIN", os.environ.get("SSHX11_REMOTE_PYTHON_BIN", "")),
    )
    p.add_argument("--ssh-bin", default=os.environ.get("SSH_BIN", "ssh"))
    p.add_argument("--agent-mode", choices=["auto", "require", "disable"], default=os.environ.get("SSHX11_REVERSE_SOCKS_AGENT_MODE", os.environ.get("SSHX11_AGENT_MODE", "auto")))
    p.add_argument("--forward-agent", action="store_true", default=str(os.environ.get("SSHX11_REVERSE_SOCKS_FORWARD_AGENT", os.environ.get("SSHX11_FORWARD_AGENT", "0"))).lower() in {"1", "true", "yes", "on"})
    p.add_argument("--identity-agent", default=os.environ.get("SSHX11_REVERSE_SOCKS_IDENTITY_AGENT", os.environ.get("SSHX11_IDENTITY_AGENT", os.environ.get("SSHX11_AGENT_SOCKET", os.environ.get("SSH_AUTH_SOCK", "")))))
    p.add_argument("--ssh-config", default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_CONFIG", os.environ.get("SSHX11_SSH_CONFIG", "")))
    p.add_argument("--proxy-jump", default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_JUMP", os.environ.get("SSHX11_PROXY_JUMP", "")))
    p.add_argument("--proxy-command", default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_COMMAND", os.environ.get("SSHX11_PROXY_COMMAND", "")))
    p.add_argument(
        "--ssh-verbosity",
        type=int,
        default=_as_int(os.environ.get("SSHX11_REVERSE_SOCKS_SSH_VERBOSITY", os.environ.get("SSHX11_SSH_VERBOSITY", "0")), 0),
    )
    p.add_argument(
        "--ssh-log-level",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_LEVEL", os.environ.get("SSHX11_SSH_LOG_LEVEL", "")),
    )
    p.add_argument(
        "--ssh-log-file",
        default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_FILE", os.environ.get("SSHX11_SSH_LOG_FILE", "")),
    )
    p.add_argument("--identity-file", default="")
    p.add_argument("--insecure-hostkey", action="store_true", default=False)
    p.add_argument("--require-remote", action="store_true", default=False)
    p.add_argument("--require-live-local-socks", action="store_true", default=False)
    p.add_argument("--timeout-s", type=float, default=2.0)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    payload: dict[str, Any]
    rc = 0
    try:
        payload = run_verify(args)
    except Exception as exc:
        payload = {
            "ok": False,
            "checked_at_unix": int(time.time()),
            "error": str(exc),
        }
        rc = 2

    out_path = _resolve_path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[artifact] {out_path}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
