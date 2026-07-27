#!/usr/bin/env python3
from __future__ import annotations

"""Run one-shot reverse-SOCKS smoke flow: start -> status -> remote verify -> optional stop."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

try:
    from tools.verification import sshx11_remote_compat as remote_compat
except Exception:  # pragma: no cover - direct script execution path
    import sshx11_remote_compat as remote_compat


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "verification_results" / "stack_audits" / "sshx11_reverse_socks_smoke.json"
DEFAULT_PROFILE_DIR = REPO_ROOT / ".vscode" / "sshx11"


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _ssh_verbosity(value: Any) -> int:
    return max(0, min(3, int(_as_int(value, 0))))


def _resolve_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def _run_json(argv: list[str], *, timeout_s: float) -> dict[str, Any]:
    started = time.time()
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=max(float(timeout_s), 1.0),
    )  # noqa: S603
    elapsed = time.time() - started
    parsed: dict[str, Any] = {}
    raw = str(proc.stdout or "").strip()
    if raw:
        # Keep last JSON object if there is additional noise.
        probe = raw
        if "\n{" in raw:
            probe = "{" + raw.rsplit("\n{", 1)[1]
        try:
            maybe = json.loads(probe)
            if isinstance(maybe, dict):
                parsed = maybe
        except Exception:
            parsed = {}
    return {
        "ok": bool(proc.returncode == 0),
        "returncode": int(proc.returncode),
        "elapsed_s": round(elapsed, 3),
        "argv": argv,
        "stdout_excerpt": raw[-1000:],
        "stderr_excerpt": str(proc.stderr or "")[-500:],
        "json": parsed,
    }


def run_smoke(args: argparse.Namespace) -> dict[str, Any]:
    host = str(args.host or "").strip()
    if not host:
        raise RuntimeError("missing_host")

    py = sys.executable
    reverse_service = str(_resolve_path("tools/verification/sshx11_reverse_socks_service.py"))
    profile_verify = str(_resolve_path("tools/verification/verify_sshx11_extension_host_paths.py"))

    common_reverse = [
        py,
        reverse_service,
        "--host",
        host,
        "--user",
        str(args.user),
        "--port",
        str(int(args.port)),
        "--remote-bind-host",
        str(args.reverse_socks_host),
        "--remote-socks-port",
        str(int(args.reverse_socks_port)),
    ]
    if str(args.ssh_bin or "").strip():
        common_reverse.extend(["--ssh-bin", str(args.ssh_bin)])
    if str(args.agent_mode or "").strip():
        common_reverse.extend(["--agent-mode", str(args.agent_mode)])
    if bool(args.forward_agent):
        common_reverse.append("--forward-agent")
    if str(args.identity_agent or "").strip():
        common_reverse.extend(["--identity-agent", str(args.identity_agent)])
    if str(args.identity_file or "").strip():
        common_reverse.extend(["--identity-file", str(args.identity_file)])
    if str(args.remote_platform or "").strip():
        common_reverse.extend(["--remote-platform", str(args.remote_platform)])
    if str(args.remote_shell_bin or "").strip():
        common_reverse.extend(["--remote-shell-bin", str(args.remote_shell_bin)])
    if bool(args.remote_shell_login):
        common_reverse.append("--remote-shell-login")
    else:
        common_reverse.append("--no-remote-shell-login")
    if str(args.remote_python_bin or "").strip():
        common_reverse.extend(["--remote-python-bin", str(args.remote_python_bin)])
    if str(args.ssh_config or "").strip():
        common_reverse.extend(["--ssh-config", str(args.ssh_config)])
    if str(args.proxy_jump or "").strip():
        common_reverse.extend(["--proxy-jump", str(args.proxy_jump)])
    if str(args.proxy_command or "").strip():
        common_reverse.extend(["--proxy-command", str(args.proxy_command)])
    if _ssh_verbosity(args.ssh_verbosity) > 0:
        common_reverse.extend(["--ssh-verbosity", str(_ssh_verbosity(args.ssh_verbosity))])
    if str(args.ssh_log_level or "").strip():
        common_reverse.extend(["--ssh-log-level", str(args.ssh_log_level)])
    if str(args.ssh_log_file or "").strip():
        common_reverse.extend(["--ssh-log-file", str(args.ssh_log_file)])
    if bool(args.insecure_hostkey):
        common_reverse.append("--insecure-hostkey")

    out: dict[str, Any] = {
        "ok": False,
        "checked_at_unix": int(time.time()),
        "host": host,
        "user": str(args.user),
        "port": int(args.port),
        "ssh_bin": str(args.ssh_bin),
        "agent_mode": str(args.agent_mode),
        "forward_agent": bool(args.forward_agent),
        "identity_agent": str(args.identity_agent or ""),
        "remote_platform": str(args.remote_platform),
        "remote_shell_bin": str(args.remote_shell_bin),
        "remote_shell_login": bool(args.remote_shell_login),
        "remote_python_bin": str(args.remote_python_bin or ""),
        "reverse_socks_host": str(args.reverse_socks_host),
        "reverse_socks_port": int(args.reverse_socks_port),
        "ssh_config": str(args.ssh_config or ""),
        "proxy_jump": str(args.proxy_jump or ""),
        "proxy_command": str(args.proxy_command or ""),
        "ssh_verbosity": int(_ssh_verbosity(args.ssh_verbosity)),
        "ssh_log_level": str(args.ssh_log_level or ""),
        "ssh_log_file": str(args.ssh_log_file or ""),
        "steps": {},
    }

    started = False
    try:
        out["steps"]["start"] = _run_json(common_reverse + ["start"], timeout_s=float(args.timeout_s))
        started = bool(out["steps"]["start"]["ok"])
        if not started:
            raise RuntimeError("reverse_socks_start_failed")

        out["steps"]["status"] = _run_json(common_reverse + ["status"], timeout_s=float(args.timeout_s))
        if not bool(out["steps"]["status"]["ok"]):
            raise RuntimeError("reverse_socks_status_failed")

        verify_cmd = [
            py,
            profile_verify,
            "--profile-dir",
            str(_resolve_path(args.profile_dir)),
            "--reverse-socks-host",
            str(args.reverse_socks_host),
            "--reverse-socks-port",
            str(int(args.reverse_socks_port)),
            "--remote-host",
            host,
            "--remote-user",
            str(args.user),
            "--remote-port",
            str(int(args.port)),
            "--ssh-bin",
            str(args.ssh_bin),
            "--agent-mode",
            str(args.agent_mode),
            "--require-remote",
            "--timeout-s",
            str(float(args.timeout_s)),
        ]
        if bool(args.forward_agent):
            verify_cmd.append("--forward-agent")
        if str(args.identity_agent or "").strip():
            verify_cmd.extend(["--identity-agent", str(args.identity_agent)])
        if str(args.remote_platform or "").strip():
            verify_cmd.extend(["--remote-platform", str(args.remote_platform)])
        if str(args.remote_shell_bin or "").strip():
            verify_cmd.extend(["--remote-shell-bin", str(args.remote_shell_bin)])
        if bool(args.remote_shell_login):
            verify_cmd.append("--remote-shell-login")
        else:
            verify_cmd.append("--no-remote-shell-login")
        if str(args.remote_python_bin or "").strip():
            verify_cmd.extend(["--remote-python-bin", str(args.remote_python_bin)])
        if bool(args.generate_profiles):
            verify_cmd.append("--generate-profiles")
        else:
            verify_cmd.append("--no-generate-profiles")
        if bool(args.write_mcp):
            verify_cmd.append("--write-mcp")
        if str(args.identity_file or "").strip():
            verify_cmd.extend(["--identity-file", str(args.identity_file)])
        if str(args.ssh_config or "").strip():
            verify_cmd.extend(["--ssh-config", str(args.ssh_config)])
        if str(args.proxy_jump or "").strip():
            verify_cmd.extend(["--proxy-jump", str(args.proxy_jump)])
        if str(args.proxy_command or "").strip():
            verify_cmd.extend(["--proxy-command", str(args.proxy_command)])
        if _ssh_verbosity(args.ssh_verbosity) > 0:
            verify_cmd.extend(["--ssh-verbosity", str(_ssh_verbosity(args.ssh_verbosity))])
        if str(args.ssh_log_level or "").strip():
            verify_cmd.extend(["--ssh-log-level", str(args.ssh_log_level)])
        if str(args.ssh_log_file or "").strip():
            verify_cmd.extend(["--ssh-log-file", str(args.ssh_log_file)])
        if bool(args.insecure_hostkey):
            verify_cmd.append("--insecure-hostkey")
        out["steps"]["verify_extension_hosts"] = _run_json(verify_cmd, timeout_s=float(args.timeout_s) + 8.0)
        if not bool(out["steps"]["verify_extension_hosts"]["ok"]):
            raise RuntimeError("reverse_socks_remote_probe_failed")

        out["ok"] = True
        out["status"] = "passed"
        return out
    finally:
        if started and not bool(args.keep_running):
            out["steps"]["stop"] = _run_json(common_reverse + ["stop"], timeout_s=float(args.timeout_s))
        elif started and bool(args.keep_running):
            out["steps"]["stop"] = {"ok": True, "status": "kept_running"}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_HOST", os.environ.get("SSHX11_REMOTE_HOST", "")))
    p.add_argument("--user", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_USER", os.environ.get("SSHX11_REMOTE_USER", "root")))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PORT", os.environ.get("SSHX11_REMOTE_PORT", "22"))))
    p.add_argument("--ssh-bin", default=os.environ.get("SSH_BIN", "ssh"))
    p.add_argument("--agent-mode", choices=["auto", "require", "disable"], default=os.environ.get("SSHX11_REVERSE_SOCKS_AGENT_MODE", os.environ.get("SSHX11_AGENT_MODE", "auto")))
    p.add_argument("--forward-agent", action="store_true", default=str(os.environ.get("SSHX11_REVERSE_SOCKS_FORWARD_AGENT", os.environ.get("SSHX11_FORWARD_AGENT", "0"))).lower() in {"1", "true", "yes", "on"})
    p.add_argument("--identity-agent", default=os.environ.get("SSHX11_REVERSE_SOCKS_IDENTITY_AGENT", os.environ.get("SSHX11_IDENTITY_AGENT", os.environ.get("SSHX11_AGENT_SOCKET", os.environ.get("SSH_AUTH_SOCK", "")))))
    p.add_argument("--identity-file", default=os.environ.get("SSHX11_REVERSE_SOCKS_IDENTITY_FILE", os.environ.get("SSHX11_REMOTE_IDENTITY_FILE", "")))
    p.add_argument(
        "--remote-platform",
        choices=list(remote_compat.SUPPORTED_REMOTE_PLATFORMS),
        default=remote_compat.normalize_remote_platform(
            os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PLATFORM", os.environ.get("SSHX11_REMOTE_PLATFORM", "auto"))
        ),
    )
    p.add_argument("--remote-shell-bin", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_SHELL_BIN", os.environ.get("SSHX11_REMOTE_SHELL_BIN", "sh")))
    p.add_argument("--remote-shell-login", action="store_true", default=str(os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_SHELL_LOGIN", os.environ.get("SSHX11_REMOTE_SHELL_LOGIN", "1"))).lower() in {"1", "true", "yes", "on"})
    p.add_argument("--no-remote-shell-login", dest="remote_shell_login", action="store_false")
    p.add_argument("--remote-python-bin", default=os.environ.get("SSHX11_REVERSE_SOCKS_REMOTE_PYTHON_BIN", os.environ.get("SSHX11_REMOTE_PYTHON_BIN", "")))
    p.add_argument("--ssh-config", default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_CONFIG", os.environ.get("SSHX11_SSH_CONFIG", "")))
    p.add_argument("--proxy-jump", default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_JUMP", os.environ.get("SSHX11_PROXY_JUMP", "")))
    p.add_argument("--proxy-command", default=os.environ.get("SSHX11_REVERSE_SOCKS_PROXY_COMMAND", os.environ.get("SSHX11_PROXY_COMMAND", "")))
    p.add_argument(
        "--ssh-verbosity",
        type=int,
        default=_as_int(os.environ.get("SSHX11_REVERSE_SOCKS_SSH_VERBOSITY", os.environ.get("SSHX11_SSH_VERBOSITY", "0")), 0),
    )
    p.add_argument("--ssh-log-level", default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_LEVEL", os.environ.get("SSHX11_SSH_LOG_LEVEL", "")))
    p.add_argument("--ssh-log-file", default=os.environ.get("SSHX11_REVERSE_SOCKS_SSH_LOG_FILE", os.environ.get("SSHX11_SSH_LOG_FILE", "")))
    p.add_argument("--insecure-hostkey", action="store_true", default=False)
    p.add_argument("--reverse-socks-host", default="127.0.0.1")
    p.add_argument("--reverse-socks-port", type=int, default=19080)
    p.add_argument("--profile-dir", type=Path, default=DEFAULT_PROFILE_DIR)
    p.add_argument("--generate-profiles", action="store_true", default=True)
    p.add_argument("--no-generate-profiles", action="store_false", dest="generate_profiles")
    p.add_argument("--write-mcp", action="store_true", default=False)
    p.add_argument("--keep-running", action="store_true", default=False)
    p.add_argument("--timeout-s", type=float, default=5.0)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    payload: dict[str, Any]
    rc = 0
    try:
        payload = run_smoke(args)
    except Exception as exc:
        payload = {
            "ok": False,
            "checked_at_unix": int(time.time()),
            "error": str(exc),
        }
        rc = 2

    output = _resolve_path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[artifact] {output}")
    return 0 if bool(payload.get("ok")) else rc


if __name__ == "__main__":
    raise SystemExit(main())
