#!/usr/bin/env python3
from __future__ import annotations

"""Install/render per-user sshx11d service launch config (macOS/Linux/Windows)."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
from typing import Any
from xml.sax.saxutils import escape as xml_escape


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11d


DEFAULT_LABEL = "local.sshx11d"
DEFAULT_DAEMON_SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11d.py"
DEFAULT_CONTRACT_FILE = REPO_ROOT / "extensions" / "vscode-sshx11" / "data" / "api-contract.v1.json"


def _resolve_path(raw: str | Path, *, base: Path) -> Path:
    p = Path(str(raw)).expanduser()
    if p.is_absolute():
        return p
    return (base / p).resolve()


def _detect_platform(raw: str) -> str:
    value = str(raw or "auto").strip().lower().replace("_", "-").replace(" ", "-")
    if value in {"mac", "macos", "darwin", "osx"}:
        return "macos"
    if value in {"linux", "linux-generic", "generic-linux"}:
        return "linux"
    if value in {"linux-headless", "headless-linux", "linux-without-gui", "linux-no-gui", "linux-iot", "linux-embedded", "embedded", "iot"}:
        return "linux-headless"
    if value in {"linux-gui", "linux-desktop", "gnome", "kde"}:
        return "linux-gui"
    if value in {"freebsd", "freebsd-generic"}:
        return "freebsd"
    if value in {"freebsd-gui", "freebsd-desktop"}:
        return "freebsd-gui"
    if value in {"openbsd"}:
        return "openbsd"
    if value in {"win", "windows"}:
        return "windows"
    if value != "auto":
        return "linux"

    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("freebsd"):
        return "freebsd"
    if sys.platform.startswith("openbsd"):
        return "openbsd"
    if os.name.lower() == "nt":
        return "windows"
    return "linux"


def _shell_join(argv: list[str]) -> str:
    try:
        return shlex.join(argv)
    except Exception:
        return " ".join(shlex.quote(part) for part in argv)


def _write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=check)


def _build_daemon_argv(args: argparse.Namespace, *, repo_root: Path, state_dir: Path) -> list[str]:
    daemon_script = _resolve_path(args.daemon_script, base=repo_root)
    contract_file = _resolve_path(args.contract_file, base=repo_root)
    argv = [
        str(Path(str(args.python_bin)).expanduser()),
        str(daemon_script),
        "serve",
        "--host",
        str(args.host),
        "--port",
        str(int(args.port)),
        "--repo-root",
        str(repo_root),
        "--state-dir",
        str(state_dir),
        "--contract-file",
        str(contract_file),
        "--timeout-s",
        str(float(args.timeout_s)),
        "--events-max",
        str(int(args.events_max)),
    ]
    if bool(args.allow_no_token):
        argv.append("--allow-no-token")
    if bool(args.allow_unsafe_subcommand):
        argv.append("--allow-unsafe-subcommand")
    return argv


def _render_macos_plist(
    *,
    label: str,
    daemon_argv: list[str],
    working_directory: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> str:
    payload = {
        "Label": label,
        "ProgramArguments": daemon_argv,
        "RunAtLoad": True,
        "KeepAlive": True,
        "WorkingDirectory": str(working_directory),
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
        "ProcessType": "Interactive",
    }
    out = plistlib.dumps(payload, fmt=plistlib.FMT_XML)
    return out.decode("utf-8")


def _render_systemd_service(*, label: str, daemon_argv: list[str], working_directory: Path) -> str:
    exec_start = _shell_join(daemon_argv)
    lines = [
        "[Unit]",
        f"Description=SSHX11 user daemon ({label})",
        "After=network.target",
        "",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={working_directory}",
        f"ExecStart={exec_start}",
        "Restart=always",
        "RestartSec=2",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    return "\n".join(lines)


def _service_name(label: str) -> str:
    out = []
    for ch in str(label or "sshx11d"):
        out.append(ch if ch.isalnum() else "_")
    name = "".join(out).strip("_") or "sshx11d"
    if name[0].isdigit():
        name = f"sshx11d_{name}"
    return name


def _render_freebsd_rcd_script(*, label: str, daemon_argv: list[str], working_directory: Path) -> str:
    name = _service_name(label)
    exec_start = _shell_join(daemon_argv)
    return "\n".join(
        [
            "#!/bin/sh",
            f"# PROVIDE: {name}",
            "# REQUIRE: NETWORKING",
            "# KEYWORD: shutdown",
            "",
            ". /etc/rc.subr",
            f'name="{name}"',
            f'rcvar="{name}_enable"',
            'command="/usr/sbin/daemon"',
            f'pidfile="/var/run/{name}.pid"',
            f'command_args="-f -p ${{pidfile}} -c {shlex.quote(str(working_directory))} -- {exec_start}"',
            f"load_rc_config {name}",
            f': ${{{name}_enable:="NO"}}',
            'run_rc_command "$1"',
            "",
        ]
    )


def _render_openbsd_rcd_script(*, label: str, daemon_argv: list[str], working_directory: Path) -> str:
    exec_start = _shell_join(daemon_argv)
    return "\n".join(
        [
            "#!/bin/ksh",
            f'daemon="{daemon_argv[0]}"',
            f'daemon_flags="{_shell_join(daemon_argv[1:])}"',
            f'daemon_user="{os.environ.get("USER", "")}"',
            f'daemon_execdir="{working_directory}"',
            ". /etc/rc.d/rc.subr",
            "rc_reload=NO",
            "rc_cmd $1",
            "",
            f"# Expanded command for audit: {exec_start}",
            "",
        ]
    )


def _render_windows_task_xml(*, label: str, python_bin: Path, daemon_argv: list[str], working_directory: Path) -> str:
    executable = str(python_bin)
    args_argv = daemon_argv[1:]  # remove python executable
    arguments = subprocess.list2cmdline(args_argv)
    executable_xml = xml_escape(executable)
    arguments_xml = xml_escape(arguments)
    workdir_xml = xml_escape(str(working_directory))
    label_xml = xml_escape(label)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        f"    <Description>SSHX11 per-user daemon ({label_xml})</Description>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <LogonTrigger>\n"
        "      <Enabled>true</Enabled>\n"
        "    </LogonTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        "    <Principal id=\"Author\">\n"
        "      <RunLevel>LeastPrivilege</RunLevel>\n"
        "      <LogonType>InteractiveToken</LogonType>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <IdleSettings>\n"
        "      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
        "      <RestartOnIdle>false</RestartOnIdle>\n"
        "    </IdleSettings>\n"
        "    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
        "    <Enabled>true</Enabled>\n"
        "    <Hidden>false</Hidden>\n"
        "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
        "    <WakeToRun>false</WakeToRun>\n"
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "    <Priority>7</Priority>\n"
        "  </Settings>\n"
        "  <Actions Context=\"Author\">\n"
        "    <Exec>\n"
        f"      <Command>{executable_xml}</Command>\n"
        f"      <Arguments>{arguments_xml}</Arguments>\n"
        f"      <WorkingDirectory>{workdir_xml}</WorkingDirectory>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def _build_plan(args: argparse.Namespace) -> dict[str, Any]:
    platform = _detect_platform(args.platform)
    repo_root = _resolve_path(args.repo_root, base=REPO_ROOT)
    state_dir = _resolve_path(args.state_dir, base=repo_root)
    python_bin = Path(str(args.python_bin)).expanduser()
    daemon_argv = _build_daemon_argv(args, repo_root=repo_root, state_dir=state_dir)
    label = str(args.label).strip() or DEFAULT_LABEL
    logs_dir = state_dir / "logs"

    base: dict[str, Any] = {
        "ok": True,
        "platform": platform,
        "label": label,
        "repo_root": str(repo_root),
        "state_dir": str(state_dir),
        "python_bin": str(python_bin),
        "daemon_argv": daemon_argv,
        "daemon_shell": _shell_join(daemon_argv),
        "files": [],
        "activation_commands": [],
        "deactivation_commands": [],
    }

    if platform == "macos":
        service_file = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        stdout_path = logs_dir / "daemon.stdout.log"
        stderr_path = logs_dir / "daemon.stderr.log"
        plist_text = _render_macos_plist(
            label=label,
            daemon_argv=daemon_argv,
            working_directory=repo_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        base["files"] = [
            {"path": str(service_file), "kind": "launchd_plist", "content": plist_text},
        ]
        base["activation_commands"] = [
            ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(service_file)],
            ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{label}"],
        ]
        base["deactivation_commands"] = [
            ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
        ]
        return base

    if platform == "windows":
        task_xml_file = state_dir / f"{label}.task.xml"
        xml_text = _render_windows_task_xml(
            label=label,
            python_bin=python_bin,
            daemon_argv=daemon_argv,
            working_directory=repo_root,
        )
        base["files"] = [
            {"path": str(task_xml_file), "kind": "task_xml", "content": xml_text},
        ]
        base["activation_commands"] = [
            ["schtasks", "/Create", "/TN", label, "/XML", str(task_xml_file), "/F"],
            ["schtasks", "/Run", "/TN", label],
        ]
        base["deactivation_commands"] = [
            ["schtasks", "/Delete", "/TN", label, "/F"],
        ]
        return base

    if platform in {"freebsd", "freebsd-gui"}:
        service_name = _service_name(label)
        service_file = Path("/usr/local/etc/rc.d") / service_name
        service_text = _render_freebsd_rcd_script(label=label, daemon_argv=daemon_argv, working_directory=repo_root)
        base["files"] = [
            {"path": str(service_file), "kind": "freebsd_rcd_service", "content": service_text},
        ]
        base["activation_commands"] = [
            ["chmod", "+x", str(service_file)],
            ["sysrc", f"{service_name}_enable=YES"],
            ["service", service_name, "start"],
        ]
        base["deactivation_commands"] = [
            ["service", service_name, "stop"],
            ["sysrc", f"{service_name}_enable=NO"],
        ]
        return base

    if platform == "openbsd":
        service_name = _service_name(label)
        service_file = Path("/etc/rc.d") / service_name
        service_text = _render_openbsd_rcd_script(label=label, daemon_argv=daemon_argv, working_directory=repo_root)
        base["files"] = [
            {"path": str(service_file), "kind": "openbsd_rcd_service", "content": service_text},
        ]
        base["activation_commands"] = [
            ["chmod", "+x", str(service_file)],
            ["rcctl", "enable", service_name],
            ["rcctl", "start", service_name],
        ]
        base["deactivation_commands"] = [
            ["rcctl", "stop", service_name],
            ["rcctl", "disable", service_name],
        ]
        return base

    # Linux generic, Linux GUI, and Linux headless all use the systemd unit when available.
    service_file = Path.home() / ".config" / "systemd" / "user" / f"{label}.service"
    service_text = _render_systemd_service(label=label, daemon_argv=daemon_argv, working_directory=repo_root)
    base["files"] = [
        {"path": str(service_file), "kind": "systemd_user_service", "content": service_text},
    ]
    base["activation_commands"] = [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", f"{label}.service"],
    ]
    base["deactivation_commands"] = [
        ["systemctl", "--user", "disable", "--now", f"{label}.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]
    return base


def _install_plan(plan: dict[str, Any]) -> dict[str, Any]:
    files = list(plan.get("files", []))
    written: list[str] = []
    for item in files:
        path = Path(str(item.get("path", "")))
        content = str(item.get("content", ""))
        _write_file(path, content)
        written.append(str(path))
    return {"ok": True, "written_files": written}


def _remove_plan_files(plan: dict[str, Any]) -> dict[str, Any]:
    files = list(plan.get("files", []))
    removed: list[str] = []
    for item in files:
        path = Path(str(item.get("path", "")))
        if path.exists():
            path.unlink()
            removed.append(str(path))
    return {"ok": True, "removed_files": removed}


def _run_commands(commands: list[list[str]], *, strict: bool) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    ok = True
    for cmd in commands:
        try:
            proc = _run([str(x) for x in cmd], check=False)
            row = {
                "argv": cmd,
                "ok": proc.returncode == 0,
                "exit_code": int(proc.returncode),
                "stdout": str(proc.stdout or "")[-2000:],
                "stderr": str(proc.stderr or "")[-2000:],
            }
            runs.append(row)
            if proc.returncode != 0:
                ok = False
                if strict:
                    break
        except Exception as exc:
            runs.append({"argv": cmd, "ok": False, "error": str(exc)})
            ok = False
            if strict:
                break
    return {"ok": ok, "runs": runs}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "command",
        nargs="?",
        default="render",
        choices=["render", "install", "uninstall", "print-windows-task"],
    )
    p.add_argument("--platform", default="auto", help="auto|macos|linux|linux-headless|linux-gui|windows|freebsd|freebsd-gui|openbsd")
    p.add_argument("--label", default=DEFAULT_LABEL)
    p.add_argument("--repo-root", default=str(REPO_ROOT))
    p.add_argument("--python-bin", default=sys.executable)
    p.add_argument("--daemon-script", default=str(DEFAULT_DAEMON_SCRIPT))
    p.add_argument("--contract-file", default=str(DEFAULT_CONTRACT_FILE))
    p.add_argument("--host", default=sshx11d.DEFAULT_HOST)
    p.add_argument("--port", type=int, default=sshx11d.DEFAULT_PORT)
    p.add_argument("--state-dir", default=str(sshx11d.default_state_dir()))
    p.add_argument("--timeout-s", type=float, default=sshx11d.DEFAULT_TIMEOUT_S)
    p.add_argument("--events-max", type=int, default=sshx11d.DEFAULT_EVENTS_MAX)
    p.add_argument("--allow-no-token", action="store_true", default=False)
    p.add_argument("--allow-unsafe-subcommand", action="store_true", default=False)
    p.add_argument("--activate", action="store_true", default=False)
    p.add_argument("--strict-activate", action="store_true", default=False)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    plan = _build_plan(args)

    if args.command == "render":
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "print-windows-task":
        windows_args = argparse.Namespace(**vars(args))
        windows_args.platform = "windows"
        windows_plan = _build_plan(windows_args)
        print(json.dumps(windows_plan, indent=2, sort_keys=True))
        return 0

    if args.command == "install":
        install_out = _install_plan(plan)
        out: dict[str, Any] = {"ok": bool(install_out.get("ok")), "plan": plan, "install": install_out}
        if bool(args.activate):
            activation = _run_commands(list(plan.get("activation_commands", [])), strict=bool(args.strict_activate))
            out["activation"] = activation
            out["ok"] = bool(out["ok"]) and bool(activation.get("ok"))
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0 if bool(out.get("ok")) else 1

    # uninstall
    deactivate_out: dict[str, Any] | None = None
    if bool(args.activate):
        deactivate_out = _run_commands(list(plan.get("deactivation_commands", [])), strict=bool(args.strict_activate))
    remove_out = _remove_plan_files(plan)
    out = {
        "ok": bool(remove_out.get("ok")) and (deactivate_out is None or bool(deactivate_out.get("ok"))),
        "plan": plan,
        "remove": remove_out,
        "deactivation": deactivate_out,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if bool(out.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
