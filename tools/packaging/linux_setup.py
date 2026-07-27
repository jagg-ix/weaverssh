#!/usr/bin/env python3
from __future__ import annotations

"""Platform setup planner for weaverssh.

The module is intentionally usable both as a CLI and as a small library:

- detect runtime package manager and dependency commands
- detect local SSH agent, key files, and ssh_config Host entries
- emit reproducible `wv connection set/use` commands

No system or profile changes are made unless the caller uses the `apply`
subcommand.

The original Linux route remains supported through build_linux_setup_plan().
"""

import argparse
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
from typing import Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from install_runtime_dependencies import build_plan as build_dependency_plan
except ImportError:  # pragma: no cover - import fallback for package execution
    from tools.packaging.install_runtime_dependencies import build_plan as build_dependency_plan


DEFAULT_KEY_NAMES = (
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "id_ed25519_sk",
    "id_ecdsa_sk",
)
UNIX_SSH_CONFIGS = ("~/.ssh/config", "/etc/ssh/ssh_config")
WINDOWS_SSH_CONFIGS = ("~/.ssh/config",)
DEFAULT_SSH_CONFIGS = UNIX_SSH_CONFIGS

PLATFORM_ALIASES = {
    "darwin": "macos",
    "macosx": "macos",
    "osx": "macos",
    "win32": "windows",
    "cygwin": "windows",
    "msys": "windows",
    "linux-on-zos": "zos-linux",
    "linux_on_zos": "zos-linux",
    "linux-zos": "zos-linux",
    "zlinux": "zos-linux",
    "zos": "zos-linux",
}

PLATFORM_DEFAULT_MANAGERS = {
    "linux": ("apt", "dnf", "yum", "zypper", "pacman", "apk"),
    "wsl": ("apt", "dnf", "yum", "zypper", "pacman", "apk"),
    "zos-linux": ("dnf", "yum", "apt", "zypper"),
    "macos": ("brew",),
    "windows": ("winget", "choco"),
    "freebsd": ("pkg",),
    "aix": ("dnf", "installp"),
}

EXTRA_DEPENDENCIES = {
    "pkg": ["openssh-portable", "xauth", "python3"],
    "installp": ["openssh", "python3"],
}


@dataclass(frozen=True)
class SSHAgentStatus:
    configured: bool
    socket: str = ""
    source: str = "SSH_AUTH_SOCK"
    provider: str = "sshAgent"


@dataclass(frozen=True)
class KeyCandidate:
    path: str
    exists: bool
    source: str


@dataclass(frozen=True)
class SSHConfigHost:
    alias: str
    hostname: str = ""
    user: str = ""
    port: int = 22
    identity_file: str = ""
    proxy_jump: str = ""
    source: str = ""


@dataclass(frozen=True)
class PlatformSetupPlan:
    ok: bool
    platform: str
    package_manager: str
    dependency_commands: list[list[str]]
    ssh_agent: SSHAgentStatus
    key_candidates: list[KeyCandidate]
    ssh_config_hosts: list[SSHConfigHost]
    selected_profile: SSHConfigHost | None
    connection_commands: list[list[str]]
    script: str
    notes: list[str] = field(default_factory=list)


LinuxSetupPlan = PlatformSetupPlan


def expand_path(raw: str, *, home: Path | None = None) -> Path:
    if home is not None and raw.startswith("~/"):
        return home / raw[2:]
    return Path(raw).expanduser()


def normalize_platform(raw: str | None, env: Mapping[str, str] | None = None) -> str:
    env = env or os.environ
    value = (raw or "").strip().lower()
    if not value or value == "auto":
        value = platform.system().lower()
    value = PLATFORM_ALIASES.get(value, value)
    if value == "linux" and is_wsl_env(env):
        return "wsl"
    if value in {"linux", "wsl", "windows", "macos", "freebsd", "aix", "zos-linux"}:
        return value
    return value or "unknown"


def is_wsl_env(env: Mapping[str, str]) -> bool:
    if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return True
    for path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if "microsoft" in text or "wsl" in text:
            return True
    return False


def windows_profile_config_path(env: Mapping[str, str]) -> str:
    userprofile = env.get("USERPROFILE", "").strip()
    if userprofile:
        return str(Path(userprofile) / ".ssh" / "config")
    home_drive = env.get("HOMEDRIVE", "").strip()
    home_path = env.get("HOMEPATH", "").strip()
    if home_drive and home_path:
        return str(Path(home_drive + home_path) / ".ssh" / "config")
    return "~/.ssh/config"


def wsl_windows_config_path(env: Mapping[str, str]) -> str:
    userprofile = env.get("USERPROFILE", "").strip()
    if not userprofile:
        return ""
    normalized = userprofile.replace("\\", "/")
    if len(normalized) >= 3 and normalized[1] == ":":
        drive = normalized[0].lower()
        rest = normalized[2:].lstrip("/")
        return f"/mnt/{drive}/{rest}/.ssh/config"
    return ""


def default_ssh_config_paths_for_platform(platform_name: str, env: Mapping[str, str]) -> list[str]:
    if platform_name == "windows":
        return [windows_profile_config_path(env), "C:/ProgramData/ssh/ssh_config"]
    if platform_name == "wsl":
        paths = list(UNIX_SSH_CONFIGS)
        if p := wsl_windows_config_path(env):
            paths.append(p)
        return paths
    if platform_name in {"linux", "macos", "freebsd", "aix", "zos-linux"}:
        return list(UNIX_SSH_CONFIGS)
    return list(DEFAULT_SSH_CONFIGS)


def choose_package_manager(platform_name: str, requested: str | None = None) -> str | None:
    if requested:
        return requested
    managers = PLATFORM_DEFAULT_MANAGERS.get(platform_name, ())
    for manager in managers:
        binary = {
            "apt": "apt-get",
            "winget": "winget",
            "choco": "choco",
            "pkg": "pkg",
            "installp": "installp",
        }.get(manager, manager)
        if binary and shutil_which(binary):
            return manager
    return managers[0] if managers else None


def shutil_which(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def dependency_commands_for_platform(
    platform_name: str,
    manager: str | None,
    *,
    include_build: bool,
    assume_yes: bool,
) -> tuple[str, list[list[str]]]:
    selected = choose_package_manager(platform_name, manager)
    if selected in {"apt", "dnf", "yum", "zypper", "pacman", "apk", "brew", "winget", "choco"}:
        dep = build_dependency_plan(selected, include_build=include_build, assume_yes=assume_yes)
        return dep.package_manager, dep.commands
    if selected == "pkg":
        packages = list(EXTRA_DEPENDENCIES["pkg"])
        if include_build:
            packages.extend(["go", "gmake", "zip", "zstd"])
        return selected, [["sudo", "pkg", "install", "-y" if assume_yes else "-n", *packages]]
    if selected == "installp":
        return selected, [["echo", "AIX installp package names are site-specific; install OpenSSH and Python 3 from your approved AIX media or AIX Toolbox."]]
    return selected or "unknown", []


def detect_ssh_agent(env: Mapping[str, str] | None = None) -> SSHAgentStatus:
    if env is None:
        env = os.environ
    pageant = str(env.get("PAGEANT_SSH_AUTH_SOCK", "") or env.get("WEAVERSSH_PAGEANT", "")).strip()
    if pageant:
        return SSHAgentStatus(configured=True, socket=pageant, source="PAGEANT_SSH_AUTH_SOCK", provider="pageant")
    gpg_socket = str(env.get("WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK", "")).strip()
    if gpg_socket:
        return SSHAgentStatus(configured=True, socket=gpg_socket, source="WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK", provider="gpgAgent")
    gpg_socket = str(env.get("GPG_AGENT_SSH_AUTH_SOCK", "")).strip()
    if gpg_socket:
        return SSHAgentStatus(configured=True, socket=gpg_socket, source="GPG_AGENT_SSH_AUTH_SOCK", provider="gpgAgent")
    socket = str(env.get("SSH_AUTH_SOCK", "")).strip()
    lowered = socket.lower()
    provider = "gpgAgent" if ("gpg-agent" in lowered or "gnupg" in lowered) else "sshAgent"
    return SSHAgentStatus(configured=bool(socket), socket=socket, provider=provider)


def detect_key_candidates(
    home: Path | None = None,
    explicit_identity: str = "",
    key_names: Sequence[str] = DEFAULT_KEY_NAMES,
) -> list[KeyCandidate]:
    home = home or Path.home()
    candidates: list[tuple[Path, str]] = []
    if explicit_identity.strip():
        candidates.append((expand_path(explicit_identity.strip(), home=home), "explicit"))
    for name in key_names:
        candidates.append((home / ".ssh" / name, "default"))

    out: list[KeyCandidate] = []
    seen: set[str] = set()
    for path, source in candidates:
        text = str(path)
        if text in seen:
            continue
        seen.add(text)
        out.append(KeyCandidate(path=text, exists=path.exists(), source=source))
    return out


def parse_ssh_config(path: Path) -> list[SSHConfigHost]:
    if not path.exists():
        return []
    hosts: list[SSHConfigHost] = []
    current_aliases: list[str] = []
    current: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_aliases, current
        for alias in current_aliases:
            if "*" in alias or "?" in alias:
                continue
            hosts.append(
                SSHConfigHost(
                    alias=alias,
                    hostname=current.get("hostname", ""),
                    user=current.get("user", ""),
                    port=parse_int(current.get("port", ""), 22),
                    identity_file=current.get("identityfile", ""),
                    proxy_jump=current.get("proxyjump", ""),
                    source=str(path),
                )
            )
        current_aliases = []
        current = {}

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            parts = line.split()
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        value = " ".join(parts[1:])
        if key == "host":
            flush()
            current_aliases = parts[1:]
            current = {}
        elif current_aliases and key in {"hostname", "user", "port", "identityfile", "proxyjump"}:
            current[key] = value
    flush()
    return hosts


def detect_ssh_config_hosts(config_paths: Sequence[str] = DEFAULT_SSH_CONFIGS, home: Path | None = None) -> list[SSHConfigHost]:
    home = home or Path.home()
    hosts: list[SSHConfigHost] = []
    seen: set[str] = set()
    for raw in config_paths:
        path = expand_path(raw, home=home)
        for host in parse_ssh_config(path):
            key = f"{host.alias}\0{host.source}"
            if key in seen:
                continue
            seen.add(key)
            hosts.append(host)
    return hosts


def parse_int(raw: str, fallback: int) -> int:
    try:
        value = int(str(raw).strip())
    except ValueError:
        return fallback
    return value if value > 0 else fallback


def select_profile(
    hosts: Sequence[SSHConfigHost],
    *,
    alias: str = "",
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_port: int = 22,
    identity_file: str = "",
) -> SSHConfigHost | None:
    if alias:
        for host in hosts:
            if host.alias == alias:
                return merge_profile(host, ssh_host=ssh_host, ssh_user=ssh_user, ssh_port=ssh_port, identity_file=identity_file)
    if ssh_host or ssh_user or identity_file:
        return SSHConfigHost(
            alias=alias or ssh_host or "profile1",
            hostname=ssh_host,
            user=ssh_user,
            port=ssh_port or 22,
            identity_file=identity_file,
            source="cli",
        )
    return hosts[0] if hosts else None


def merge_profile(host: SSHConfigHost, *, ssh_host: str, ssh_user: str, ssh_port: int, identity_file: str) -> SSHConfigHost:
    return SSHConfigHost(
        alias=host.alias,
        hostname=ssh_host or host.hostname,
        user=ssh_user or host.user,
        port=ssh_port or host.port or 22,
        identity_file=identity_file or host.identity_file,
        proxy_jump=host.proxy_jump,
        source=host.source,
    )


def build_connection_commands(profile: SSHConfigHost | None, *, active: bool = True, credential_provider: str = "sshAgent") -> list[list[str]]:
    if profile is None:
        return []
    name = profile.alias or profile.hostname or "profile1"
    cmd = ["wv", "connection", "set", name]
    if profile.hostname:
        cmd.extend(["--host", profile.hostname])
    if profile.user:
        cmd.extend(["--user", profile.user])
    if profile.port:
        cmd.extend(["--port", str(profile.port)])
    if profile.identity_file:
        cmd.extend(["--identity-file", profile.identity_file])
    cmd.extend(["--adapter", "openSSH", "--credential-provider", credential_provider])
    if active:
        cmd.append("--active")
    return [cmd]


def shell_script(commands: Sequence[Sequence[str]], *, platform_name: str = "linux") -> str:
    if platform_name == "windows":
        lines = ["# weaverssh Windows setup script", "$ErrorActionPreference = 'Stop'"]
        lines.extend(" ".join(shlex.quote(part) for part in cmd) for cmd in commands)
        return "\n".join(lines) + "\n"
    lines = ["#!/bin/sh", "set -eu"]
    lines.extend(" ".join(shlex.quote(part) for part in cmd) for cmd in commands)
    return "\n".join(lines) + "\n"


def build_platform_setup_plan(
    *,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
    manager: str | None = None,
    platform_name: str | None = None,
    include_build: bool = False,
    assume_yes: bool = False,
    ssh_config_paths: Sequence[str] | None = None,
    profile_alias: str = "",
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_port: int = 22,
    identity_file: str = "",
) -> PlatformSetupPlan:
    if env is None:
        env = os.environ
    home = home or Path.home()
    system = normalize_platform(platform_name, env)
    package_manager, dep_commands = dependency_commands_for_platform(
        system,
        manager,
        include_build=include_build,
        assume_yes=assume_yes,
    )
    if ssh_config_paths is None:
        ssh_config_paths = default_ssh_config_paths_for_platform(system, env)
    agent = detect_ssh_agent(env)
    keys = detect_key_candidates(home=home, explicit_identity=identity_file)
    hosts = detect_ssh_config_hosts(ssh_config_paths, home=home)
    selected = select_profile(hosts, alias=profile_alias, ssh_host=ssh_host, ssh_user=ssh_user, ssh_port=ssh_port, identity_file=identity_file)
    credential_provider = agent.provider if agent.configured else ("keyFile" if any(k.exists for k in keys) or identity_file else "sshAgent")
    commands = build_connection_commands(selected, credential_provider=credential_provider)
    notes: list[str] = []
    if system == "wsl":
        notes.append("WSL route uses Linux tooling and also scans the Windows user's ssh_config when USERPROFILE is available")
    if system == "windows":
        notes.append("Windows route supports OpenSSH/Pageant-style identity discovery and emits commands suitable for PowerShell or cmd PATH")
    if system == "aix":
        notes.append("AIX package installation is organization-specific; prefer approved AIX Toolbox/dnf or installp media")
    if system == "zos-linux":
        notes.append("z/OS Linux route assumes a Linux-on-Z/s390x userland; package manager depends on the distribution")
    if system == "freebsd":
        notes.append("FreeBSD route assumes pkg-managed OpenSSH/Python where base-system OpenSSH is insufficient")
    if not agent.configured:
        notes.append("no SSH agent socket detected; start ssh-agent/Pageant or use --identity-file")
    if not any(k.exists for k in keys):
        notes.append("no default SSH private key files were found")
    if selected is None:
        notes.append("no ssh_config Host entry or explicit --ssh-host was found; no profile command was generated")
    return PlatformSetupPlan(
        ok=bool(dep_commands) or system in {"aix"},
        platform=system,
        package_manager=package_manager,
        dependency_commands=dep_commands,
        ssh_agent=agent,
        key_candidates=keys,
        ssh_config_hosts=hosts,
        selected_profile=selected,
        connection_commands=commands,
        script=shell_script(commands, platform_name=system),
        notes=notes,
    )


def build_linux_setup_plan(**kwargs) -> PlatformSetupPlan:
    kwargs.setdefault("platform_name", "linux")
    return build_platform_setup_plan(**kwargs)


def apply_connection_commands(commands: Sequence[Sequence[str]]) -> None:
    for cmd in commands:
        subprocess.run(list(cmd), check=True)


def print_human(plan: LinuxSetupPlan) -> None:
    print(f"platform: {plan.platform}")
    print(f"package-manager: {plan.package_manager}")
    print("dependency commands:")
    for cmd in plan.dependency_commands:
        print("  " + " ".join(shlex.quote(part) for part in cmd))
    print(f"credential-agent: {plan.ssh_agent.provider} {'configured' if plan.ssh_agent.configured else 'missing'} {plan.ssh_agent.socket}")
    print("key candidates:")
    for key in plan.key_candidates:
        marker = "found" if key.exists else "missing"
        print(f"  - [{marker}] {key.path}")
    print("ssh_config hosts:")
    if not plan.ssh_config_hosts:
        print("  - none")
    for host in plan.ssh_config_hosts:
        print(f"  - {host.alias} -> {host.user}@{host.hostname}:{host.port} ({host.source})")
    print("connection setup commands:")
    if not plan.connection_commands:
        print("  - none")
    for cmd in plan.connection_commands:
        print("  " + " ".join(shlex.quote(part) for part in cmd))
    if plan.notes:
        print("notes:")
        for note in plan.notes:
            print(f"  - {note}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("detect", "plan", "emit-script", "apply"), nargs="?", default="plan")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument(
        "--platform",
        default="auto",
        choices=("auto", "linux", "wsl", "windows", "macos", "macosx", "darwin", "freebsd", "aix", "zos-linux", "linux-on-zos"),
        help="setup route to plan; auto detects the local platform",
    )
    parser.add_argument("--manager", choices=("apt", "dnf", "yum", "zypper", "pacman", "apk", "brew", "winget", "choco", "pkg", "installp"))
    parser.add_argument("--include-build", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--ssh-config", action="append", default=[], help="ssh_config path; repeatable")
    parser.add_argument("--profile-alias", default="", help="ssh_config Host alias to convert to a wv profile")
    parser.add_argument("--ssh-host", default="", help="explicit SSH host if no ssh_config alias should be used")
    parser.add_argument("--ssh-user", default="", help="explicit SSH user")
    parser.add_argument("--ssh-port", type=int, default=22, help="explicit SSH port")
    parser.add_argument("--identity-file", default="", help="local SSH private key path")
    parser.add_argument("--output", type=Path, default=None, help="write generated script or JSON to this path")
    parser.add_argument("--execute", action="store_true", help="required with apply to run generated wv connection commands")
    args = parser.parse_args(argv)

    config_paths = args.ssh_config or None
    plan = build_platform_setup_plan(
        platform_name=args.platform,
        manager=args.manager,
        include_build=args.include_build,
        assume_yes=args.yes,
        ssh_config_paths=config_paths,
        profile_alias=args.profile_alias,
        ssh_host=args.ssh_host,
        ssh_user=args.ssh_user,
        ssh_port=args.ssh_port,
        identity_file=args.identity_file,
    )

    if args.command == "emit-script":
        text = plan.script
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0

    if args.command == "apply":
        if not args.execute:
            print("linux setup apply requires --execute; use plan or emit-script first", file=sys.stderr)
            return 2
        apply_connection_commands(plan.connection_commands)
        return 0

    payload = json.dumps(asdict(plan), indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    if args.format == "json" or args.command == "detect":
        print(payload)
    else:
        print_human(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
