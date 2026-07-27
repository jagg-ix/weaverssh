#!/usr/bin/env python3
from __future__ import annotations

"""Plan, inspect, or run OS package-manager installs for weaverssh prerequisites."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
from typing import Any

LINUX_DEPENDENCIES: dict[str, list[str]] = {
    "apt": ["ca-certificates", "openssh-client", "xauth", "python3", "python3-venv", "python3-tk"],
    "dnf": ["ca-certificates", "openssh-clients", "xorg-x11-xauth", "python3", "python3-tkinter"],
    "yum": ["ca-certificates", "openssh-clients", "xorg-x11-xauth", "python3", "python3-tkinter"],
    "zypper": ["ca-certificates", "openssh", "xauth", "python3", "python3-tk"],
    "pacman": ["ca-certificates", "openssh", "xorg-xauth", "python", "tk"],
    "apk": ["ca-certificates", "openssh-client", "xauth", "python3", "tk"],
}
MACOS_DEPENDENCIES = {
    "brew": ["go", "python", "xquartz"],
}
WINDOWS_DEPENDENCIES = {
    "winget": ["Git.Git", "GoLang.Go", "Python.Python.3.12"],
    "choco": ["git", "golang", "python"],
}
BSD_DEPENDENCIES = {
    "pkg": ["ca_root_nss", "openssh-portable", "xauth", "python3"],
    "pkg_add": ["xauth"],
}
AIX_DEPENDENCIES = {
    "installp": ["openssh", "xauth"],
}
HOME_RUNTIME_TOOLS = ["ssh", "python3"]
HOME_BUILD_TOOLS = ["go", "git", "make"]
DEFAULT_HOME_PREFIX = "~/.weaverssh"
DEFAULT_GO_VERSION = "1.24.4"


@dataclass(frozen=True)
class DependencyStatus:
    package: str
    installed: bool
    state: str
    detail: str
    query_command: list[str]
    error: str = ""


@dataclass(frozen=True)
class DependencyPlan:
    platform: str
    package_manager: str
    install_method: str
    home_prefix: str
    packages: list[str]
    selected_packages: list[str]
    installed_packages: list[str]
    missing_packages: list[str]
    unknown_packages: list[str]
    commands: list[list[str]]
    requires_privilege: bool
    action: str = "install"
    replace: bool = False
    force: bool = False
    only_missing: bool = True
    status_summary: dict[str, int] | None = None
    statuses: list[DependencyStatus] | None = None
    safeguards: list[str] | None = None


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _linux_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"')
    return out


def detect_package_manager(requested: str | None = None) -> tuple[str, str]:
    if requested:
        if requested in LINUX_DEPENDENCIES:
            return "linux", requested
        if requested in MACOS_DEPENDENCIES:
            return "darwin", requested
        if requested in WINDOWS_DEPENDENCIES:
            return "windows", requested
        if requested in BSD_DEPENDENCIES:
            return ("freebsd" if requested == "pkg" else "openbsd"), requested
        if requested in AIX_DEPENDENCIES:
            return "aix", requested
        return platform.system().lower(), requested
    system = platform.system().lower()
    if system == "linux":
        for manager in ("apt", "dnf", "yum", "zypper", "pacman", "apk"):
            binary = "apt-get" if manager == "apt" else manager
            if _which(binary):
                return system, manager
        os_release = _linux_os_release()
        distro = " ".join([os_release.get("ID", ""), os_release.get("ID_LIKE", "")]).lower()
        if any(name in distro for name in ("debian", "ubuntu")):
            return system, "apt"
        if any(name in distro for name in ("fedora", "rhel", "centos")):
            return system, "dnf"
        if "suse" in distro:
            return system, "zypper"
        if "arch" in distro:
            return system, "pacman"
        if "alpine" in distro:
            return system, "apk"
    if system == "darwin":
        return system, "brew"
    if system in ("windows", "cygwin", "msys"):
        if _which("winget"):
            return system, "winget"
        return system, "choco"
    if system == "freebsd":
        return system, "pkg"
    if system in ("openbsd", "netbsd"):
        return system, "pkg_add"
    if system == "aix":
        return system, "installp"
    return system, "unknown"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def resolve_install_method(method: str, package_manager: str | None) -> str:
    selected = (method or "auto").strip().lower()
    if selected == "auto":
        return "package-manager" if package_manager else "home"
    if selected in {"home", "package-manager"}:
        return selected
    raise ValueError(f"unsupported install method: {method}")


def resolve_home_packages(include_build: bool) -> list[str]:
    packages = list(HOME_RUNTIME_TOOLS)
    if include_build:
        packages.extend(HOME_BUILD_TOOLS)
    return _dedupe(packages)


def home_installable_tools() -> set[str]:
    return {"go"}


def resolve_packages(manager: str, include_build: bool) -> list[str]:
    if manager in LINUX_DEPENDENCIES:
        packages = list(LINUX_DEPENDENCIES[manager])
        if include_build:
            if manager == "apt":
                packages.extend(["golang", "make", "dpkg-dev", "rpm", "zstd", "zip"])
            elif manager in ("dnf", "yum"):
                packages.extend(["golang", "make", "rpm-build", "zstd", "zip"])
            elif manager == "zypper":
                packages.extend(["go", "make", "rpm-build", "zstd", "zip"])
            elif manager == "pacman":
                packages.extend(["go", "make", "fakeroot", "zstd", "zip"])
            elif manager == "apk":
                packages.extend(["go", "make", "rpm", "zstd", "zip"])
        return _dedupe(packages)
    if manager == "brew":
        packages = list(MACOS_DEPENDENCIES[manager])
        if include_build:
            packages.extend(["rpm", "zstd"])
        return _dedupe(packages)
    if manager in WINDOWS_DEPENDENCIES:
        return list(WINDOWS_DEPENDENCIES[manager])
    if manager in BSD_DEPENDENCIES:
        packages = list(BSD_DEPENDENCIES[manager])
        if include_build:
            if manager == "pkg":
                packages.extend(["go", "gmake", "git", "zip", "zstd"])
            elif manager == "pkg_add":
                packages.extend(["go", "gmake", "git", "python3"])
        return _dedupe(packages)
    if manager in AIX_DEPENDENCIES:
        return list(AIX_DEPENDENCIES[manager])
    return []


def requires_privilege_for(manager: str) -> bool:
    if manager in LINUX_DEPENDENCIES:
        return os.geteuid() != 0 if hasattr(os, "geteuid") else True
    if manager in WINDOWS_DEPENDENCIES:
        return True
    if manager in BSD_DEPENDENCIES:
        return os.geteuid() != 0 if hasattr(os, "geteuid") else True
    if manager in AIX_DEPENDENCIES:
        return True
    return False


def build_plan(
    package_manager: str | None = None,
    include_build: bool = False,
    assume_yes: bool = False,
    replace: bool = False,
    force: bool = False,
    inspect: bool = False,
    only_missing: bool = True,
    method: str = "auto",
    home_prefix: str = DEFAULT_HOME_PREFIX,
) -> DependencyPlan:
    system, detected_manager = detect_package_manager(package_manager)
    install_method = resolve_install_method(method, package_manager)
    manager = detected_manager if install_method == "package-manager" else "home"
    packages = resolve_home_packages(include_build) if install_method == "home" else resolve_packages(manager, include_build)
    statuses = (
        inspect_home_tool_statuses(packages, home_prefix)
        if inspect and install_method == "home"
        else inspect_package_statuses(manager, packages)
        if inspect
        else None
    )
    installed_packages, missing_packages, unknown_packages = classify_packages(statuses)
    effective_only_missing = only_missing and not (replace or force)
    selected_packages = select_target_packages(
        packages,
        statuses=statuses,
        missing_packages=missing_packages,
        unknown_packages=unknown_packages,
        replace=replace,
        force=force,
        only_missing=effective_only_missing,
    )
    requires_privilege = False if install_method == "home" else requires_privilege_for(manager)
    commands = (
        build_home_commands(selected_packages, include_build=include_build, home_prefix=home_prefix, replace=replace, force=force)
        if install_method == "home"
        else build_commands(
            manager,
            selected_packages,
            assume_yes=assume_yes,
            replace=replace,
            force=force,
            requires_privilege=requires_privilege,
        )
    )
    safeguards: list[str] = []
    if install_method == "home":
        safeguards.append("default home method writes only under the selected home prefix")
        unsupported = [pkg for pkg in selected_packages if pkg not in home_installable_tools()]
        if unsupported:
            safeguards.append("these tools must already exist on PATH or be installed by an operator: " + ", ".join(unsupported))
    if force:
        safeguards.append("force requested; install requires --confirm-force")
    if replace:
        safeguards.append("replace requested; commands intentionally target selected package set")
    if inspect and not selected_packages and effective_only_missing:
        safeguards.append("all inspected packages are already installed; no install command generated")
    return DependencyPlan(
        platform=system,
        package_manager=manager,
        install_method=install_method,
        home_prefix=home_prefix,
        packages=packages,
        selected_packages=selected_packages,
        installed_packages=installed_packages,
        missing_packages=missing_packages,
        unknown_packages=unknown_packages,
        commands=commands,
        requires_privilege=requires_privilege,
        action="replace" if replace else "install",
        replace=replace,
        force=force,
        only_missing=effective_only_missing,
        status_summary=status_summary(statuses),
        statuses=statuses,
        safeguards=safeguards,
    )


def classify_packages(statuses: list[DependencyStatus] | None) -> tuple[list[str], list[str], list[str]]:
    if statuses is None:
        return [], [], []
    installed = [item.package for item in statuses if item.state == "installed"]
    missing = [item.package for item in statuses if item.state == "missing"]
    unknown = [item.package for item in statuses if item.state == "unknown"]
    return installed, missing, unknown


def status_summary(statuses: list[DependencyStatus] | None) -> dict[str, int] | None:
    if statuses is None:
        return None
    summary = {"installed": 0, "missing": 0, "unknown": 0, "total": len(statuses)}
    for item in statuses:
        if item.state in summary:
            summary[item.state] += 1
    return summary


def select_target_packages(
    packages: list[str],
    *,
    statuses: list[DependencyStatus] | None,
    missing_packages: list[str],
    unknown_packages: list[str],
    replace: bool,
    force: bool,
    only_missing: bool,
) -> list[str]:
    if replace or force:
        return list(packages)
    if statuses is None or not only_missing:
        return list(packages)
    return _dedupe([*missing_packages, *unknown_packages])


def build_commands(
    manager: str,
    packages: list[str],
    *,
    assume_yes: bool,
    replace: bool,
    force: bool,
    requires_privilege: bool,
) -> list[list[str]]:
    if not packages:
        return []
    sudo = ["sudo"] if requires_privilege else []
    commands: list[list[str]] = []
    if manager == "apt":
        commands.append([*sudo, "apt-get", "update"])
        install_cmd = [*sudo, "apt-get", "install"]
        if assume_yes:
            install_cmd.append("-y")
        install_cmd.append("--no-install-recommends")
        if replace:
            install_cmd.append("--reinstall")
        if force:
            install_cmd.extend(["--allow-downgrades", "--allow-change-held-packages", "-o", "Dpkg::Options::=--force-confnew"])
        commands.append([*install_cmd, *packages])
    elif manager in ("dnf", "yum"):
        action = "reinstall" if replace else "install"
        install_cmd = [*sudo, manager, action, "-y" if assume_yes else "--assumeno"]
        if force:
            install_cmd.append("--allowerasing")
        commands.append([*install_cmd, *packages])
    elif manager == "zypper":
        install_cmd = [*sudo, "zypper", "install", "-y" if assume_yes else "--dry-run"]
        if replace or force:
            install_cmd.append("--force")
        commands.append([*install_cmd, *packages])
    elif manager == "pacman":
        install_cmd = [*sudo, "pacman", "-Syu" if force else "-Sy"]
        if not replace:
            install_cmd.append("--needed")
        if force:
            install_cmd.extend(["--overwrite", "*"])
        install_cmd.append("--noconfirm" if assume_yes else "--print")
        commands.append([*install_cmd, *packages])
    elif manager == "apk":
        install_cmd = [*sudo, "apk", "fix" if replace else "add"]
        if force:
            install_cmd.append("--force-refresh")
        commands.append([*install_cmd, *packages])
    elif manager == "brew":
        formulae = [pkg for pkg in packages if pkg != "xquartz"]
        casks = [pkg for pkg in packages if pkg == "xquartz"]
        if formulae:
            commands.append(["brew", "reinstall" if replace or force else "install", *formulae])
        commands.extend(["brew", "reinstall" if replace or force else "install", "--cask", cask] for cask in casks)
    elif manager == "winget":
        commands = [
            [
                "winget",
                "install",
                "--id",
                pkg,
                "--exact",
                *([] if not (replace or force) else ["--force"]),
                "--silent" if assume_yes else "--interactive",
            ]
            for pkg in packages
        ]
    elif manager == "choco":
        commands = [
            [
                "choco",
                "upgrade" if replace or force else "install",
                pkg,
                "-y" if assume_yes else "--noop",
                *([] if not force else ["--force"]),
            ]
            for pkg in packages
        ]
    elif manager == "pkg":
        install_cmd = [*sudo, "pkg", "install", "-y" if assume_yes else "-n"]
        if replace or force:
            install_cmd.append("-f")
        commands.append([*install_cmd, *packages])
    elif manager == "pkg_add":
        commands.append([*sudo, "pkg_add", "-I" if assume_yes else "-n", *packages])
    elif manager == "installp":
        commands.append(["echo", "AIX installp requires approved local media; install OpenSSH and xauth from the organization package source"])
    return commands


def _expand_home_prefix(home_prefix: str) -> Path:
    return Path(home_prefix or DEFAULT_HOME_PREFIX).expanduser()


def home_tool_candidates(tool: str, home_prefix: str) -> list[Path]:
    prefix = _expand_home_prefix(home_prefix)
    if tool == "go":
        return [prefix / "toolchains" / "go" / "bin" / "go", prefix / "bin" / "go"]
    return [prefix / "bin" / tool]


def inspect_home_tool_statuses(tools: list[str], home_prefix: str) -> list[DependencyStatus]:
    statuses: list[DependencyStatus] = []
    for tool in tools:
        query = ["command", "-v", tool]
        found = shutil.which(tool)
        if found:
            statuses.append(DependencyStatus(tool, True, "installed", found, query))
            continue
        home_hits = [str(path) for path in home_tool_candidates(tool, home_prefix) if path.exists()]
        if home_hits:
            statuses.append(DependencyStatus(tool, True, "installed", home_hits[0], query))
            continue
        installable = tool in home_installable_tools()
        detail = "missing; home installer can provide this tool" if installable else "missing; requires existing PATH tool or explicit package-manager install"
        statuses.append(DependencyStatus(tool, False, "missing", detail, query))
    return statuses


def build_home_commands(
    tools: list[str],
    *,
    include_build: bool,
    home_prefix: str,
    replace: bool,
    force: bool,
) -> list[list[str]]:
    if not tools:
        return []
    prefix = str(_expand_home_prefix(home_prefix))
    commands: list[list[str]] = [
        ["mkdir", "-p", f"{prefix}/bin", f"{prefix}/toolchains", f"{prefix}/logs", f"{prefix}/tmp"],
    ]
    if "go" in tools:
        commands.append(["sh", "-c", home_go_install_script(prefix, replace=replace or force)])
    if include_build:
        commands.append(["sh", "-c", f'printf "%s\\n" "export PATH=\\"{prefix}/bin:$PATH\\"" > "{prefix}/env.sh"'])
    return commands


def home_go_install_script(prefix: str, *, replace: bool) -> str:
    rm_existing = f'rm -rf "{prefix}/toolchains/go"; ' if replace else f'test ! -x "{prefix}/toolchains/go/bin/go" || exit 0; '
    return (
        "set -eu; "
        f'prefix="{prefix}"; '
        'mkdir -p "$prefix/toolchains" "$prefix/tmp" "$prefix/bin"; '
        'os="$(uname -s | tr "[:upper:]" "[:lower:]")"; '
        'arch="$(uname -m)"; '
        'case "$arch" in x86_64|amd64) arch="amd64";; arm64|aarch64) arch="arm64";; *) echo "unsupported Go bootstrap arch: $arch" >&2; exit 2;; esac; '
        'case "$os" in linux|darwin) ;; *) echo "unsupported Go bootstrap OS: $os" >&2; exit 2;; esac; '
        f'version="${{WEAVERSSH_GO_VERSION:-{DEFAULT_GO_VERSION}}}"; '
        'archive="go${version}.${os}-${arch}.tar.gz"; '
        'url="https://go.dev/dl/${archive}"; '
        'dest="$prefix/tmp/$archive"; '
        'if command -v curl >/dev/null 2>&1; then curl -fL "$url" -o "$dest"; '
        'elif command -v python3 >/dev/null 2>&1; then python3 - "$url" "$dest" <<PY\n'
        'import sys, urllib.request\n'
        'urllib.request.urlretrieve(sys.argv[1], sys.argv[2])\n'
        'PY\n'
        'else echo "curl or python3 is required to download Go into the home prefix" >&2; exit 2; fi; '
        + rm_existing +
        'tar -C "$prefix/toolchains" -xzf "$dest"; '
        'ln -sf "$prefix/toolchains/go/bin/go" "$prefix/bin/go"; '
        '"$prefix/bin/go" version'
    )


def package_status_command(manager: str, package: str) -> list[str]:
    if manager == "apt":
        return ["dpkg-query", "-W", "-f=${Status}", package]
    if manager in ("dnf", "yum", "zypper"):
        return ["rpm", "-q", package]
    if manager == "pacman":
        return ["pacman", "-Q", package]
    if manager == "apk":
        return ["apk", "info", "-e", package]
    if manager == "brew":
        if package == "xquartz":
            return ["brew", "list", "--cask"]
        return ["brew", "list", "--versions", package]
    if manager == "winget":
        return ["winget", "list", "--id", package, "--exact"]
    if manager == "choco":
        return ["choco", "list", "--local-only", "--exact", package]
    if manager == "pkg":
        return ["pkg", "info", "-e", package]
    if manager == "pkg_add":
        return ["pkg_info", "-e", package]
    if manager == "installp":
        return ["lslpp", "-L", package]
    return []


def inspect_package_statuses(manager: str, packages: list[str]) -> list[DependencyStatus]:
    statuses: list[DependencyStatus] = []
    for package in packages:
        query = package_status_command(manager, package)
        if not query:
            statuses.append(DependencyStatus(package, False, "unknown", "no query command available", []))
            continue
        if not _which(query[0]):
            statuses.append(DependencyStatus(package, False, "unknown", f"query tool not found: {query[0]}", query))
            continue
        proc = subprocess.run(query, capture_output=True, text=True, check=False)
        text = " ".join(part.strip() for part in (proc.stdout, proc.stderr) if part.strip())
        installed = proc.returncode == 0
        if manager == "apt":
            installed = proc.returncode == 0 and "install ok installed" in proc.stdout
        elif manager == "brew" and query == ["brew", "list", "--cask"]:
            installed = proc.returncode == 0 and package.lower() in {line.strip().lower() for line in proc.stdout.splitlines()}
            text = "installed" if installed else "missing"
        elif manager in ("winget", "choco"):
            installed = proc.returncode == 0 and package.lower() in text.lower()
        state = "installed" if installed else "missing"
        statuses.append(
            DependencyStatus(
                package=package,
                installed=installed,
                state=state,
                detail=text or state,
                query_command=query,
                error="" if proc.returncode == 0 else text,
            )
        )
    return statuses


def _jsonable(payload: object) -> Any:
    if hasattr(payload, "__dataclass_fields__"):
        return asdict(payload)
    return payload


def _write_log(log_file: str | None, event: str, payload: object) -> None:
    if not log_file:
        return
    path = Path(log_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "payload": _jsonable(payload),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def _run(commands: list[list[str]], log_file: str | None = None) -> None:
    for cmd in commands:
        started = time.monotonic()
        _write_log(log_file, "command_start", {"command": cmd})
        proc = subprocess.run(cmd, check=False)
        _write_log(
            log_file,
            "command_finish",
            {
                "command": cmd,
                "exit_code": proc.returncode,
                "duration_sec": round(time.monotonic() - started, 3),
            },
        )
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "status", "install"), nargs="?", default="plan")
    parser.add_argument("--method", choices=("home", "package-manager", "auto"), default="auto", help="Install method; default auto uses home unless --manager is set")
    parser.add_argument("--home-prefix", default=DEFAULT_HOME_PREFIX, help="Home install prefix used by --method home")
    parser.add_argument("--manager", choices=("apt", "dnf", "yum", "zypper", "pacman", "apk", "brew", "winget", "choco", "pkg", "pkg_add", "installp"))
    parser.add_argument("--include-build", action="store_true", help="Include Go/build/package tooling, not only runtime dependencies")
    parser.add_argument("--yes", action="store_true", help="Use non-interactive yes flags where supported")
    parser.add_argument("--replace", action="store_true", help="Use package-manager reinstall/upgrade semantics where supported")
    parser.add_argument("--force", action="store_true", help="Add stronger package-manager replacement/upgrade flags where supported")
    parser.add_argument("--confirm-force", action="store_true", help="Required with install --force to execute forced replacement commands")
    parser.add_argument("--dry-run", action="store_true", help="With install, print and log the plan without running package-manager commands")
    parser.add_argument("--all", action="store_true", help="Target all configured packages instead of only missing/unknown packages when inspecting")
    parser.add_argument("--log-file", help="Append JSONL audit records for status and install runs")
    args = parser.parse_args()

    inspect = args.command in {"status", "install"} or args.all
    only_missing = not args.all
    plan = build_plan(
        args.manager,
        include_build=args.include_build,
        assume_yes=args.yes,
        replace=args.replace,
        force=args.force,
        inspect=inspect,
        only_missing=only_missing,
        method=args.method,
        home_prefix=args.home_prefix,
    )
    _write_log(args.log_file, args.command, plan)
    print(json.dumps(asdict(plan), indent=2, sort_keys=True))

    if args.command == "install":
        if args.dry_run:
            _write_log(args.log_file, "install_dry_run", {"commands": plan.commands})
            return 0
        if plan.install_method == "home":
            unsupported = [pkg for pkg in plan.selected_packages if pkg not in home_installable_tools()]
            if unsupported:
                _write_log(args.log_file, "home_unsupported_denied", {"packages": unsupported})
                raise SystemExit(
                    "home method cannot install these missing tools: "
                    + ", ".join(unsupported)
                    + "; install them manually or use --method package-manager"
                )
        if args.force and not args.confirm_force:
            _write_log(args.log_file, "force_denied", {"reason": "missing --confirm-force"})
            raise SystemExit("install --force requires --confirm-force")
        if not plan.commands:
            _write_log(args.log_file, "install_noop", {"reason": "no selected packages"})
            return 0
        _run(plan.commands, args.log_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
