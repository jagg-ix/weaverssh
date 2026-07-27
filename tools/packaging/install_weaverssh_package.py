#!/usr/bin/env python3
from __future__ import annotations

"""Plan or run OS-native installation commands for a built weaverssh package."""

import argparse
import json
import os
from pathlib import Path
import subprocess
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class PackageInstallPlan:
    package: str
    format: str
    platform: str
    commands: list[list[str]]
    requires_privilege: bool
    notes: list[str]


def _needs_sudo() -> bool:
    return os.geteuid() != 0 if hasattr(os, "geteuid") else True


def detect_format(package: Path) -> str:
    name = package.name.lower()
    if name.endswith(".pkg.tar.zst") or name.endswith(".pkg.tar.xz") or name.endswith(".pkg.tar.gz"):
        return "arch"
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "tar.gz"
    if name.endswith(".deb"):
        return "deb"
    if name.endswith(".rpm"):
        return "rpm"
    if name.endswith(".apk"):
        return "apk"
    if name.endswith(".pkg"):
        if "freebsd" in name or "pkgng" in name:
            return "freebsd-pkg"
        return "pkg"
    if name.endswith(".msi"):
        return "msi"
    if name.endswith(".zip"):
        return "zip"
    raise ValueError(f"unsupported package artifact extension: {package}")


def target_platform(fmt: str) -> str:
    if fmt in ("deb", "rpm", "arch", "apk"):
        return "linux"
    if fmt == "pkg":
        return "darwin"
    if fmt == "freebsd-pkg":
        return "freebsd"
    if fmt == "msi":
        return "windows"
    return "portable"


def _rooted_path(target_root: str, *parts: str) -> str:
    root = Path(target_root)
    if target_root == "/":
        return str(Path("/", *parts))
    return str(root.joinpath(*parts))


def build_plan(
    package: Path,
    target_root: str = "/",
    extract_dir: Path = Path("/tmp/weaverssh-install"),
    manager: str | None = None,
) -> PackageInstallPlan:
    fmt = detect_format(package)
    system = target_platform(fmt)
    package_arg = str(package)
    sudo = ["sudo"] if _needs_sudo() and system != "windows" else []
    notes: list[str] = []
    commands: list[list[str]]

    if fmt == "deb":
        chosen = manager or "apt"
        if chosen == "apt":
            commands = [[*sudo, "apt-get", "install", "-y", package_arg]]
        elif chosen == "dpkg":
            commands = [[*sudo, "dpkg", "-i", package_arg]]
            notes.append("dpkg does not resolve missing dependencies; run apt-get -f install if needed.")
        else:
            raise ValueError(f"unsupported manager for deb package: {chosen}")
    elif fmt == "rpm":
        chosen = manager or "dnf"
        if chosen == "dnf":
            commands = [[*sudo, "dnf", "install", "-y", package_arg]]
        elif chosen == "yum":
            commands = [[*sudo, "yum", "localinstall", "-y", package_arg]]
        elif chosen == "zypper":
            commands = [[*sudo, "zypper", "install", "-y", package_arg]]
        elif chosen == "rpm":
            commands = [[*sudo, "rpm", "-Uvh", package_arg]]
            notes.append("rpm does not resolve missing dependencies; prefer dnf, yum, or zypper when available.")
        else:
            raise ValueError(f"unsupported manager for rpm package: {chosen}")
    elif fmt == "arch":
        commands = [[*sudo, "pacman", "-U", "--noconfirm", package_arg]]
    elif fmt == "apk":
        commands = [[*sudo, "apk", "add", "--allow-untrusted", package_arg]]
        notes.append("Unsigned local APKs require --allow-untrusted unless signed by a trusted Alpine key.")
    elif fmt == "pkg":
        commands = [[*sudo, "installer", "-pkg", package_arg, "-target", target_root]]
    elif fmt == "freebsd-pkg":
        chosen = manager or "pkg"
        if chosen != "pkg":
            raise ValueError(f"unsupported manager for FreeBSD pkg package: {chosen}")
        commands = [[*sudo, "pkg", "add", package_arg]]
        notes.append("FreeBSD packages should be signed or installed from a trusted local repository for production use.")
    elif fmt == "msi":
        commands = [["msiexec", "/i", package_arg, "/qn"]]
        notes.append("Run from an elevated Windows shell when installing system-wide.")
    elif fmt == "tar.gz":
        commands = [[*sudo, "tar", "-C", target_root, "-xzf", package_arg]]
        notes.append("Portable archives are not tracked by the OS package database.")
    elif fmt == "zip":
        commands = [
            ["python3", "-m", "zipfile", "-e", package_arg, str(extract_dir)],
            [*sudo, "cp", "-a", str(extract_dir / "usr") + "/.", _rooted_path(target_root, "usr")],
        ]
        notes.append("Portable archives are not tracked by the OS package database.")
    else:
        raise ValueError(f"unsupported package artifact format: {fmt}")

    return PackageInstallPlan(
        package=package_arg,
        format=fmt,
        platform=system,
        commands=commands,
        requires_privilege=bool(sudo) or fmt in ("msi",),
        notes=notes,
    )


def run_plan(plan: PackageInstallPlan) -> None:
    for cmd in plan.commands:
        subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("positionals", nargs="*", metavar="command/package", help="Use '[plan|install] <artifact>' or just '<artifact>'")
    parser.add_argument("--target-root", default="/", help="Target root for macOS pkg and portable archive installs")
    parser.add_argument("--extract-dir", type=Path, default=Path("/tmp/weaverssh-install"), help="Temporary extraction dir for zip archives")
    parser.add_argument("--manager", choices=("apt", "dpkg", "dnf", "yum", "zypper", "rpm", "pkg"), help="Override package installer command family")
    args, extras = parser.parse_known_args()
    if any(extra.startswith("-") for extra in extras):
        parser.error("unrecognized arguments: " + " ".join(extras))
    positionals = [*args.positionals, *extras]

    if not positionals:
        raise SystemExit("usage: install_weaverssh_package.py [plan|install] <artifact>")

    if positionals[0] in ("plan", "install"):
        command = positionals[0]
        if len(positionals) != 2:
            raise SystemExit("usage: install_weaverssh_package.py [plan|install] <artifact>")
        package = Path(positionals[1])
    else:
        command = "plan"
        if len(positionals) != 1:
            raise SystemExit("usage: install_weaverssh_package.py [plan|install] <artifact>")
        package = Path(positionals[0])

    if command == "install" and not package.exists():
        raise SystemExit(f"package artifact does not exist: {package}")

    plan = build_plan(package, target_root=args.target_root, extract_dir=args.extract_dir, manager=args.manager)
    print(json.dumps(asdict(plan), indent=2, sort_keys=True))
    if command == "install":
        run_plan(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
