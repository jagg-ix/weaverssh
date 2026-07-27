#!/usr/bin/env python3
from __future__ import annotations

"""Detect a host/build target and drive WeaverSSH source builds and native packages.

This is an orchestration layer over the repository's existing matrix builder and
package generators. It does not install dependencies or mutate the host package
manager. Use the existing dependency planner before executing a build.
"""

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform as host_platform
import subprocess
import sys
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPO_ROOT / "tools" / "packaging" / "build_weaverssh_matrix.py"
PACKAGER = REPO_ROOT / "tools" / "packaging" / "weaverssh_packager.py"
RPM_BUILDER = REPO_ROOT / "tools" / "packaging" / "build_rpm_package.py"
WINDOWS_BUILDER = REPO_ROOT / "tools" / "packaging" / "build_windows_package.py"
PYTHON_COMMAND = os.environ.get("PYTHON", sys.executable or "python3")

DEBIAN_IDS = {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
REDHAT_IDS = {"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"}
SUSE_IDS = {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "suse"}
ARCH_IDS = {"arch", "manjaro", "endeavouros", "garuda"}


@dataclass(frozen=True)
class SourceBuildPlan:
    schema: str
    host_platform: str
    target_platform: str
    flavor: str
    distro: str
    distro_like: list[str]
    arch: str
    go_target: str
    build_dir: str
    binary_dir: str
    package_family: str
    package_format: str
    package_output_hint: str
    dependency_plan_command: list[str]
    build_command: list[str]
    package_command: list[str]
    notes: list[str]


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def _is_wsl(env: Mapping[str, str], release_text: str = "") -> bool:
    if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return True
    return "microsoft" in release_text.lower() or "wsl" in release_text.lower()


def normalize_platform(value: str, env: Mapping[str, str] | None = None) -> tuple[str, str]:
    env = env or os.environ
    raw = value.strip().lower()
    if not raw or raw == "auto":
        raw = host_platform.system().lower()
    aliases = {
        "darwin": "darwin",
        "mac": "darwin",
        "macos": "darwin",
        "osx": "darwin",
        "win32": "windows",
        "msys": "windows",
        "cygwin": "windows",
        "linux": "linux",
        "freebsd": "freebsd",
        "wsl": "linux",
    }
    normalized = aliases.get(raw, raw)
    flavor = "native"
    if raw == "wsl":
        flavor = "wsl"
    elif normalized == "linux" and _is_wsl(env, host_platform.release()):
        flavor = "wsl"
    return normalized, flavor


def normalize_arch(value: str) -> str:
    raw = (value or host_platform.machine()).strip().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "i386": "386",
        "i686": "386",
        "x86": "386",
        "armv7l": "armv7",
        "armv7": "armv7",
    }
    return mapping.get(raw, raw)


def parse_distro(override: str, os_release: Mapping[str, str]) -> tuple[str, list[str]]:
    distro = override.strip().lower() or os_release.get("ID", "").strip().lower()
    distro_like = [item for item in os_release.get("ID_LIKE", "").strip().lower().split() if item]
    return distro or "unknown", distro_like


def distro_family(platform_name: str, distro: str, distro_like: Sequence[str]) -> tuple[str, str]:
    if platform_name == "darwin":
        return "macos", "pkg"
    if platform_name == "windows":
        return "windows", "zip"
    if platform_name == "freebsd":
        return "freebsd", "freebsd-pkg"
    if platform_name != "linux":
        return "portable", "tar.gz"

    ids = {distro, *distro_like}
    if ids & DEBIAN_IDS:
        return "debian", "deb"
    if ids & REDHAT_IDS:
        return "redhat", "rpm"
    if ids & SUSE_IDS:
        return "suse", "rpm"
    if ids & ARCH_IDS:
        return "archlinux", "arch"
    return "portable-linux", "tar.gz+zip"


def go_target(platform_name: str, arch: str) -> str:
    if arch == "armv7":
        return f"{platform_name}/arm/v7"
    return f"{platform_name}/{arch}"


def build_dir_label(platform_name: str, arch: str) -> str:
    return f"{platform_name}-{arch}"


def package_output_hint(family: str, version: str, release: str, arch: str) -> str:
    safe_version = version.lstrip("v")
    if family == "debian":
        deb_arch = {"386": "i386", "armv7": "armhf"}.get(arch, arch)
        return f"dist/packages/weaverssh_{safe_version}-{release}_{deb_arch}.deb"
    if family in {"redhat", "suse"}:
        rpm_arch = {"amd64": "x86_64", "arm64": "aarch64", "386": "i386", "armv7": "armv7hl"}.get(arch, arch)
        return f"dist/packages/weaverssh-{safe_version}-{release}.{rpm_arch}.rpm"
    if family == "archlinux":
        pac_arch = {"amd64": "x86_64", "arm64": "aarch64", "armv7": "armv7h"}.get(arch, arch)
        return f"dist/packages/weaverssh-{safe_version}-{release}-{pac_arch}.pkg.tar.zst"
    if family == "freebsd":
        return f"dist/packages/weaverssh-{safe_version}-{release}-freebsd-{arch}.pkg"
    if family == "macos":
        return f"dist/packages/weaverssh-{safe_version}-{release}-{arch}.pkg"
    if family == "windows":
        return f"dist/packages/weaverssh-{safe_version}-{release}-windows-{arch}.zip"
    return f"dist/packages/weaverssh-{safe_version}-{release}-{arch}.tar.gz"


def dependency_plan(platform_name: str, flavor: str, family: str) -> list[str]:
    platform_arg = "wsl" if flavor == "wsl" else {
        "darwin": "macos",
        "windows": "windows",
        "freebsd": "freebsd",
    }.get(platform_name, "linux")
    return [PYTHON_COMMAND, "tools/packaging/linux_setup.py", "plan", "--platform", platform_arg, "--include-build"]


def build_command(target: str, security_profile: str, build_dir: Path) -> list[str]:
    return [
        PYTHON_COMMAND,
        "tools/packaging/build_weaverssh_matrix.py",
        "build",
        "--target",
        target,
        "--security-profile",
        security_profile,
        "--build-dir",
        str(build_dir),
    ]


def package_command(
    family: str,
    package_format: str,
    binary_dir: Path,
    version: str,
    release: str,
    arch: str,
    dist_dir: Path,
) -> list[str]:
    common = ["--version", version, "--release", release, "--arch", arch, "--binary-dir", str(binary_dir), "--dist-dir", str(dist_dir)]
    if family == "windows":
        return [PYTHON_COMMAND, str(WINDOWS_BUILDER.relative_to(REPO_ROOT)), "build", *common]
    if family in {"redhat", "suse"}:
        return [PYTHON_COMMAND, str(RPM_BUILDER.relative_to(REPO_ROOT)), "build", "--family", family, *common]
    prefix = "/usr/local" if family in {"macos", "freebsd"} else "/usr"
    formats = [package_format]
    if family == "portable-linux":
        formats = ["tar.gz", "zip"]
    cmd = [PYTHON_COMMAND, str(PACKAGER.relative_to(REPO_ROOT))]
    for fmt in formats:
        cmd.extend(["--format", fmt])
    cmd.extend(["--version", version, "--release", release, "--arch", arch, "--prefix", prefix, "--binary-dir", str(binary_dir), "--dist-dir", str(dist_dir)])
    return cmd


def make_plan(
    *,
    platform_name: str = "auto",
    distro_override: str = "",
    arch: str = "",
    version: str = "0.1.0",
    release: str = "1",
    security_profile: str = "hardened",
    build_dir: Path = REPO_ROOT / "build",
    dist_dir: Path = REPO_ROOT / "dist" / "packages",
    env: Mapping[str, str] | None = None,
    os_release: Mapping[str, str] | None = None,
) -> SourceBuildPlan:
    env = env or os.environ
    target_platform, flavor = normalize_platform(platform_name, env)
    target_arch = normalize_arch(arch)
    release_data = dict(os_release) if os_release is not None else _read_os_release()
    distro, distro_like = parse_distro(distro_override, release_data)
    family, package_format = distro_family(target_platform, distro, distro_like)
    target = go_target(target_platform, target_arch)
    binary_dir = build_dir / build_dir_label(target_platform, target_arch)
    notes: list[str] = []
    host = host_platform.system().lower()
    if flavor == "wsl":
        notes.append("WSL uses the Linux Go target and the package family of its installed distribution.")
    if target_platform == "darwin" and host != "darwin":
        notes.append("The Go binary can be cross-compiled, but macOS .pkg creation requires pkgbuild on macOS.")
    if target_platform == "windows":
        notes.append("The package is a source-built zip containing wv.exe plus PowerShell install and uninstall scripts.")
    if family == "portable-linux":
        notes.append("Unknown Linux distribution: generate portable tar.gz and zip archives instead of a distro-specific package.")
    return SourceBuildPlan(
        schema="weaverssh.source-build-plan.v1",
        host_platform=host,
        target_platform=target_platform,
        flavor=flavor,
        distro=distro,
        distro_like=distro_like,
        arch=target_arch,
        go_target=target,
        build_dir=str(build_dir),
        binary_dir=str(binary_dir),
        package_family=family,
        package_format=package_format,
        package_output_hint=package_output_hint(family, version, release, target_arch),
        dependency_plan_command=dependency_plan(target_platform, flavor, family),
        build_command=build_command(target, security_profile, build_dir),
        package_command=package_command(family, package_format, binary_dir, version, release, target_arch, dist_dir),
        notes=notes,
    )


def run_command(command: Sequence[str]) -> None:
    subprocess.run(list(command), cwd=REPO_ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build", "package", "all"), nargs="?", default="plan")
    parser.add_argument("--platform", default="auto", help="auto, linux, wsl, darwin/osx, windows, or freebsd")
    parser.add_argument("--distro", default="", help="Linux distribution ID override")
    parser.add_argument("--arch", default="", help="amd64, arm64, 386, armv7, or another Go architecture")
    parser.add_argument("--version", default=os.environ.get("WEAVERSSH_VERSION", "0.1.0"))
    parser.add_argument("--release", default=os.environ.get("WEAVERSSH_RELEASE", "1"))
    parser.add_argument("--security-profile", choices=("hardened", "compat", "debug"), default="hardened")
    parser.add_argument("--build-dir", type=Path, default=REPO_ROOT / "build")
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "packages")
    parser.add_argument("--execute", action="store_true", help="execute the selected build/package command")
    args = parser.parse_args()

    plan = make_plan(
        platform_name=args.platform,
        distro_override=args.distro,
        arch=args.arch,
        version=args.version,
        release=args.release,
        security_profile=args.security_profile,
        build_dir=args.build_dir,
        dist_dir=args.dist_dir,
    )
    if args.command == "plan" or not args.execute:
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        if args.command != "plan" and not args.execute:
            print("source_build.py: execution requires --execute", file=sys.stderr)
            return 2
        return 0

    if args.command in {"build", "all"}:
        run_command(plan.build_command)
    if args.command in {"package", "all"}:
        binary = Path(plan.binary_dir) / ("wv.exe" if plan.target_platform == "windows" else "wv")
        if not binary.exists():
            raise SystemExit(f"built binary not found: {binary}; run the build command first")
        run_command(plan.package_command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
