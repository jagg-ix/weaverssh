#!/usr/bin/env python3
from __future__ import annotations

"""Build installable weaverssh OS packages from built binaries.

The packager intentionally uses only standard OS package tools when possible:
- deb: dpkg-deb
- rpm: rpmbuild
- arch: tar + zstd, with pacman .PKGINFO metadata
- apk: tar.gz with Alpine .PKGINFO metadata, installable with apk add --allow-untrusted
- pkg: pkgbuild on macOS
- freebsd-pkg: FreeBSD pkg-style archive with +MANIFEST
- tar.gz / zip: portable archives using Python stdlib

It never installs packages itself; it creates artifacts under dist/packages.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time
import zipfile
from dataclasses import dataclass, asdict
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_NAME = "weaverssh"
DEFAULT_VERSION = os.environ.get("WEAVERSSH_VERSION", "0.1.0")
DEFAULT_RELEASE = os.environ.get("WEAVERSSH_RELEASE", "1")
DEFAULT_MAINTAINER = os.environ.get("WEAVERSSH_MAINTAINER", "weaverssh maintainers <noreply@example.invalid>")
DEFAULT_URL = "https://weaverssh.com"
DESCRIPTION = "weaverssh — a user-space data bus over SSH (single unified `wv` binary)"
# Single unified binary. Everything is a `wv <command>` subcommand.
BINARIES = ("wv",)
DOC_FILES = (
    "README.md",
    "docs/weaverssh_system_components.md",
    "docs/weaverssh_component_inventory.md",
    "docs/developer_testing_and_verification.md",
    "docs/packaging/install_packages.md",
)
TOOL_FILES = (
    "tools/verification/sshx11_ops.sh",
    "tools/verification/sshx11_user_service_install.py",
    "tools/verification/sshx11_socks_fallback_service.py",
    "tools/verification/sshx11_socks_fallback_probe.py",
)
SYSTEMD_USER_UNITS = (
    "packaging/systemd/user/wv-agent.service",
    "packaging/systemd/user/wv-socks.service",
)
DEB_DEPENDS = "ca-certificates, openssh-client, xauth, python3"
RPM_REQUIRES = ("ca-certificates", "openssh-clients", "xorg-x11-xauth", "python3")
ARCH_DEPENDS = ("ca-certificates", "openssh", "xorg-xauth", "python")
APK_DEPENDS = ("ca-certificates", "openssh-client", "xauth", "python3", "tk")
FREEBSD_DEPENDS = ("ca_root_nss", "openssh-portable", "xauth")


@dataclass(frozen=True)
class PackageConfig:
    version: str
    release: str
    arch: str
    prefix: str
    binary_dir: Path
    build_dir: Path
    dist_dir: Path
    maintainer: str
    url: str


@dataclass(frozen=True)
class PackagePlan:
    format: str
    package_name: str
    version: str
    release: str
    arch: str
    prefix: str
    binary_dir: str
    output: str
    dependencies: list[str]
    files: list[str]
    required_tools: list[str]


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required packaging tool not found: {name}")
    return path


def _safe_version(version: str) -> str:
    cleaned = version.strip().lstrip("v") or DEFAULT_VERSION
    for ch in " -+/":
        cleaned = cleaned.replace(ch, ".")
    return cleaned


def _machine_arch() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "i386": "386",
        "i686": "386",
    }
    return mapping.get(machine, machine or "amd64")


def _canonical_arch(arch: str) -> str:
    normalized = arch.lower().strip()
    mapping = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "armhf": "armv7",
        "armv7hl": "armv7",
        "armv7h": "armv7",
        "i386": "386",
        "i686": "386",
        "x86": "386",
    }
    return mapping.get(normalized, normalized)


def _deb_arch(arch: str) -> str:
    arch = _canonical_arch(arch)
    return {"amd64": "amd64", "arm64": "arm64", "386": "i386", "armv7": "armhf"}.get(arch, arch)


def _rpm_arch(arch: str) -> str:
    arch = _canonical_arch(arch)
    return {"amd64": "x86_64", "arm64": "aarch64", "386": "i386", "armv7": "armv7hl"}.get(arch, arch)


def _archlinux_arch(arch: str) -> str:
    arch = _canonical_arch(arch)
    return {"amd64": "x86_64", "arm64": "aarch64", "armv7": "armv7h"}.get(arch, arch)


def _alpine_arch(arch: str) -> str:
    arch = _canonical_arch(arch)
    return {"amd64": "x86_64", "arm64": "aarch64", "386": "x86", "armv7": "armv7"}.get(arch, arch)


def _freebsd_arch(arch: str) -> str:
    arch = _canonical_arch(arch)
    return {"amd64": "amd64", "arm64": "aarch64", "386": "i386", "armv7": "armv7"}.get(arch, arch)


def _install_path(prefix: str, *parts: str) -> str:
    return str(Path(prefix.strip("/"), *parts))


def _copy_file(src: Path, dst: Path, mode: int | None = None) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    if mode is not None:
        dst.chmod(mode)


def _copy_tree_files(stage: Path, cfg: PackageConfig) -> list[str]:
    if not cfg.binary_dir.exists():
        raise FileNotFoundError(f"binary directory does not exist: {cfg.binary_dir}")

    installed: list[str] = []
    bin_dir = stage / _install_path(cfg.prefix, "bin")
    for binary in BINARIES:
        src = cfg.binary_dir / binary
        if not src.exists():
            raise FileNotFoundError(f"missing built binary {binary}: expected {src}")
        dst = bin_dir / binary
        _copy_file(src, dst, 0o755)
        installed.append("/" + str(dst.relative_to(stage)))

    doc_dir = stage / _install_path(cfg.prefix, "share", "doc", PACKAGE_NAME)
    for rel in DOC_FILES:
        src = REPO_ROOT / rel
        if src.exists():
            dst = doc_dir / Path(rel).name
            _copy_file(src, dst, 0o644)
            installed.append("/" + str(dst.relative_to(stage)))

    tool_base = stage / _install_path(cfg.prefix, "share", PACKAGE_NAME, "tools", "verification")
    for rel in TOOL_FILES:
        src = REPO_ROOT / rel
        if src.exists():
            mode = 0o755 if os.access(src, os.X_OK) or src.suffix == ".sh" else 0o644
            dst = tool_base / Path(rel).name
            _copy_file(src, dst, mode)
            installed.append("/" + str(dst.relative_to(stage)))

    systemd_dir = stage / "usr" / "lib" / "systemd" / "user"
    for rel in SYSTEMD_USER_UNITS:
        src = REPO_ROOT / rel
        if src.exists() and cfg.prefix == "/usr":
            dst = systemd_dir / Path(rel).name
            _copy_file(src, dst, 0o644)
            installed.append("/" + str(dst.relative_to(stage)))

    return sorted(installed)


def _stage_install_tree(cfg: PackageConfig, suffix: str) -> tuple[Path, list[str]]:
    stage = cfg.build_dir / f"{PACKAGE_NAME}-{cfg.version}-{suffix}-root"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    files = _copy_tree_files(stage, cfg)
    return stage, files


def _files_for_plan(cfg: PackageConfig) -> list[str]:
    files = [f"{cfg.prefix}/bin/{name}" for name in BINARIES]
    files.extend(f"{cfg.prefix}/share/doc/{PACKAGE_NAME}/{Path(rel).name}" for rel in DOC_FILES if (REPO_ROOT / rel).exists())
    files.extend(f"{cfg.prefix}/share/{PACKAGE_NAME}/tools/verification/{Path(rel).name}" for rel in TOOL_FILES if (REPO_ROOT / rel).exists())
    if cfg.prefix == "/usr":
        files.extend(f"/usr/lib/systemd/user/{Path(rel).name}" for rel in SYSTEMD_USER_UNITS if (REPO_ROOT / rel).exists())
    return sorted(files)


def build_plan(fmt: str, cfg: PackageConfig) -> PackagePlan:
    fmt = normalize_format(fmt)
    out = output_path(fmt, cfg)
    required_tools: list[str] = []
    dependencies: list[str] = []
    if fmt == "deb":
        required_tools = ["dpkg-deb"]
        dependencies = [part.strip() for part in DEB_DEPENDS.split(",")]
    elif fmt == "rpm":
        required_tools = ["rpmbuild"]
        dependencies = list(RPM_REQUIRES)
    elif fmt == "pkg":
        required_tools = ["pkgbuild"]
    elif fmt == "arch":
        required_tools = ["tar", "zstd"]
        dependencies = list(ARCH_DEPENDS)
    elif fmt == "apk":
        required_tools = []
        dependencies = list(APK_DEPENDS)
    elif fmt == "freebsd-pkg":
        required_tools = []
        dependencies = list(FREEBSD_DEPENDS)
    elif fmt == "zip":
        required_tools = []
    elif fmt == "tar.gz":
        required_tools = []
    else:
        raise ValueError(f"unsupported package format: {fmt}")
    return PackagePlan(
        format=fmt,
        package_name=PACKAGE_NAME,
        version=cfg.version,
        release=cfg.release,
        arch=cfg.arch,
        prefix=cfg.prefix,
        binary_dir=str(cfg.binary_dir),
        output=str(out),
        dependencies=dependencies,
        files=_files_for_plan(cfg),
        required_tools=required_tools,
    )


def normalize_format(fmt: str) -> str:
    fmt = fmt.lower().strip()
    aliases = {
        "tgz": "tar.gz",
        "tar": "tar.gz",
        "pacman": "arch",
        "pkg.tar.zst": "arch",
        "alpine": "apk",
        "macos-pkg": "pkg",
        "pkgng": "freebsd-pkg",
        "freebsd": "freebsd-pkg",
        "freebsd_pkg": "freebsd-pkg",
    }
    return aliases.get(fmt, fmt)


def output_path(fmt: str, cfg: PackageConfig) -> Path:
    fmt = normalize_format(fmt)
    arch = cfg.arch
    if fmt == "deb":
        return cfg.dist_dir / f"{PACKAGE_NAME}_{cfg.version}-{cfg.release}_{_deb_arch(arch)}.deb"
    if fmt == "rpm":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}.{_rpm_arch(arch)}.rpm"
    if fmt == "arch":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-{_archlinux_arch(arch)}.pkg.tar.zst"
    if fmt == "pkg":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-{arch}.pkg"
    if fmt == "apk":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-r{cfg.release}-{_alpine_arch(arch)}.apk"
    if fmt == "freebsd-pkg":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-freebsd-{_freebsd_arch(arch)}.pkg"
    if fmt == "zip":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-{arch}.zip"
    if fmt == "tar.gz":
        return cfg.dist_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-{arch}.tar.gz"
    raise ValueError(f"unsupported package format: {fmt}")


def build_deb(cfg: PackageConfig) -> Path:
    _require_tool("dpkg-deb")
    stage, files = _stage_install_tree(cfg, "deb")
    debian = stage / "DEBIAN"
    debian.mkdir(parents=True)
    installed_size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()) // 1024
    control = f"""Package: {PACKAGE_NAME}
Version: {cfg.version}-{cfg.release}
Section: net
Priority: optional
Architecture: {_deb_arch(cfg.arch)}
Maintainer: {cfg.maintainer}
Depends: {DEB_DEPENDS}
Installed-Size: {installed_size}
Homepage: {cfg.url}
Description: {DESCRIPTION}
 weaverssh provides SSH-native X11/WebSocket relay components and
 operator-facing binaries for outbound-only debugging workflows.
"""
    (debian / "control").write_text(control, encoding="utf-8")
    (debian / "postinst").write_text(_post_install_message(), encoding="utf-8")
    (debian / "postinst").chmod(0o755)
    out = output_path("deb", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    _run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(out)])
    return out


def build_rpm(cfg: PackageConfig) -> Path:
    _require_tool("rpmbuild")
    stage, _files = _stage_install_tree(cfg, "rpm-src")
    topdir = cfg.build_dir / "rpmbuild"
    for name in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / name).mkdir(parents=True, exist_ok=True)
    source_name = f"{PACKAGE_NAME}-{cfg.version}"
    source_dir = cfg.build_dir / source_name
    if source_dir.exists():
        shutil.rmtree(source_dir)
    shutil.copytree(stage, source_dir)
    source_tar = topdir / "SOURCES" / f"{source_name}.tar.gz"
    with tarfile.open(source_tar, "w:gz") as tf:
        tf.add(source_dir, arcname=source_name)
    shutil.rmtree(source_dir)

    requires = "\n".join(f"Requires: {dep}" for dep in RPM_REQUIRES)
    files = "\n".join(build_plan("rpm", cfg).files)
    spec = f"""Name: {PACKAGE_NAME}
Version: {cfg.version}
Release: {cfg.release}%{{?dist}}
Summary: {DESCRIPTION}
License: Apache-2.0
URL: {cfg.url}
BuildArch: {_rpm_arch(cfg.arch)}
{requires}

%description
weaverssh provides SSH-native X11/WebSocket relay components and operator-facing
binaries for outbound-only debugging workflows.

%prep
%setup -q

%build

%install
mkdir -p %{{buildroot}}
cp -a . %{{buildroot}}/

%post
/bin/echo "weaverssh installed. Run 'wv --help'. Use 'wv agent', 'wv proxy', 'wv share', and other wv subcommands for services."

%files
{files}
"""
    spec_path = topdir / "SPECS" / f"{PACKAGE_NAME}.spec"
    spec_path.write_text(spec, encoding="utf-8")
    _run(["rpmbuild", "--define", f"_topdir {topdir}", "-bb", str(spec_path)])
    candidates = sorted((topdir / "RPMS").rglob("*.rpm"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise RuntimeError("rpmbuild completed without producing an rpm")
    out = output_path("rpm", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidates[0], out)
    return out


def build_tar_gz(cfg: PackageConfig) -> Path:
    stage, _files = _stage_install_tree(cfg, "tar")
    out = output_path("tar.gz", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with tarfile.open(out, "w:gz") as tf:
        for path in sorted(stage.rglob("*")):
            tf.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    return out


def build_zip(cfg: PackageConfig) -> Path:
    stage, _files = _stage_install_tree(cfg, "zip")
    out = output_path("zip", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                zf.write(path, arcname=str(path.relative_to(stage)))
    return out


def build_macos_pkg(cfg: PackageConfig) -> Path:
    _require_tool("pkgbuild")
    stage, _files = _stage_install_tree(cfg, "pkg")
    out = output_path("pkg", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    _run([
        "pkgbuild",
        "--root",
        str(stage),
        "--identifier",
        "io.github.jaggix.weaverssh",
        "--version",
        cfg.version,
        "--install-location",
        "/",
        str(out),
    ])
    return out


def build_arch_pkg(cfg: PackageConfig) -> Path:
    _require_tool("tar")
    _require_tool("zstd")
    stage, _files = _stage_install_tree(cfg, "arch")
    metadata = [
        f"pkgname = {PACKAGE_NAME}",
        f"pkgbase = {PACKAGE_NAME}",
        f"pkgver = {cfg.version}-{cfg.release}",
        f"pkgdesc = {DESCRIPTION}",
        f"url = {cfg.url}",
        "builddate = " + str(int(time.time())),
        f"packager = {cfg.maintainer}",
        f"size = {sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())}",
        f"arch = {_archlinux_arch(cfg.arch)}",
        "license = custom",
    ]
    metadata.extend(f"depend = {dep}" for dep in ARCH_DEPENDS)
    (stage / ".PKGINFO").write_text("\n".join(metadata) + "\n", encoding="utf-8")
    tar_out = cfg.build_dir / f"{PACKAGE_NAME}-{cfg.version}-{cfg.release}-{_archlinux_arch(cfg.arch)}.pkg.tar"
    if tar_out.exists():
        tar_out.unlink()
    with tarfile.open(tar_out, "w") as tf:
        for path in sorted(stage.rglob("*")):
            tf.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    out = output_path("arch", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    _run(["zstd", "-q", "-f", str(tar_out), "-o", str(out)])
    return out


def build_apk(cfg: PackageConfig) -> Path:
    stage, _files = _stage_install_tree(cfg, "apk")
    metadata = [
        "# Generated by weaverssh_packager.py",
        f"pkgname = {PACKAGE_NAME}",
        f"pkgver = {cfg.version}-r{cfg.release}",
        f"pkgdesc = {DESCRIPTION}",
        f"url = {cfg.url}",
        "builddate = " + str(int(time.time())),
        f"packager = {cfg.maintainer}",
        f"size = {sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())}",
        f"arch = {_alpine_arch(cfg.arch)}",
        "license = custom",
        f"origin = {PACKAGE_NAME}",
        f"maintainer = {cfg.maintainer}",
    ]
    metadata.extend(f"depend = {dep}" for dep in APK_DEPENDS)
    (stage / ".PKGINFO").write_text("\n".join(metadata) + "\n", encoding="utf-8")
    out = output_path("apk", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with tarfile.open(out, "w:gz") as tf:
        for path in sorted(stage.rglob("*")):
            tf.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    return out


def build_freebsd_pkg(cfg: PackageConfig) -> Path:
    stage, files = _stage_install_tree(cfg, "freebsd-pkg")
    checksums: dict[str, str] = {}
    for rel in files:
        path = stage / rel.lstrip("/")
        if path.is_file():
            import hashlib

            checksums[rel] = hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "name": PACKAGE_NAME,
        "origin": f"local/{PACKAGE_NAME}",
        "version": f"{cfg.version}_{cfg.release}",
        "comment": DESCRIPTION,
        "maintainer": cfg.maintainer,
        "www": cfg.url,
        "abi": f"FreeBSD:14:{_freebsd_arch(cfg.arch)}",
        "arch": f"FreeBSD:14:{_freebsd_arch(cfg.arch)}",
        "prefix": cfg.prefix,
        "flatsize": sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()),
        "desc": "weaverssh provides SSH-native operator workflows through the wv binary.",
        "deps": {dep: {"origin": f"security/{dep}", "version": "*"} for dep in FREEBSD_DEPENDS},
        "files": checksums,
    }
    (stage / "+MANIFEST").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out = output_path("freebsd-pkg", cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with tarfile.open(out, "w:xz") as tf:
        tf.add(stage / "+MANIFEST", arcname="+MANIFEST")
        for path in sorted(stage.rglob("*")):
            if path.name == "+MANIFEST":
                continue
            tf.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    return out


def build_package(fmt: str, cfg: PackageConfig) -> Path:
    fmt = normalize_format(fmt)
    if fmt == "deb":
        return build_deb(cfg)
    if fmt == "rpm":
        return build_rpm(cfg)
    if fmt == "tar.gz":
        return build_tar_gz(cfg)
    if fmt == "zip":
        return build_zip(cfg)
    if fmt == "pkg":
        return build_macos_pkg(cfg)
    if fmt == "arch":
        return build_arch_pkg(cfg)
    if fmt == "apk":
        return build_apk(cfg)
    if fmt == "freebsd-pkg":
        return build_freebsd_pkg(cfg)
    raise ValueError(f"unsupported package format: {fmt}")


def _post_install_message() -> str:
    return """#!/bin/sh
set -e
echo "weaverssh installed. Run 'wv --help'. Use 'wv agent', 'wv proxy', 'wv share', and other wv subcommands for services."
echo "Optional user services are installed as templates under /usr/lib/systemd/user/."
exit 0
"""


def _parse_formats(raw: Iterable[str]) -> list[str]:
    out: list[str] = []
    for item in raw:
        for part in item.split(","):
            fmt = normalize_format(part)
            if fmt == "all":
                out.extend(["deb", "rpm", "tar.gz", "zip", "arch", "apk", "pkg", "freebsd-pkg"])
            elif fmt:
                out.append(fmt)
    seen: set[str] = set()
    deduped: list[str] = []
    for fmt in out:
        if fmt not in seen:
            deduped.append(fmt)
            seen.add(fmt)
    return deduped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", "-f", action="append", default=[], help="Package format: deb,rpm,tar.gz,zip,arch,apk,pkg,freebsd-pkg,all")
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--release", default=DEFAULT_RELEASE)
    parser.add_argument("--arch", default=_machine_arch())
    parser.add_argument("--prefix", default="/usr", help="Install prefix inside package; use /usr for Linux packages, /usr/local for macOS pkg")
    parser.add_argument("--binary-dir", type=Path, default=REPO_ROOT / "build" / "bin")
    parser.add_argument("--build-dir", type=Path, default=REPO_ROOT / "build" / "package")
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "packages")
    parser.add_argument("--maintainer", default=DEFAULT_MAINTAINER)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--plan", action="store_true", help="Print package plan JSON and do not build")
    args = parser.parse_args()

    cfg = PackageConfig(
        version=_safe_version(args.version),
        release=_safe_version(args.release),
        arch=args.arch,
        prefix=args.prefix.rstrip("/") or "/usr",
        binary_dir=args.binary_dir,
        build_dir=args.build_dir,
        dist_dir=args.dist_dir,
        maintainer=args.maintainer,
        url=args.url,
    )
    formats = _parse_formats(args.format or ["tar.gz"])
    plans = [build_plan(fmt, cfg) for fmt in formats]
    if args.plan:
        print(json.dumps([asdict(plan) for plan in plans], indent=2, sort_keys=True))
        return 0

    outputs: list[str] = []
    for fmt in formats:
        out = build_package(fmt, cfg)
        outputs.append(str(out))
    print(json.dumps({"ok": True, "outputs": outputs}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
