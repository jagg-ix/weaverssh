#!/usr/bin/env python3
from __future__ import annotations

"""Build Red Hat-family or SUSE-family RPM packages from a prebuilt wv binary."""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRES = {
    "redhat": ("ca-certificates", "openssh-clients", "xorg-x11-xauth", "python3"),
    "suse": ("ca-certificates", "openssh", "xauth", "python3"),
}


@dataclass(frozen=True)
class RPMPlan:
    schema: str
    family: str
    version: str
    release: str
    arch: str
    rpm_arch: str
    binary: str
    output: str
    requirements: list[str]
    required_tools: list[str]


def rpm_arch(arch: str) -> str:
    normalized = arch.strip().lower()
    return {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "386": "i386",
        "i386": "i386",
        "armv7": "armv7hl",
        "armv7hl": "armv7hl",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
        "riscv64": "riscv64",
    }.get(normalized, normalized)


def clean_version(value: str) -> str:
    value = value.strip().lstrip("v")
    if not value or any(ch.isspace() or ch in "/+" for ch in value):
        raise ValueError(f"invalid RPM version: {value!r}")
    return value


def make_plan(family: str, version: str, release: str, arch: str, binary_dir: Path, dist_dir: Path) -> RPMPlan:
    family = family.strip().lower()
    if family not in REQUIRES:
        raise ValueError("RPM family must be redhat or suse")
    version = clean_version(version)
    release = release.strip()
    if not release or any(ch.isspace() or ch in "/+" for ch in release):
        raise ValueError(f"invalid RPM release: {release!r}")
    binary = binary_dir / "wv"
    out = dist_dir / f"weaverssh-{version}-{release}.{rpm_arch(arch)}.rpm"
    return RPMPlan(
        schema="weaverssh.rpm-build-plan.v1",
        family=family,
        version=version,
        release=release,
        arch=arch,
        rpm_arch=rpm_arch(arch),
        binary=str(binary),
        output=str(out),
        requirements=list(REQUIRES[family]),
        required_tools=["rpmbuild"],
    )


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required packaging tool not found: {name}")
    return path


def copy_docs(stage: Path) -> None:
    doc_dir = stage / "usr" / "share" / "doc" / "weaverssh"
    doc_dir.mkdir(parents=True, exist_ok=True)
    for rel in ("README.md", "docs/packaging/cross-platform-source-builds.md"):
        src = REPO_ROOT / rel
        if src.exists():
            shutil.copy2(src, doc_dir / src.name)


def build(plan: RPMPlan, build_dir: Path) -> Path:
    require_tool("rpmbuild")
    binary = Path(plan.binary)
    if not binary.is_file():
        raise FileNotFoundError(f"missing built wv binary: {binary}")

    topdir = build_dir / f"rpmbuild-{plan.family}-{plan.rpm_arch}"
    if topdir.exists():
        shutil.rmtree(topdir)
    for name in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / name).mkdir(parents=True, exist_ok=True)

    source_name = f"weaverssh-{plan.version}"
    source_root = build_dir / source_name
    if source_root.exists():
        shutil.rmtree(source_root)
    (source_root / "usr" / "bin").mkdir(parents=True)
    shutil.copy2(binary, source_root / "usr" / "bin" / "wv")
    (source_root / "usr" / "bin" / "wv").chmod(0o755)
    copy_docs(source_root)

    source_tar = topdir / "SOURCES" / f"{source_name}.tar.gz"
    with tarfile.open(source_tar, "w:gz") as archive:
        archive.add(source_root, arcname=source_name)
    shutil.rmtree(source_root)

    requirements = "\n".join(f"Requires: {item}" for item in plan.requirements)
    spec = f"""Name: weaverssh
Version: {plan.version}
Release: {plan.release}%{{?dist}}
Summary: User-space data bus over SSH
License: Apache-2.0
URL: https://github.com/jagg-ix/weaverssh
Source0: %{{name}}-%{{version}}.tar.gz
BuildArch: {plan.rpm_arch}
{requirements}

%description
WeaverSSH provides an SSH-native, user-space data bus with routed filesystem,
network, event, and policy-named execution services.

%prep
%setup -q

%build

%install
rm -rf %{{buildroot}}
cp -a usr %{{buildroot}}/

%files
/usr/bin/wv
/usr/share/doc/weaverssh/*

%post
/bin/echo "WeaverSSH installed. Run: wv --help"
"""
    spec_path = topdir / "SPECS" / "weaverssh.spec"
    spec_path.write_text(spec, encoding="utf-8")
    subprocess.run(["rpmbuild", "--define", f"_topdir {topdir}", "-bb", str(spec_path)], cwd=REPO_ROOT, check=True)
    candidates = sorted((topdir / "RPMS").rglob("*.rpm"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not candidates:
        raise RuntimeError("rpmbuild completed without producing an RPM")
    output = Path(plan.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidates[0], output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--family", choices=sorted(REQUIRES), required=True)
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--release", default="1")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=REPO_ROOT / "build" / "packages")
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "packages")
    args = parser.parse_args()
    plan = make_plan(args.family, args.version, args.release, args.arch, args.binary_dir, args.dist_dir)
    if args.command == "plan":
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        return 0
    output = build(plan, args.build_dir)
    print(json.dumps({"ok": True, "output": str(output)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
