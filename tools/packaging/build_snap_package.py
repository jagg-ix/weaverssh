#!/usr/bin/env python3
from __future__ import annotations

"""Generate and optionally build a Snap package project for weaverssh.

The Snap project consumes an already-built Linux `wv` binary. That keeps Snap
packaging aligned with the single-binary runtime model and avoids requiring the
Snap build to understand the whole repository layout.
"""

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_NAME = "weaverssh"
DEFAULT_VERSION = "0.1.0"
DEFAULT_RELEASE = "1"
DEFAULT_SUMMARY = "weaverssh user-space data bus over SSH"
DEFAULT_DESCRIPTION = """weaverssh provides a single wv binary for SSH-native
connectivity, X11/WebSocket relay workflows, user-space service plugins, and
profile-driven deployment helpers."""
DEFAULT_BASE = "core24"
DEFAULT_CONFINEMENT = "strict"
DEFAULT_GRADE = "stable"
DEFAULT_PROJECT_DIR = "dist/snap/weaverssh"
DEFAULT_DIST_DIR = "dist/snap"
DEFAULT_PLUGS = ("home", "network", "network-bind", "removable-media", "ssh-keys", "x11")


@dataclass(frozen=True)
class SnapPlan:
    name: str
    version: str
    release: str
    snap_version: str
    arch: str
    snap_arch: str
    base: str
    confinement: str
    grade: str
    binary: str
    project_dir: str
    output: str
    plugs: list[str]
    apps: list[str]
    required_tools: list[str]
    build_command: list[str]


def canonical_arch(arch: str) -> str:
    normalized = arch.strip().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armhf": "armv7",
        "armv7": "armv7",
        "armv7h": "armv7",
        "armv7hl": "armv7",
        "i386": "386",
        "i686": "386",
        "x86": "386",
        "ppc64el": "ppc64le",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
        "riscv64": "riscv64",
    }
    return mapping.get(normalized, normalized or "amd64")


def snap_arch(arch: str) -> str:
    canonical = canonical_arch(arch)
    mapping = {
        "amd64": "amd64",
        "arm64": "arm64",
        "armv7": "armhf",
        "386": "i386",
        "ppc64le": "ppc64el",
        "s390x": "s390x",
        "riscv64": "riscv64",
    }
    if canonical not in mapping:
        raise ValueError(f"unsupported Snap architecture: {arch}")
    return mapping[canonical]


def safe_version(version: str, release: str) -> str:
    value = f"{version.strip().lstrip('v') or DEFAULT_VERSION}-{release.strip() or DEFAULT_RELEASE}"
    return value.replace(" ", ".").replace("/", ".").replace("+", ".")


def yaml_scalar(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_snapcraft_yaml(plan: SnapPlan, *, summary: str, description: str) -> str:
    lines = [
        f"name: {plan.name}",
        f"base: {plan.base}",
        f"version: {yaml_scalar(plan.snap_version)}",
        f"summary: {yaml_scalar(summary)}",
        "description: |",
    ]
    for line in description.strip().splitlines():
        lines.append(f"  {line.rstrip()}")
    lines.extend(
        [
            f"grade: {plan.grade}",
            f"confinement: {plan.confinement}",
            "architectures:",
            f"  - build-on: {plan.snap_arch}",
            f"    build-for: {plan.snap_arch}",
            "apps:",
            "  wv:",
            "    command: bin/wv",
        ]
    )
    if plan.plugs:
        lines.append("    plugs:")
        for plug in plan.plugs:
            lines.append(f"      - {plug}")
    lines.extend(
        [
            "parts:",
            "  weaverssh:",
            "    plugin: dump",
            "    source: payload",
            "",
        ]
    )
    return "\n".join(lines)


def build_plan(
    *,
    binary: Path,
    project_dir: Path,
    dist_dir: Path,
    name: str,
    version: str,
    release: str,
    arch: str,
    base: str,
    confinement: str,
    grade: str,
    plugs: list[str],
    snapcraft: str,
) -> SnapPlan:
    normalized_arch = canonical_arch(arch)
    mapped_snap_arch = snap_arch(normalized_arch)
    snap_version = safe_version(version, release)
    output = dist_dir / f"{name}_{snap_version}_{mapped_snap_arch}.snap"
    return SnapPlan(
        name=name,
        version=version,
        release=release,
        snap_version=snap_version,
        arch=normalized_arch,
        snap_arch=mapped_snap_arch,
        base=base,
        confinement=confinement,
        grade=grade,
        binary=str(binary),
        project_dir=str(project_dir),
        output=str(output),
        plugs=plugs,
        apps=["wv"],
        required_tools=[snapcraft],
        build_command=[snapcraft, "pack", str(project_dir), "--output", str(output)],
    )


def write_project(plan: SnapPlan, *, summary: str, description: str) -> None:
    binary = Path(plan.binary)
    if not binary.exists():
        raise FileNotFoundError(f"wv binary not found: {binary}")
    project_dir = Path(plan.project_dir)
    snap_dir = project_dir / "snap"
    payload_bin = project_dir / "payload" / "bin"
    snap_dir.mkdir(parents=True, exist_ok=True)
    payload_bin.mkdir(parents=True, exist_ok=True)

    shutil.copy2(binary, payload_bin / "wv")
    os.chmod(payload_bin / "wv", 0o755)
    (snap_dir / "snapcraft.yaml").write_text(render_snapcraft_yaml(plan, summary=summary, description=description), encoding="utf-8")
    (project_dir / "README.md").write_text(
        "# weaverssh Snap project\n\n"
        "This directory is generated by tools/packaging/build_snap_package.py.\n"
        "It contains a binary payload and snap/snapcraft.yaml for building a .snap.\n\n"
        "Build manually with:\n\n"
        f"    {' '.join(plan.build_command)}\n",
        encoding="utf-8",
    )


def run_build(plan: SnapPlan) -> None:
    tool = shutil.which(plan.required_tools[0])
    if not tool:
        raise RuntimeError(f"required Snap build tool not found: {plan.required_tools[0]}")
    output = Path(plan.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [tool, *plan.build_command[1:]]
    subprocess.run(command, check=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate and optionally build a weaverssh Snap project")
    parser.add_argument("--binary", required=True, help="Path to the Linux wv binary to place in the Snap payload")
    parser.add_argument("--project-dir", default=DEFAULT_PROJECT_DIR)
    parser.add_argument("--dist-dir", default=DEFAULT_DIST_DIR)
    parser.add_argument("--name", default=DEFAULT_NAME)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--release", default=DEFAULT_RELEASE)
    parser.add_argument("--arch", default="amd64", help="Go/package architecture, for example amd64, arm64, armv7")
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--confinement", choices=("strict", "classic", "devmode"), default=DEFAULT_CONFINEMENT)
    parser.add_argument("--grade", choices=("stable", "devel"), default=DEFAULT_GRADE)
    parser.add_argument("--summary", default=DEFAULT_SUMMARY)
    parser.add_argument("--description", default=DEFAULT_DESCRIPTION)
    parser.add_argument("--plug", action="append", help="Add an app plug. Defaults are used unless --no-default-plugs is set")
    parser.add_argument("--no-default-plugs", action="store_true")
    parser.add_argument("--snapcraft", default="snapcraft")
    parser.add_argument("--plan", action="store_true", help="Print JSON plan without writing files")
    parser.add_argument("--build", action="store_true", help="Run snapcraft pack after generating the project")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    plugs = [] if args.no_default_plugs else list(DEFAULT_PLUGS)
    for plug in args.plug or []:
        if plug not in plugs:
            plugs.append(plug)
    try:
        plan = build_plan(
            binary=Path(args.binary),
            project_dir=Path(args.project_dir),
            dist_dir=Path(args.dist_dir),
            name=args.name,
            version=args.version,
            release=args.release,
            arch=args.arch,
            base=args.base,
            confinement=args.confinement,
            grade=args.grade,
            plugs=plugs,
            snapcraft=args.snapcraft,
        )
        if args.plan:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        write_project(plan, summary=args.summary, description=args.description)
        if args.build:
            run_build(plan)
        print(json.dumps({**asdict(plan), "written": str(Path(plan.project_dir) / "snap" / "snapcraft.yaml")}, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        raise SystemExit(f"error: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
