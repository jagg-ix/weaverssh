#!/usr/bin/env python3
from __future__ import annotations

"""Build weaverssh binaries for maintained OS/architecture target sets.

The default hardened profile uses reproducible/release-oriented Go flags and
adds PIE where Go supports it for ASLR-friendly binaries.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
from dataclasses import dataclass, asdict
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARIES = (
    ("wv", "./cmd/wv"),
    ("wv-server", "./cmd/wv-server"),
    ("wv-client", "./cmd/wv-client"),
    ("wv-agent", "./cmd/wv-agent"),
    ("wv-socks", "./cmd/wv-socks"),
    ("wv-9p", "./cmd/wv-9p"),
    ("wv-native-forward", "./cmd/wv-native-forward"),
)
PIE_TARGETS = frozenset(
    {
        "linux/amd64",
        "linux/arm64",
        "linux/ppc64le",
        "darwin/amd64",
        "darwin/arm64",
        "windows/386",
        "windows/amd64",
        "windows/arm64",
    }
)
PRESETS: dict[str, tuple[str, ...]] = {
    "linux-major": (
        "linux/amd64",
        "linux/arm64",
        "linux/arm/v7",
        "linux/386",
        "linux/ppc64le",
        "linux/s390x",
        "linux/riscv64",
    ),
    "darwin-major": (
        "darwin/amd64",
        "darwin/arm64",
    ),
    "windows-major": (
        "windows/amd64",
        "windows/arm64",
        "windows/386",
    ),
    "freebsd-major": (
        "freebsd/amd64",
        "freebsd/arm64",
    ),
    "openbsd-major": (
        "openbsd/amd64",
        "openbsd/arm64",
    ),
}
PRESETS["major"] = (
    *PRESETS["linux-major"],
    *PRESETS["darwin-major"],
    *PRESETS["windows-major"],
    *PRESETS["freebsd-major"],
    *PRESETS["openbsd-major"],
)


@dataclass(frozen=True)
class BuildTarget:
    spec: str
    goos: str
    goarch: str
    goarm: str
    label: str
    package_arch: str


@dataclass(frozen=True)
class BinaryPlan:
    name: str
    package: str
    output: str


@dataclass(frozen=True)
class TargetPlan:
    target: BuildTarget
    output_dir: str
    security_profile: str
    build_flags: list[str]
    pie_enabled: bool
    binaries: list[BinaryPlan]


def parse_target(spec: str) -> BuildTarget:
    parts = [part for part in spec.strip().split("/") if part]
    if len(parts) not in (2, 3):
        raise ValueError(f"target must be GOOS/GOARCH or GOOS/GOARCH/vN: {spec}")
    goos, goarch = parts[0], parts[1]
    goarm = ""
    if len(parts) == 3:
        if goarch != "arm" or not parts[2].startswith("v"):
            raise ValueError(f"third target component is only supported as arm variant vN: {spec}")
        goarm = parts[2][1:]
    label_arch = f"armv{goarm}" if goarch == "arm" and goarm else goarch
    package_arch = label_arch
    return BuildTarget(
        spec="/".join(parts),
        goos=goos,
        goarch=goarch,
        goarm=goarm,
        label=f"{goos}-{label_arch}",
        package_arch=package_arch,
    )


def expand_targets(presets: Iterable[str], targets: Iterable[str]) -> list[BuildTarget]:
    specs: list[str] = []
    for preset in presets:
        if preset not in PRESETS:
            raise ValueError(f"unknown target preset {preset}; choose one of {', '.join(sorted(PRESETS))}")
        specs.extend(PRESETS[preset])
    for item in targets:
        specs.extend(part.strip() for part in item.split(",") if part.strip())
    if not specs:
        specs.extend(PRESETS["major"])

    seen: set[str] = set()
    out: list[BuildTarget] = []
    for spec in specs:
        target = parse_target(spec)
        key = target.spec
        if key not in seen:
            out.append(target)
            seen.add(key)
    return out


def binary_output_name(target: BuildTarget, name: str) -> str:
    return f"{name}.exe" if target.goos == "windows" else name


def supports_pie(target: BuildTarget) -> bool:
    return target.spec in PIE_TARGETS


def security_build_flags(target: BuildTarget, profile: str) -> tuple[list[str], bool]:
    if profile == "debug":
        return [], False
    if profile not in ("compat", "hardened"):
        raise ValueError(f"unknown security profile: {profile}")

    flags = ["-trimpath", "-buildvcs=false", "-ldflags=-s -w"]
    pie_enabled = profile == "hardened" and supports_pie(target)
    if pie_enabled:
        flags.append("-buildmode=pie")
    return flags, pie_enabled


def build_plan(target: BuildTarget, build_dir: Path, security_profile: str = "hardened") -> TargetPlan:
    output_dir = build_dir / target.label
    flags, pie_enabled = security_build_flags(target, security_profile)
    binaries = [
        BinaryPlan(name=name, package=pkg, output=str(output_dir / binary_output_name(target, name)))
        for name, pkg in BINARIES
    ]
    return TargetPlan(
        target=target,
        output_dir=str(output_dir),
        security_profile=security_profile,
        build_flags=flags,
        pie_enabled=pie_enabled,
        binaries=binaries,
    )


def run_build(plan: TargetPlan, go_cmd: str, cgo_enabled: str) -> None:
    target = plan.target
    output_dir = Path(plan.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOOS"] = target.goos
    env["GOARCH"] = target.goarch
    env["CGO_ENABLED"] = cgo_enabled
    if target.goarm:
        env["GOARM"] = target.goarm
    else:
        env.pop("GOARM", None)

    for binary in plan.binaries:
        subprocess.run(
            [go_cmd, "build", *plan.build_flags, "-o", binary.output, binary.package],
            cwd=str(REPO_ROOT),
            env=env,
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--preset", action="append", default=[], help=f"Target preset: {', '.join(sorted(PRESETS))}")
    parser.add_argument("--target", action="append", default=[], help="Explicit target such as linux/amd64, linux/arm/v7, or comma-separated list")
    parser.add_argument("--build-dir", type=Path, default=REPO_ROOT / "build")
    parser.add_argument("--go", default="go")
    parser.add_argument("--cgo-enabled", default="0")
    parser.add_argument("--security-profile", choices=("hardened", "compat", "debug"), default="hardened")
    args = parser.parse_args()

    targets = expand_targets(args.preset, args.target)
    plans = [build_plan(target, args.build_dir, args.security_profile) for target in targets]
    if args.command == "plan":
        print(json.dumps([asdict(plan) for plan in plans], indent=2, sort_keys=True))
        return 0

    outputs: list[str] = []
    for plan in plans:
        run_build(plan, args.go, args.cgo_enabled)
        outputs.extend(binary.output for binary in plan.binaries)
    print(json.dumps({"ok": True, "outputs": outputs}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
