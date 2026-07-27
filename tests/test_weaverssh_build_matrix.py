from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_matrix():
    path = REPO_ROOT / "tools/packaging/build_weaverssh_matrix.py"
    spec = importlib.util.spec_from_file_location("weaverssh_build_matrix", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["weaverssh_build_matrix"] = module
    spec.loader.exec_module(module)
    return module


def test_major_matrix_contains_maintained_os_architecture_targets() -> None:
    matrix = _load_matrix()

    targets = matrix.expand_targets(["major"], [])
    specs = {target.spec for target in targets}

    assert "linux/amd64" in specs
    assert "linux/arm64" in specs
    assert "linux/arm/v7" in specs
    assert "linux/ppc64le" in specs
    assert "linux/s390x" in specs
    assert "linux/riscv64" in specs
    assert "darwin/amd64" in specs
    assert "darwin/arm64" in specs
    assert "windows/amd64" in specs
    assert "windows/arm64" in specs
    assert "freebsd/amd64" in specs
    assert "openbsd/amd64" in specs
    assert "openbsd/arm64" in specs
    assert len(specs) == len(targets)


def test_target_plan_uses_stable_labels_and_windows_exe_suffix(tmp_path: Path) -> None:
    matrix = _load_matrix()

    linux_armv7 = matrix.build_plan(matrix.parse_target("linux/arm/v7"), tmp_path)
    windows_arm64 = matrix.build_plan(matrix.parse_target("windows/arm64"), tmp_path)

    assert linux_armv7.target.label == "linux-armv7"
    assert linux_armv7.target.package_arch == "armv7"
    assert linux_armv7.binaries[0].output.endswith("linux-armv7/wv")
    assert windows_arm64.target.label == "windows-arm64"
    assert windows_arm64.binaries[0].output.endswith("windows-arm64/wv.exe")
    assert any(binary.name == "wv-native-forward" for binary in linux_armv7.binaries)
    assert any(binary.output.endswith("windows-arm64/wv-native-forward.exe") for binary in windows_arm64.binaries)


def test_hardened_profile_enables_pie_only_on_supported_targets(tmp_path: Path) -> None:
    matrix = _load_matrix()

    linux_amd64 = matrix.build_plan(matrix.parse_target("linux/amd64"), tmp_path, "hardened")
    linux_386 = matrix.build_plan(matrix.parse_target("linux/386"), tmp_path, "hardened")
    compat_linux_amd64 = matrix.build_plan(matrix.parse_target("linux/amd64"), tmp_path, "compat")
    debug_linux_amd64 = matrix.build_plan(matrix.parse_target("linux/amd64"), tmp_path, "debug")

    assert linux_amd64.security_profile == "hardened"
    assert linux_amd64.pie_enabled is True
    assert "-buildmode=pie" in linux_amd64.build_flags
    assert "-trimpath" in linux_amd64.build_flags
    assert "-buildvcs=false" in linux_amd64.build_flags
    assert "-ldflags=-s -w" in linux_amd64.build_flags
    assert linux_386.pie_enabled is False
    assert "-buildmode=pie" not in linux_386.build_flags
    assert "-trimpath" in linux_386.build_flags
    assert compat_linux_amd64.pie_enabled is False
    assert "-buildmode=pie" not in compat_linux_amd64.build_flags
    assert "-trimpath" in compat_linux_amd64.build_flags
    assert debug_linux_amd64.build_flags == []


def test_matrix_cli_plan_outputs_json_for_explicit_targets(tmp_path: Path) -> None:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools/packaging/build_weaverssh_matrix.py"),
        "plan",
        "--target",
        "linux/amd64,windows/386",
        "--build-dir",
        str(tmp_path),
    ]

    plans = json.loads(subprocess.check_output(cmd, text=True))

    assert [plan["target"]["spec"] for plan in plans] == ["linux/amd64", "windows/386"]
    assert plans[0]["binaries"][0]["output"].endswith("linux-amd64/wv")
    assert plans[0]["pie_enabled"] is True
    assert "-buildmode=pie" in plans[0]["build_flags"]
    assert plans[1]["binaries"][0]["output"].endswith("windows-386/wv.exe")
    assert plans[1]["pie_enabled"] is True

def test_makefile_platform_shortcuts_include_bsd_targets() -> None:
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in [
        "build-freebsd-amd64",
        "build-freebsd-arm64",
        "build-openbsd-amd64",
        "build-openbsd-arm64",
    ]:
        assert f"{target}:" in text
    assert "BUILD_TARGET=freebsd/arm64" in text
    assert "BUILD_TARGET=openbsd/amd64" in text
    assert "BUILD_TARGET=openbsd/arm64" in text
    assert "Linux, macOS, Windows, FreeBSD, and OpenBSD major architectures" in text
