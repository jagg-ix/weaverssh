from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_BUILD = REPO_ROOT / "tools" / "packaging" / "source_build.py"
RPM_BUILDER = REPO_ROOT / "tools" / "packaging" / "build_rpm_package.py"
WINDOWS_BUILDER = REPO_ROOT / "tools" / "packaging" / "build_windows_package.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_requested_platform_and_distro_routes(tmp_path: Path) -> None:
    source = load(SOURCE_BUILD, "weaverssh_source_build")
    cases = [
        ("osx", "", "macos", "pkg"),
        ("freebsd", "", "freebsd", "freebsd-pkg"),
        ("windows", "", "windows", "zip"),
        ("wsl", "ubuntu", "debian", "deb"),
        ("linux", "debian", "debian", "deb"),
        ("linux", "rhel", "redhat", "rpm"),
        ("linux", "opensuse", "suse", "rpm"),
        ("linux", "arch", "archlinux", "arch"),
        ("linux", "unknown", "portable-linux", "tar.gz+zip"),
    ]
    for platform_name, distro, family, fmt in cases:
        plan = source.make_plan(
            platform_name=platform_name,
            distro_override=distro,
            arch="amd64",
            build_dir=tmp_path / "build",
            dist_dir=tmp_path / "dist",
            env={},
            os_release={},
        )
        assert plan.package_family == family
        assert plan.package_format == fmt
        assert plan.go_target in {"darwin/amd64", "freebsd/amd64", "windows/amd64", "linux/amd64"}
        assert plan.build_command[1:3] == ["tools/packaging/build_weaverssh_matrix.py", "build"]


def test_wsl_is_linux_target_with_distribution_package(tmp_path: Path) -> None:
    source = load(SOURCE_BUILD, "weaverssh_source_build_wsl")
    plan = source.make_plan(
        platform_name="linux",
        distro_override="",
        arch="arm64",
        build_dir=tmp_path / "build",
        dist_dir=tmp_path / "dist",
        env={"WSL_DISTRO_NAME": "Ubuntu"},
        os_release={"ID": "ubuntu", "ID_LIKE": "debian"},
    )
    assert plan.target_platform == "linux"
    assert plan.flavor == "wsl"
    assert plan.go_target == "linux/arm64"
    assert plan.package_family == "debian"
    assert any("WSL uses the Linux Go target" in note for note in plan.notes)


def test_redhat_and_suse_rpm_requirements_are_distinct(tmp_path: Path) -> None:
    rpm = load(RPM_BUILDER, "weaverssh_rpm_builder")
    redhat = rpm.make_plan("redhat", "1.2.3", "1", "amd64", tmp_path / "bin", tmp_path / "dist")
    suse = rpm.make_plan("suse", "1.2.3", "1", "amd64", tmp_path / "bin", tmp_path / "dist")
    assert "xorg-x11-xauth" in redhat.requirements
    assert "openssh-clients" in redhat.requirements
    assert "xauth" in suse.requirements
    assert "openssh" in suse.requirements
    assert "xorg-x11-xauth" not in suse.requirements


def test_windows_zip_contains_binary_installers_and_checksums(tmp_path: Path) -> None:
    builder = load(WINDOWS_BUILDER, "weaverssh_windows_builder")
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    (binary_dir / "wv.exe").write_bytes(b"MZ-test")
    plan = builder.make_plan("1.2.3", "4", "amd64", binary_dir, tmp_path / "dist")
    output = builder.build(plan)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert {"wv.exe", "install.ps1", "uninstall.ps1", "MANIFEST.json", "SHA256SUMS.txt"} <= names
        manifest = json.loads(archive.read("MANIFEST.json"))
        assert manifest["schema"] == "weaverssh.windows-package.v1"
        assert manifest["arch"] == "amd64"


def test_gnumakefile_exposes_cross_platform_make_targets() -> None:
    top = (REPO_ROOT / "GNUmakefile").read_text(encoding="utf-8")
    layer = (REPO_ROOT / "mk" / "platform-build.mk").read_text(encoding="utf-8")
    assert "include Makefile" in top
    assert "include mk/platform-build.mk" in top
    for target in [
        "build-osx",
        "build-freebsd-native",
        "build-windows-native",
        "build-wsl",
        "build-vanilla-linux",
        "package-ubuntu",
        "package-debian",
        "package-redhat",
        "package-suse",
        "package-archlinux",
    ]:
        assert f"{target}:" in layer


def test_source_build_cli_requires_execute_for_mutation(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SOURCE_BUILD),
            "build",
            "--platform",
            "linux",
            "--distro",
            "ubuntu",
            "--arch",
            "amd64",
            "--build-dir",
            str(tmp_path / "build"),
            "--dist-dir",
            str(tmp_path / "dist"),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["package_family"] == "debian"
    assert "execution requires --execute" in proc.stderr
