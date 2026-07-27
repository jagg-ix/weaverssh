from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(rel: str, name: str):
    path = REPO_ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _fake_binary_dir(tmp_path: Path) -> Path:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(parents=True)
    for name in ("wv", "wv-server", "wv-client", "wv-agent", "wv-socks", "wv-9p", "wv-native-forward"):
        path = binary_dir / name
        path.write_text(f"#!/bin/sh\necho {name}\n", encoding="utf-8")
        path.chmod(0o755)
    return binary_dir


def test_package_plan_covers_linux_native_formats_and_core_files(tmp_path: Path) -> None:
    packager = _load_module("tools/packaging/weaverssh_packager.py", "weaverssh_packager_plan")
    cfg = packager.PackageConfig(
        version="1.2.3",
        release="4",
        arch="amd64",
        prefix="/usr",
        binary_dir=_fake_binary_dir(tmp_path),
        build_dir=tmp_path / "build",
        dist_dir=tmp_path / "dist",
        maintainer="test <test@example.invalid>",
        url="https://example.invalid/weaverssh",
    )

    deb_plan = packager.build_plan("deb", cfg)
    rpm_plan = packager.build_plan("rpm", cfg)
    arch_plan = packager.build_plan("arch", cfg)
    apk_plan = packager.build_plan("apk", cfg)

    assert deb_plan.output.endswith("weaverssh_1.2.3-4_amd64.deb")
    assert rpm_plan.output.endswith("weaverssh-1.2.3-4.x86_64.rpm")
    assert arch_plan.output.endswith("weaverssh-1.2.3-4-x86_64.pkg.tar.zst")
    assert apk_plan.output.endswith("weaverssh-1.2.3-r4-x86_64.apk")
    assert "openssh-client" in deb_plan.dependencies
    assert "openssh-clients" in rpm_plan.dependencies
    assert "xorg-xauth" in arch_plan.dependencies
    assert "openssh-client" in apk_plan.dependencies
    for plan in (deb_plan, rpm_plan, arch_plan, apk_plan):
        assert "/usr/bin/wv" in plan.files
        assert "/usr/bin/wv-agent" not in plan.files
        assert "/usr/bin/wv-socks" not in plan.files
        assert "/usr/bin/wv-9p" not in plan.files
        assert "/usr/bin/wv-native-forward" not in plan.files
        assert "/usr/lib/systemd/user/wv-agent.service" in plan.files


def test_portable_package_builds_tar_and_zip_from_fake_binaries(tmp_path: Path) -> None:
    packager = _load_module("tools/packaging/weaverssh_packager.py", "weaverssh_packager_build")
    cfg = packager.PackageConfig(
        version="1.2.3",
        release="4",
        arch="amd64",
        prefix="/usr",
        binary_dir=_fake_binary_dir(tmp_path),
        build_dir=tmp_path / "build",
        dist_dir=tmp_path / "dist",
        maintainer="test <test@example.invalid>",
        url="https://example.invalid/weaverssh",
    )

    tar_path = packager.build_package("tar.gz", cfg)
    zip_path = packager.build_package("zip", cfg)

    assert tar_path.exists()
    assert zip_path.exists()
    with tarfile.open(tar_path, "r:gz") as tf:
        name_list = tf.getnames()
        names = set(name_list)
        assert len(name_list) == len(names)
    assert "usr/bin/wv" in names
    assert "usr/bin/wv-client" not in names
    assert "usr/bin/wv-9p" not in names
    assert "usr/bin/wv-native-forward" not in names
    assert "usr/lib/systemd/user/wv-agent.service" in names

    with zipfile.ZipFile(zip_path) as zf:
        zip_names = set(zf.namelist())
    assert "usr/bin/wv" in zip_names
    assert "usr/share/doc/weaverssh/README.md" in zip_names


def test_alpine_apk_builds_with_pkginfo_from_fake_binaries(tmp_path: Path) -> None:
    packager = _load_module("tools/packaging/weaverssh_packager.py", "weaverssh_packager_apk")
    cfg = packager.PackageConfig(
        version="1.2.3",
        release="4",
        arch="amd64",
        prefix="/usr",
        binary_dir=_fake_binary_dir(tmp_path),
        build_dir=tmp_path / "build",
        dist_dir=tmp_path / "dist",
        maintainer="test <test@example.invalid>",
        url="https://example.invalid/weaverssh",
    )

    apk_path = packager.build_package("apk", cfg)

    assert apk_path.exists()
    with tarfile.open(apk_path, "r:gz") as tf:
        name_list = tf.getnames()
        names = set(name_list)
        assert len(name_list) == len(names)
        pkginfo = tf.extractfile(".PKGINFO")
        assert pkginfo is not None
        pkginfo_text = pkginfo.read().decode("utf-8")
    assert ".PKGINFO" in names
    assert "usr/bin/wv" in names
    assert "usr/bin/wv-agent" not in names
    assert "usr/bin/wv-9p" not in names
    assert "usr/bin/wv-native-forward" not in names
    assert "pkgname = weaverssh" in pkginfo_text
    assert "pkgver = 1.2.3-r4" in pkginfo_text
    assert "depend = openssh-client" in pkginfo_text


def test_cli_explicit_formats_do_not_include_default_tar(tmp_path: Path) -> None:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools/packaging/weaverssh_packager.py"),
        "--plan",
        "--format",
        "deb,rpm",
        "--version",
        "1.2.3",
        "--release",
        "4",
        "--arch",
        "amd64",
        "--binary-dir",
        str(_fake_binary_dir(tmp_path)),
    ]

    plans = json.loads(subprocess.check_output(cmd, text=True))

    assert [plan["format"] for plan in plans] == ["deb", "rpm"]


def test_package_architecture_names_cover_major_linux_architectures(tmp_path: Path) -> None:
    packager = _load_module("tools/packaging/weaverssh_packager.py", "weaverssh_packager_arches")

    cases = {
        "amd64": {
            "deb": "weaverssh_1.2.3-4_amd64.deb",
            "rpm": "weaverssh-1.2.3-4.x86_64.rpm",
            "arch": "weaverssh-1.2.3-4-x86_64.pkg.tar.zst",
            "apk": "weaverssh-1.2.3-r4-x86_64.apk",
        },
        "arm64": {
            "deb": "weaverssh_1.2.3-4_arm64.deb",
            "rpm": "weaverssh-1.2.3-4.aarch64.rpm",
            "arch": "weaverssh-1.2.3-4-aarch64.pkg.tar.zst",
            "apk": "weaverssh-1.2.3-r4-aarch64.apk",
        },
        "armv7": {
            "deb": "weaverssh_1.2.3-4_armhf.deb",
            "rpm": "weaverssh-1.2.3-4.armv7hl.rpm",
            "arch": "weaverssh-1.2.3-4-armv7h.pkg.tar.zst",
            "apk": "weaverssh-1.2.3-r4-armv7.apk",
        },
        "386": {
            "deb": "weaverssh_1.2.3-4_i386.deb",
            "rpm": "weaverssh-1.2.3-4.i386.rpm",
            "apk": "weaverssh-1.2.3-r4-x86.apk",
        },
        "ppc64le": {
            "deb": "weaverssh_1.2.3-4_ppc64le.deb",
            "rpm": "weaverssh-1.2.3-4.ppc64le.rpm",
            "apk": "weaverssh-1.2.3-r4-ppc64le.apk",
        },
        "s390x": {
            "deb": "weaverssh_1.2.3-4_s390x.deb",
            "rpm": "weaverssh-1.2.3-4.s390x.rpm",
            "apk": "weaverssh-1.2.3-r4-s390x.apk",
        },
        "riscv64": {
            "deb": "weaverssh_1.2.3-4_riscv64.deb",
            "rpm": "weaverssh-1.2.3-4.riscv64.rpm",
            "apk": "weaverssh-1.2.3-r4-riscv64.apk",
        },
    }

    for arch, expected_by_format in cases.items():
        cfg = packager.PackageConfig(
            version="1.2.3",
            release="4",
            arch=arch,
            prefix="/usr",
            binary_dir=_fake_binary_dir(tmp_path / arch),
            build_dir=tmp_path / "build" / arch,
            dist_dir=tmp_path / "dist",
            maintainer="test <test@example.invalid>",
            url="https://example.invalid/weaverssh",
        )
        for fmt, expected_name in expected_by_format.items():
            assert Path(packager.output_path(fmt, cfg)).name == expected_name



def test_freebsd_pkg_plan_and_archive_contains_manifest(tmp_path: Path) -> None:
    packager = _load_module("tools/packaging/weaverssh_packager.py", "weaverssh_packager_freebsd")
    cfg = packager.PackageConfig(
        version="1.2.3",
        release="4",
        arch="amd64",
        prefix="/usr/local",
        binary_dir=_fake_binary_dir(tmp_path),
        build_dir=tmp_path / "build",
        dist_dir=tmp_path / "dist",
        maintainer="test <test@example.invalid>",
        url="https://example.invalid/weaverssh",
    )

    plan = packager.build_plan("freebsd-pkg", cfg)
    assert plan.output.endswith("weaverssh-1.2.3-4-freebsd-amd64.pkg")
    assert plan.dependencies == ["ca_root_nss", "openssh-portable", "xauth"]
    assert "/usr/local/bin/wv" in plan.files

    pkg_path = packager.build_package("freebsd-pkg", cfg)
    assert pkg_path.exists()
    with tarfile.open(pkg_path, "r:xz") as tf:
        names = set(tf.getnames())
        assert "+MANIFEST" in names
        manifest_file = tf.extractfile("+MANIFEST")
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read().decode("utf-8"))
    assert manifest["name"] == "weaverssh"
    assert manifest["arch"] == "FreeBSD:14:amd64"
    assert "/usr/local/bin/wv" in manifest["files"]

def test_dependency_plans_use_major_package_manager_names() -> None:
    deps = _load_module("tools/packaging/install_runtime_dependencies.py", "weaverssh_dependency_plan")

    apt = deps.build_plan("apt", include_build=True, assume_yes=True)
    dnf = deps.build_plan("dnf", include_build=True, assume_yes=True)
    pacman = deps.build_plan("pacman", include_build=True, assume_yes=True)
    apk = deps.build_plan("apk", include_build=True, assume_yes=True)
    brew = deps.build_plan("brew", include_build=True, assume_yes=True)

    assert "openssh-client" in apt.packages
    assert "dpkg-dev" in apt.packages
    assert apt.platform == "linux"
    assert "openssh-clients" in dnf.packages
    assert "rpm-build" in dnf.packages
    assert dnf.platform == "linux"
    assert "xorg-xauth" in pacman.packages
    assert "zstd" in pacman.packages
    assert "openssh-client" in apk.packages
    assert "tk" in apk.packages
    assert apk.platform == "linux"
    assert "xquartz" in brew.packages
    assert brew.platform == "darwin"
    assert ["brew", "install", "--cask", "xquartz"] in brew.commands



def test_dependency_plans_cover_bsd_and_aix_package_managers() -> None:
    deps = _load_module("tools/packaging/install_runtime_dependencies.py", "weaverssh_dependency_platform_matrix")

    freebsd = deps.build_plan("pkg", include_build=True, assume_yes=True, method="package-manager")
    openbsd = deps.build_plan("pkg_add", include_build=True, assume_yes=True, method="package-manager")
    aix = deps.build_plan("installp", include_build=True, assume_yes=True, method="package-manager")

    assert freebsd.platform == "freebsd"
    assert freebsd.package_manager == "pkg"
    assert "openssh-portable" in freebsd.packages
    assert freebsd.commands[0][:3] in (["sudo", "pkg", "install"], ["pkg", "install", "-y"])

    assert openbsd.platform == "openbsd"
    assert openbsd.package_manager == "pkg_add"
    assert "xauth" in openbsd.packages
    assert any("pkg_add" in part for part in openbsd.commands[0])

    assert aix.platform == "aix"
    assert aix.package_manager == "installp"
    assert "openssh" in aix.packages
    assert "AIX installp requires approved local media" in " ".join(aix.commands[0])

def test_dependency_plan_defaults_to_home_method() -> None:
    deps = _load_module("tools/packaging/install_runtime_dependencies.py", "weaverssh_dependency_home")

    plan = deps.build_plan(include_build=True, inspect=False, home_prefix="~/.weaverssh-test")

    assert plan.install_method == "home"
    assert plan.package_manager == "home"
    assert plan.requires_privilege is False
    assert "go" in plan.packages
    assert plan.home_prefix == "~/.weaverssh-test"
    assert plan.commands[0][:2] == ["mkdir", "-p"]
    assert not any("apt-get" in cmd or "brew" in cmd for command in plan.commands for cmd in command)
    assert not any("{prefix}" in cmd for command in plan.commands for cmd in command)


def test_dependency_plan_supports_replace_force_and_status(monkeypatch) -> None:
    deps = _load_module("tools/packaging/install_runtime_dependencies.py", "weaverssh_dependency_replace")

    apt = deps.build_plan("apt", include_build=True, assume_yes=True, replace=True, force=True)
    joined = " ".join(apt.commands[1])
    assert "--reinstall" in joined
    assert "--allow-downgrades" in joined
    assert "--allow-change-held-packages" in joined

    brew = deps.build_plan("brew", include_build=True, replace=True, force=True)
    assert any(cmd[:2] == ["brew", "reinstall"] for cmd in brew.commands)

    monkeypatch.setattr(deps.shutil, "which", lambda _name: None)
    statuses = deps.inspect_package_statuses("apt", ["ca-certificates"])
    assert statuses[0].package == "ca-certificates"
    assert statuses[0].installed is False
    assert "query tool not found" in statuses[0].detail


def test_dependency_cli_status_and_log_file(tmp_path: Path) -> None:
    script = REPO_ROOT / "tools/packaging/install_runtime_dependencies.py"
    log_file = tmp_path / "deps.jsonl"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "status",
            "--manager",
            "brew",
            "--log-file",
            str(log_file),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["package_manager"] == "brew"
    assert payload["statuses"]
    assert log_file.exists()
    assert '"event": "status"' in log_file.read_text(encoding="utf-8")


def test_dependency_cli_force_requires_confirmation(tmp_path: Path) -> None:
    script = REPO_ROOT / "tools/packaging/install_runtime_dependencies.py"
    log_file = tmp_path / "deps.jsonl"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "install",
            "--manager",
            "brew",
            "--force",
            "--log-file",
            str(log_file),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "requires --confirm-force" in proc.stderr
    assert '"event": "force_denied"' in log_file.read_text(encoding="utf-8")


def test_dependency_cli_install_dry_run_does_not_require_force_confirmation(tmp_path: Path) -> None:
    script = REPO_ROOT / "tools/packaging/install_runtime_dependencies.py"
    log_file = tmp_path / "deps.jsonl"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "install",
            "--manager",
            "apt",
            "--replace",
            "--force",
            "--dry-run",
            "--log-file",
            str(log_file),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["force"] is True
    assert payload["selected_packages"] == payload["packages"]
    assert '"event": "install_dry_run"' in log_file.read_text(encoding="utf-8")


def test_package_install_plans_detect_major_artifact_formats() -> None:
    installer = _load_module("tools/packaging/install_weaverssh_package.py", "weaverssh_package_installer")

    deb = installer.build_plan(Path("dist/packages/weaverssh_1.2.3-4_amd64.deb"))
    rpm = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4.x86_64.rpm"))
    arch = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4-x86_64.pkg.tar.zst"))
    apk = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-r4-x86_64.apk"))
    pkg = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4-arm64.pkg"))
    msi = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4-amd64.msi"))
    tar = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4-amd64.tar.gz"))
    zip_plan = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4-amd64.zip"))

    assert deb.format == "deb"
    assert deb.platform == "linux"
    assert deb.commands[0][:3] in (["sudo", "apt-get", "install"], ["apt-get", "install", "-y"])
    assert deb.commands[0][-1].endswith(".deb")
    assert rpm.format == "rpm"
    assert rpm.platform == "linux"
    assert rpm.commands[0][:3] in (["sudo", "dnf", "install"], ["dnf", "install", "-y"])
    assert rpm.commands[0][-1].endswith(".rpm")
    assert arch.format == "arch"
    assert arch.commands[0][:3] in (["sudo", "pacman", "-U"], ["pacman", "-U", "--noconfirm"])
    assert apk.format == "apk"
    assert apk.platform == "linux"
    assert "--allow-untrusted" in apk.commands[0]
    assert pkg.format == "pkg"
    assert pkg.platform == "darwin"
    assert "installer" in pkg.commands[0]
    assert msi.format == "msi"
    assert msi.platform == "windows"
    assert msi.commands[0][0] == "msiexec"
    assert tar.format == "tar.gz"
    assert tar.platform == "portable"
    assert "-xzf" in tar.commands[0]
    assert zip_plan.format == "zip"
    assert zip_plan.platform == "portable"
    assert zip_plan.commands[0][:3] == ["python3", "-m", "zipfile"]
    assert zip_plan.commands[1][-2].endswith("/usr/.")


def test_package_install_plan_supports_deb_and_rpm_manager_overrides() -> None:
    installer = _load_module("tools/packaging/install_weaverssh_package.py", "weaverssh_package_installer_overrides")

    dpkg = installer.build_plan(Path("dist/packages/weaverssh_1.2.3-4_amd64.deb"), manager="dpkg")
    yum = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4.x86_64.rpm"), manager="yum")
    zypper = installer.build_plan(Path("dist/packages/weaverssh-1.2.3-4.x86_64.rpm"), manager="zypper")

    assert "dpkg" in dpkg.commands[0]
    assert "yum" in yum.commands[0]
    assert "localinstall" in yum.commands[0]
    assert "zypper" in zypper.commands[0]


def test_package_install_cli_accepts_manager_between_command_and_artifact() -> None:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools/packaging/install_weaverssh_package.py"),
        "plan",
        "--manager",
        "yum",
        "dist/packages/weaverssh-1.2.3-4.x86_64.rpm",
    ]

    plan = json.loads(subprocess.check_output(cmd, text=True))

    assert plan["format"] == "rpm"
    assert "yum" in plan["commands"][0]
    assert "localinstall" in plan["commands"][0]
