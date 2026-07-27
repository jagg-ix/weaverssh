from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import sys
import tarfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIST = REPO_ROOT / "tools" / "packaging" / "build_source_distribution.py"
RECIPES = REPO_ROOT / "tools" / "packaging" / "build_source_recipes.py"
VERIFY = REPO_ROOT / "tools" / "packaging" / "verify_release_artifact.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fixture_source(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "cmd" / "wv").mkdir(parents=True)
    (root / "go.mod").write_text("module example.invalid/weaverssh\n\ngo 1.24\n\nrequire example.invalid/dependency v1.2.3\n", encoding="utf-8")
    (root / "cmd" / "wv" / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    (root / "Makefile").write_text("build:\n\tgo build ./cmd/wv\n", encoding="utf-8")
    return root


def test_source_archives_are_reproducible_and_self_describing(tmp_path: Path) -> None:
    source = load(SOURCE_DIST, "source_dist_test")
    root = fixture_source(tmp_path)
    first = source.make_plan("1.2.3", "4", root, tmp_path / "dist-a", 1700000000, False)
    second = source.make_plan("1.2.3", "4", root, tmp_path / "dist-b", 1700000000, False)
    source.build(first)
    source.build(second)
    assert source.sha256(Path(first.tar_gz)) == source.sha256(Path(second.tar_gz))
    assert source.sha256(Path(first.zip)) == source.sha256(Path(second.zip))
    with tarfile.open(first.tar_gz, "r:gz") as archive:
        names = set(archive.getnames())
        assert "weaverssh-1.2.3/SBOM.spdx.json" in names
        assert "weaverssh-1.2.3/SOURCE-MANIFEST.json" in names
        assert "weaverssh-1.2.3/SHA256SUMS.txt" in names
        manifest_handle = archive.extractfile("weaverssh-1.2.3/SOURCE-MANIFEST.json")
        assert manifest_handle is not None
        manifest = json.load(manifest_handle)
        assert manifest["schema"] == "weaverssh.source-distribution.v1"
        assert manifest["source_date_epoch"] == 1700000000


def test_source_recipes_pin_digest_and_separate_rpm_families(tmp_path: Path) -> None:
    recipes = load(RECIPES, "source_recipes_test")
    archive = tmp_path / "weaverssh-1.2.3-1-source.tar.gz"
    archive.write_bytes(b"source")
    plan = recipes.make_plan("1.2.3", "1", "", "", archive, tmp_path / "recipes", [])
    recipes.build(plan)
    root = Path(plan.output_dir) / "weaverssh-1.2.3-1"
    assert plan.source_sha256 in (root / "archlinux" / "PKGBUILD").read_text(encoding="utf-8")
    redhat = (root / "redhat" / "weaverssh.spec").read_text(encoding="utf-8")
    suse = (root / "suse" / "weaverssh.spec").read_text(encoding="utf-8")
    assert "openssh-clients" in redhat and "xorg-x11-xauth" in redhat
    assert "Requires: openssh\n" in suse and "Requires: xauth\n" in suse
    assert "xorg-x11-xauth" not in suse
    assert (root / "debian" / "rules").stat().st_mode & 0o111
    assert "Thu, 01 Jan 1970 00:00:00 +0000" in (root / "debian" / "changelog").read_text(encoding="utf-8")
    distinfo = (root / "freebsd" / "distinfo").read_text(encoding="utf-8")
    assert f"SIZE ({archive.name}) = {archive.stat().st_size}" in distinfo
    assert "-mod=vendor" in (root / "homebrew" / "weaverssh.rb").read_text(encoding="utf-8")


def test_artifact_verifier_checks_detached_and_internal_checksums(tmp_path: Path) -> None:
    verifier = load(VERIFY, "artifact_verify_test")
    archive = tmp_path / "weaverssh-windows-amd64.zip"
    payload = b"MZ-test"
    digest = verifier.hashlib.sha256(payload).hexdigest()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("wv.exe", payload)
        zf.writestr("SHA256SUMS.txt", f"{digest}  wv.exe\n")
    archive.with_name(archive.name + ".sha256").write_text(f"{verifier.sha256(archive)}  {archive.name}\n", encoding="utf-8")
    plan = verifier.make_plan(archive)
    result = verifier.verify(plan)
    assert result["ok"] is True
    assert result["archive"]["internal_checksums_verified"] == 1
    assert result["install_command"][0] == "powershell"


def test_artifact_verifier_rejects_path_traversal(tmp_path: Path) -> None:
    verifier = load(VERIFY, "artifact_verify_unsafe_test")
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape", b"bad")
    try:
        verifier.verify_zip(archive)
    except ValueError as exc:
        assert "unsafe zip members" in str(exc)
    else:
        raise AssertionError("unsafe archive was accepted")


def test_artifact_verifier_rejects_escaping_symlink_targets(tmp_path: Path) -> None:
    verifier = load(VERIFY, "artifact_verify_link_test")
    tar_path = tmp_path / "bad-links.tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        info = tarfile.TarInfo("root/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../escape"
        archive.addfile(info)
    try:
        verifier.verify_tar(tar_path)
    except ValueError as exc:
        assert "unsafe tar link" in str(exc)
    else:
        raise AssertionError("unsafe tar symlink was accepted")

    zip_path = tmp_path / "bad-links.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        info = zipfile.ZipInfo("root/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../escape")
    try:
        verifier.verify_zip(zip_path)
    except ValueError as exc:
        assert "unsafe zip symlink" in str(exc)
    else:
        raise AssertionError("unsafe zip symlink was accepted")


def test_install_plans_cover_requested_package_families(tmp_path: Path) -> None:
    verifier = load(VERIFY, "artifact_plan_test")
    cases = {
        "weaverssh.deb": "dpkg",
        "weaverssh.rpm": "dnf",
        "weaverssh.pkg.tar.zst": "pacman",
        "weaverssh-freebsd-amd64.pkg": "pkg",
        "weaverssh-macos.pkg": "installer",
    }
    for name, command in cases.items():
        plan = verifier.make_plan(tmp_path / name)
        assert command in plan.install_command
    suse = verifier.make_plan(tmp_path / "weaverssh.rpm", rpm_family="suse")
    assert "zypper" in suse.install_command


def test_gnumakefile_source_release_layer_is_exposed() -> None:
    top = (REPO_ROOT / "GNUmakefile").read_text(encoding="utf-8")
    layer = (REPO_ROOT / "mk" / "source-release.mk").read_text(encoding="utf-8")
    assert "include mk/source-release.mk" in top
    for target in (
        "source-dist-plan",
        "source-dist",
        "source-recipes-plan",
        "source-recipes",
        "verify-artifact",
        "artifact-install-plan",
        "test-source-release",
    ):
        assert f"{target}:" in layer
