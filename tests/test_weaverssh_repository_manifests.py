from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "packaging" / "build_repository_manifests.py"


def fake_archive(tmp_path: Path, target_label: str, *, version: str = "1.2.3", release: str = "4") -> Path:
    root = tmp_path / f"weaverssh-{version}-{release}-{target_label}"
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True)
    binary = bin_dir / ("wv.exe" if target_label.startswith("windows-") else "wv")
    binary.write_text("#!/bin/sh\necho weaverssh test\n", encoding="utf-8")
    binary.chmod(0o755)
    (root / "README.md").write_text("# weaverssh\n", encoding="utf-8")
    archive = tmp_path / f"weaverssh-{version}-{release}-{target_label}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname=root.name)
    return archive


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_manifests(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_repository_manifest_plan_covers_nix_scoop_and_chocolatey(tmp_path: Path) -> None:
    linux = fake_archive(tmp_path, "linux-amd64")
    windows = fake_archive(tmp_path, "windows-amd64")

    proc = run_manifests("--plan", "--archive", str(linux), "--archive", str(windows), "--output-dir", str(tmp_path / "out"))

    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["channels"] == ["nix", "scoop", "chocolatey"]
    assert plan["version"] == "1.2.3-4"
    assert any(output.endswith("nix/weaverssh-bin.nix") for output in plan["outputs"])
    assert any(output.endswith("scoop/weaverssh.json") for output in plan["outputs"])
    assert any(output.endswith("chocolatey/weaverssh/weaverssh.nuspec") for output in plan["outputs"])
    assert {artifact["target"] for artifact in plan["artifacts"]} == {"linux/amd64", "windows/amd64"}


def test_repository_manifest_generation_writes_channel_files(tmp_path: Path) -> None:
    linux = fake_archive(tmp_path, "linux-amd64")
    darwin = fake_archive(tmp_path, "darwin-arm64")
    windows = fake_archive(tmp_path, "windows-amd64")
    out = tmp_path / "out"

    proc = run_manifests(
        "--archive",
        str(linux),
        "--archive",
        str(darwin),
        "--archive",
        str(windows),
        "--url-base",
        "https://example.invalid/releases/v1.2.3",
        "--output-dir",
        str(out),
    )

    assert proc.returncode == 0, proc.stderr
    nix = out / "nix" / "weaverssh-bin.nix"
    scoop = out / "scoop" / "weaverssh.json"
    nuspec = out / "chocolatey" / "weaverssh" / "weaverssh.nuspec"
    choco_install = out / "chocolatey" / "weaverssh" / "tools" / "chocolateyinstall.ps1"
    assert nix.exists()
    assert scoop.exists()
    assert nuspec.exists()
    assert choco_install.exists()

    nix_text = nix.read_text(encoding="utf-8")
    assert 'pname = "weaverssh"' in nix_text
    assert "fetchurl" in nix_text
    assert "sha256-" in nix_text
    assert '"x86_64-linux"' in nix_text
    assert '"aarch64-darwin"' in nix_text
    assert "hostPlatform.system" in nix_text
    assert "install -m 0755" in nix_text

    scoop_payload = json.loads(scoop.read_text(encoding="utf-8"))
    assert scoop_payload["version"] == "1.2.3-4"
    assert scoop_payload["architecture"]["64bit"]["hash"] == sha256(windows)
    assert scoop_payload["bin"] == [["bin\\wv.exe", "wv"]]

    assert "<id>weaverssh</id>" in nuspec.read_text(encoding="utf-8")
    install_text = choco_install.read_text(encoding="utf-8")
    assert "Get-ChocolateyWebFile" in install_text
    assert sha256(windows) in install_text


def test_repository_manifest_rejects_missing_channel_archive(tmp_path: Path) -> None:
    linux = fake_archive(tmp_path, "linux-amd64")

    proc = run_manifests("--archive", str(linux), "--channel", "scoop", "--plan")

    assert proc.returncode != 0
    assert "Scoop manifest requires" in proc.stderr or "windows archive" in proc.stderr


def test_makefile_exposes_repository_manifest_targets() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    for target in (
        "package-freebsd-pkg:",
        "repository-manifests-plan:",
        "repository-manifests:",
        "package-nix:",
        "package-scoop:",
        "package-chocolatey:",
    ):
        assert target in makefile
    assert "freebsd-pkg" in makefile
    assert "build_repository_manifests.py" in makefile
