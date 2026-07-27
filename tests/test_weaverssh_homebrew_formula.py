from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "packaging" / "build_homebrew_formula.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_homebrew_formula", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def fake_archive(tmp_path: Path, target_label: str, *, version: str = "1.2.3", release: str = "4") -> Path:
    root = tmp_path / f"weaverssh-{version}-{release}-{target_label}"
    (root / "bin").mkdir(parents=True)
    wv = root / "bin" / "wv"
    wv.write_text(
        "#!/bin/sh\n"
        "case \"${1:-help}\" in\n"
        "  version) echo 'weaverssh test' ;;\n"
        "  help) echo 'Usage: wv <command>' ;;\n"
        "  *) echo 'Usage: wv <command>' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    wv.chmod(0o755)
    (root / "README.md").write_text("# weaverssh\n", encoding="utf-8")
    archive = tmp_path / f"weaverssh-{version}-{release}-{target_label}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname=root.name)
    return archive


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_formula(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_homebrew_plan_infers_archive_metadata_and_sha256(tmp_path: Path) -> None:
    archive = fake_archive(tmp_path, "darwin-arm64")

    proc = run_formula("--plan", "--archive", str(archive))

    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["version"] == "1.2.3-4"
    assert plan["output"].endswith("dist/homebrew/Formula/weaverssh.rb")
    artifact = plan["artifacts"][0]
    assert artifact["target"] == "darwin/arm64"
    assert artifact["url"] == archive.resolve().as_uri()
    assert artifact["sha256"] == sha256(archive)


def test_homebrew_formula_generation_supports_macos_and_linux_archives(tmp_path: Path) -> None:
    archives = [
        fake_archive(tmp_path, "darwin-arm64"),
        fake_archive(tmp_path, "darwin-amd64"),
        fake_archive(tmp_path, "linux-amd64"),
    ]
    output = tmp_path / "Formula" / "weaverssh.rb"

    proc = run_formula(
        *(arg for archive in archives for arg in ("--archive", str(archive))),
        "--url-base",
        "https://example.invalid/releases/v1.2.3",
        "--output",
        str(output),
    )

    assert proc.returncode == 0, proc.stderr
    assert output.exists()
    formula = output.read_text(encoding="utf-8")
    assert "class Weaverssh < Formula" in formula
    assert 'version "1.2.3-4"' in formula
    assert "on_macos do" in formula
    assert "on_linux do" in formula
    assert "Hardware::CPU.arm?" in formula
    assert "Hardware::CPU.intel?" in formula
    assert 'url "https://example.invalid/releases/v1.2.3/weaverssh-1.2.3-4-darwin-arm64.tar.gz"' in formula
    assert f'sha256 "{sha256(archives[0])}"' in formula
    assert 'bin.install binary => "wv"' in formula
    assert 'shell_output("#{bin}/wv version")' in formula
    assert "wv deps status" in formula

    if shutil.which("ruby"):
        syntax = subprocess.run(["ruby", "-c", str(output)], text=True, capture_output=True, check=False)
        assert syntax.returncode == 0, syntax.stderr


def test_homebrew_formula_make_target_writes_configured_output(tmp_path: Path) -> None:
    archive = fake_archive(tmp_path, "darwin-arm64")
    output = tmp_path / "tap" / "Formula" / "weaverssh.rb"

    proc = subprocess.run(
        [
            "make",
            "homebrew-formula",
            f"HOMEBREW_ARCHIVE={archive}",
            f"HOMEBREW_FORMULA_OUTPUT={output}",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert output.exists()
    assert 'url "file://' in output.read_text(encoding="utf-8")


def test_homebrew_formula_rejects_mixed_versions(tmp_path: Path) -> None:
    first = fake_archive(tmp_path, "darwin-arm64", version="1.2.3")
    second = fake_archive(tmp_path, "darwin-amd64", version="2.0.0")

    proc = run_formula("--archive", str(first), "--archive", str(second), "--plan")

    assert proc.returncode != 0
    assert "same version/release" in proc.stderr


def test_homebrew_formula_rejects_unsupported_archive_target(tmp_path: Path) -> None:
    archive = fake_archive(tmp_path, "windows-amd64")

    proc = run_formula("--archive", str(archive), "--plan")

    assert proc.returncode != 0
    assert "supports darwin/linux" in proc.stderr


def test_homebrew_cpu_predicates_are_defined_for_major_arches() -> None:
    formula = load_module()
    assert formula.cpu_predicate("darwin", "arm64") == "Hardware::CPU.arm?"
    assert formula.cpu_predicate("darwin", "amd64") == "Hardware::CPU.intel?"
    assert "is_64_bit" in formula.cpu_predicate("linux", "amd64")
    assert "is_64_bit" in formula.cpu_predicate("linux", "arm64")
