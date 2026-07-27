from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "packaging" / "build_snap_package.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_snap_package", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def fake_wv(tmp_path: Path) -> Path:
    binary = tmp_path / "wv"
    binary.write_text("#!/bin/sh\necho weaverssh test\n", encoding="utf-8")
    binary.chmod(0o755)
    return binary


def run_snap(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_snap_plan_maps_architecture_and_default_interfaces(tmp_path: Path) -> None:
    binary = fake_wv(tmp_path)

    proc = run_snap(
        "--plan",
        "--binary",
        str(binary),
        "--project-dir",
        str(tmp_path / "project"),
        "--dist-dir",
        str(tmp_path / "dist"),
        "--version",
        "1.2.3",
        "--release",
        "4",
        "--arch",
        "armv7",
    )

    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["snap_version"] == "1.2.3-4"
    assert plan["arch"] == "armv7"
    assert plan["snap_arch"] == "armhf"
    assert plan["base"] == "core24"
    assert plan["confinement"] == "strict"
    assert plan["output"].endswith("weaverssh_1.2.3-4_armhf.snap")
    assert plan["build_command"][-2:] == ["--output", plan["output"]]
    for plug in ("home", "network", "network-bind", "removable-media", "ssh-keys", "x11"):
        assert plug in plan["plugs"]


def test_snap_project_generation_writes_snapcraft_yaml_and_payload(tmp_path: Path) -> None:
    binary = fake_wv(tmp_path)
    project = tmp_path / "snap-project"

    proc = run_snap(
        "--binary",
        str(binary),
        "--project-dir",
        str(project),
        "--dist-dir",
        str(tmp_path / "dist"),
        "--version",
        "1.2.3",
        "--release",
        "4",
        "--arch",
        "amd64",
    )

    assert proc.returncode == 0, proc.stderr
    snapcraft = project / "snap" / "snapcraft.yaml"
    payload = project / "payload" / "bin" / "wv"
    assert snapcraft.exists()
    assert payload.exists()
    assert payload.stat().st_mode & 0o111
    text = snapcraft.read_text(encoding="utf-8")
    assert "name: weaverssh" in text
    assert "base: core24" in text
    assert 'version: "1.2.3-4"' in text
    assert "confinement: strict" in text
    assert "build-for: amd64" in text
    assert "command: bin/wv" in text
    assert "- ssh-keys" in text
    assert "plugin: dump" in text
    assert "source: payload" in text


def test_snap_make_project_target_writes_configured_project(tmp_path: Path) -> None:
    binary = fake_wv(tmp_path)
    project = tmp_path / "make-project"
    dist = tmp_path / "dist"

    proc = subprocess.run(
        [
            "make",
            "package-snap-project",
            f"SNAP_BINARY={binary}",
            f"SNAP_PROJECT_DIR={project}",
            f"SNAP_DIST_DIR={dist}",
            "SNAP_ARCH=amd64",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert (project / "snap" / "snapcraft.yaml").exists()
    assert (project / "payload" / "bin" / "wv").exists()


def test_snap_project_generation_rejects_missing_binary(tmp_path: Path) -> None:
    proc = run_snap("--binary", str(tmp_path / "missing-wv"), "--project-dir", str(tmp_path / "project"))

    assert proc.returncode != 0
    assert "wv binary not found" in proc.stderr


def test_snap_project_generation_rejects_unsupported_architecture(tmp_path: Path) -> None:
    binary = fake_wv(tmp_path)

    proc = run_snap("--plan", "--binary", str(binary), "--arch", "mips64")

    assert proc.returncode != 0
    assert "unsupported Snap architecture" in proc.stderr


def test_snap_architecture_mapping_covers_major_linux_targets() -> None:
    snap = load_module()
    assert snap.snap_arch("amd64") == "amd64"
    assert snap.snap_arch("arm64") == "arm64"
    assert snap.snap_arch("armv7") == "armhf"
    assert snap.snap_arch("386") == "i386"
    assert snap.snap_arch("ppc64le") == "ppc64el"
    assert snap.snap_arch("s390x") == "s390x"
    assert snap.snap_arch("riscv64") == "riscv64"
