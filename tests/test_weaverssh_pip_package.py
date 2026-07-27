from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]




def _python_with_setuptools() -> str:
    candidates = [shutil.which("python3"), sys.executable]
    for candidate in candidates:
        if not candidate:
            continue
        probe = subprocess.run(
            [candidate, "-c", "import setuptools"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return candidate
    pytest.skip("pip package build requires a Python interpreter with setuptools available")

def _pythonpath(extra: Path | None = None) -> str:
    parts = []
    if extra is not None:
        parts.append(str(extra))
    parts.extend([str(REPO_ROOT / "python"), str(REPO_ROOT)])
    return os.pathsep.join(parts)


def test_pyproject_defines_pip_package_entrypoints_and_extras() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "weaverssh"
    assert project["requires-python"] == ">=3.10"
    assert project["scripts"]["weaverssh-py"] == "weaverssh_support.cli:main"
    extras = project["optional-dependencies"]
    for name in ("core", "mcp", "webterm", "tray", "vision", "all"):
        assert name in extras
    assert "mcp>=1.9" in extras["mcp"]
    assert any(dep.startswith("opencv-python") for dep in extras["vision"])


def test_weaverssh_support_cli_loads_manifest_and_profiles_from_repo() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath()
    output = subprocess.check_output(
        [sys.executable, "-m", "weaverssh_support", "--profiles"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
    )
    assert "core" in output
    assert "mcp" in output
    requirements = subprocess.check_output(
        [sys.executable, "-m", "weaverssh_support", "--requirements", "mcp"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
    )
    assert "requirements/python/mcp.txt" in requirements
    tools_json = subprocess.check_output(
        [sys.executable, "-m", "weaverssh_support", "--list", "--json"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
    )
    tools = json.loads(tools_json)
    assert any(tool["name"] == "deps" and tool["module"] == "tools.packaging.install_runtime_dependencies" for tool in tools)


def test_repo_can_be_installed_with_pip_target_without_dependencies(tmp_path: Path) -> None:
    target = tmp_path / "pip-target"
    python_bin = _python_with_setuptools()
    subprocess.run(
        [
            python_bin,
            "-m",
            "pip",
            "install",
            "--no-build-isolation",
            "--no-deps",
            "--target",
            str(target),
            ".",
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath(target)
    output = subprocess.check_output(
        [python_bin, "-m", "weaverssh_support", "--list"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
    )
    assert "weaverssh Python tools" in output
    assert "deps" in output
    subprocess.run(
        [python_bin, "-c", "import tools.packaging.install_runtime_dependencies as deps; print(deps.DEFAULT_HOME_PREFIX)"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
