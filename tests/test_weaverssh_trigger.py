from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "weaverssh_trigger.py"
WRAPPER = REPO_ROOT / "weaverssh"
VALIDATION_WRAPPER = REPO_ROOT / "weaverssh-validate"


def load_module():
    spec = importlib.util.spec_from_file_location("weaverssh_trigger", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def run_trigger(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_core_trigger_registry_contains_operator_paths_and_excludes_jepsen() -> None:
    module = load_module()
    names = set(module.workflow_map_for_surface("core"))
    assert "binary-dist" in names
    assert "ansible-posix-install" in names
    assert "ansible-docker-install" in names
    assert "ansible-k8s-install" in names
    assert "homebrew-formula-plan" in names
    assert "homebrew-formula" in names
    assert "snap-plan" in names
    assert "snap-project" in names
    assert "snap-package" in names
    assert "jepsen-unit" not in names
    assert "jepsen-ansible-plan" not in names
    assert "jepsen-ansible-system" not in names


def test_validation_trigger_registry_contains_jepsen_paths() -> None:
    module = load_module()
    names = set(module.workflow_map_for_surface("validation"))
    assert "bench-plan" in names
    assert "jepsen-unit" in names
    assert "jepsen-ansible-plan" in names
    assert "jepsen-ansible-system" in names
    assert module.workflow_map_for_surface("validation")["jepsen-ansible-system"].destructive is True


def test_core_list_and_help_do_not_present_jepsen_as_weaverssh_workflow() -> None:
    listed = run_trigger("list")
    assert listed.returncode == 0, listed.stderr
    assert "Available workflows" in listed.stdout
    assert "ansible-posix-plan" in listed.stdout
    assert "homebrew-formula" in listed.stdout
    assert "snap-project" in listed.stdout
    assert "jepsen-ansible-system" not in listed.stdout

    helped = run_trigger("help", "ansible-k8s-install")
    assert helped.returncode == 0, helped.stderr
    assert "make ansible-install-k8s" in helped.stdout
    assert "jepsen" not in helped.stdout.lower()


def test_core_trigger_rejects_jepsen_workflow_with_surface_hint() -> None:
    proc = run_trigger("plan", "jepsen-ansible-plan")
    assert proc.returncode == 2
    assert "not available on ./weaverssh" in proc.stderr
    assert "jepsen-ansible-plan" not in proc.stderr.split("Available workflows:", 1)[-1]


def test_validation_plan_prints_exact_command_and_passes_extra_make_variables() -> None:
    proc = run_trigger(
        "--surface",
        "validation",
        "plan",
        "jepsen-ansible-plan",
        "JEPSEN_NODES=203.0.113.10,203.0.113.20",
        "JEPSEN_USER=kb",
        "JEPSEN_ANSIBLE_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
    )
    assert proc.returncode == 0, proc.stderr
    assert "workflow: jepsen-ansible-plan" in proc.stdout
    assert "destructive: no" in proc.stdout
    assert "make jepsen-ansible-install-plan" in proc.stdout
    assert "JEPSEN_NODES=203.0.113.10,203.0.113.20" in proc.stdout
    assert "JEPSEN_ANSIBLE_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz" in proc.stdout


def test_validation_trigger_refuses_destructive_run_without_gate() -> None:
    proc = run_trigger("--surface", "validation", "run", "jepsen-ansible-system")
    assert proc.returncode == 2
    assert "refusing to run destructive workflow" in proc.stderr


def test_root_wrappers_exist_and_delegate_to_correct_surfaces() -> None:
    assert WRAPPER.exists()
    assert os.access(WRAPPER, os.X_OK)
    core = subprocess.run(
        [str(WRAPPER), "plan", "ansible-posix-plan", "ANSIBLE_INVENTORY=inventory.ini"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert core.returncode == 0, core.stderr
    assert "make ansible-install-plan" in core.stdout
    assert "ANSIBLE_INVENTORY=inventory.ini" in core.stdout

    assert VALIDATION_WRAPPER.exists()
    assert os.access(VALIDATION_WRAPPER, os.X_OK)
    validation = subprocess.run(
        [str(VALIDATION_WRAPPER), "plan", "jepsen-plan", "JEPSEN_USER=kb"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert validation.returncode == 0, validation.stderr
    assert "make jepsen-plan" in validation.stdout
    assert "JEPSEN_USER=kb" in validation.stdout
