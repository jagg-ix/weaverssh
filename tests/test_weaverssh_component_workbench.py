from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "weaverssh_component_workbench.py"
INSTALL_SCRIPT = REPO_ROOT / "tools" / "verification" / "install_weaverssh_development.sh"
DEPLOY_SCRIPT = REPO_ROOT / "tools" / "verification" / "deploy_weaverssh_local.sh"
VERIFY_SCRIPT = REPO_ROOT / "tools" / "verification" / "verify_weaverssh_workflows.sh"

spec = importlib.util.spec_from_file_location("weaverssh_component_workbench", SCRIPT)
assert spec is not None and spec.loader is not None
workbench = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = workbench
spec.loader.exec_module(workbench)


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_registry_integrity_and_phase_coverage() -> None:
    errors = workbench.validate_registry()
    assert errors == []
    targets = workbench.registry()
    assert len(targets) >= 17
    for target in targets:
        assert set(target.phases) == set(workbench.PHASES)
        for phase in workbench.PHASES:
            assert target.phases[phase], f"{target.id} missing {phase} commands"


def test_registry_contains_major_components_and_workflows() -> None:
    ids = {target.id for target in workbench.registry()}
    assert {
        "build-system",
        "core-runtime",
        "authproof-security",
        "control-plane",
        "dataplane-policy",
        "vfs-9p",
        "vfs-mesh",
        "transport-socks",
        "backhaul-multihop",
        "extension-ui-api",
        "per-user-api",
        "formal-contracts",
        "end-user-workflows",
        "local-service-workflow",
        "remote-linode-workflow",
        "webdav-workflow",
        "collab-repl-workflow",
    } <= ids


def test_cli_json_plan_exposes_component_commands() -> None:
    proc = run_cli("--format", "json", "plan", "dataplane-policy", "--phase", "verify")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    command_ids = {entry["command_id"] for entry in payload["commands"]}
    assert {"dataplane.json-plan", "dataplane.openflow-plan"} <= command_ids
    assert all(entry["risk"] == "safe" for entry in payload["commands"])


def test_cli_shell_plan_marks_deploy_risk() -> None:
    proc = run_cli("--format", "shell", "plan", "control-plane", "--phase", "deploy")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "risk=daemon" in proc.stdout
    assert "tools/verification/sshx11_ops.sh service-start" in proc.stdout


def test_execute_refuses_risky_deploy_without_explicit_risk_opt_in() -> None:
    proc = run_cli("run", "control-plane", "--phase", "deploy", "--execute")
    assert proc.returncode == 3
    assert "refusing control-plane:deploy:control-plane.service-start" in proc.stderr
    assert "--include-risk daemon" in proc.stderr


def test_verify_workflow_script_can_plan_safe_test_phase() -> None:
    proc = subprocess.run(
        [str(VERIFY_SCRIPT), "dataplane-policy", "--phase", "test", "--plan"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "tests/test_sshx11_dataplane_iptables.py" in proc.stdout


def test_install_and_deploy_scripts_are_executable_and_delegate_to_workbench() -> None:
    for script in (INSTALL_SCRIPT, DEPLOY_SCRIPT, VERIFY_SCRIPT):
        assert script.exists()
        assert script.stat().st_mode & 0o111, f"{script} is not executable"
        text = script.read_text(encoding="utf-8")
        assert "weaverssh_component_workbench.py" in text


def test_deploy_script_plan_defaults_to_non_executing_shell_plan() -> None:
    proc = subprocess.run(
        [str(DEPLOY_SCRIPT), "core-runtime", "--plan"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "# core-runtime deploy core-runtime.build-native risk=safe" in proc.stdout
    assert "make build-main build-server build-client-native build-agent build-socks" in proc.stdout
