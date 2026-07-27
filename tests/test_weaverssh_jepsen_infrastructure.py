from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "run_weaverssh_jepsen.py"
JEPSEN_ROOT = REPO_ROOT / "tools" / "jepsen" / "weaverssh"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_weaverssh_jepsen", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)


@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_jepsen_runner_dry_run_writes_plan(tmp_path: Path) -> None:
    output = tmp_path / "plan.json"
    nodes_file = tmp_path / "nodes.txt"
    proc = _run(
        [
            "python3",
            str(SCRIPT),
            "--dry-run",
            "--nodes",
            "203.0.113.10,203.0.113.20,203.0.113.10",
            "--username",
            "kb",
            "--identity-file",
            "~/.ssh/id_ed25519",
            "--generated-nodes-file",
            str(nodes_file),
            "--output",
            str(output),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["status"] == "dry_run"
    assert payload["nodes"] == ["203.0.113.10", "203.0.113.20"]
    assert payload["ssh"]["username"] == "kb"
    assert payload["destructive"] is False
    assert "clojure" in payload["command"][0]
    assert "--nodes-file" in payload["command"]
    assert nodes_file.read_text(encoding="utf-8").splitlines() == ["203.0.113.10", "203.0.113.20"]




@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_jepsen_runner_plans_ansible_install_workload(tmp_path: Path) -> None:
    output = tmp_path / "ansible-plan.json"
    nodes_file = tmp_path / "nodes.txt"
    proc = _run(
        [
            "python3",
            str(SCRIPT),
            "--dry-run",
            "--nodes",
            "203.0.113.10,203.0.113.20",
            "--username",
            "kb",
            "--workload",
            "ansible-install",
            "--nemesis",
            "none",
            "--remote-root",
            "~/weaverssh-sut/current",
            "--ansible-playbook",
            "ansible/playbooks/install_wv.yml",
            "--ansible-archive",
            "dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
            "--ansible-checksum",
            "sha256:abc123",
            "--generated-nodes-file",
            str(nodes_file),
            "--output",
            str(output),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["workload"] == "ansible-install"
    assert payload["nemesis"] == "none"
    assert payload["ansible"]["playbook"] == "ansible/playbooks/install_wv.yml"
    assert payload["ansible"]["archive"] == "dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz"
    assert payload["ansible"]["checksum"] == "sha256:abc123"
    assert payload["safety"]["ansible_install_workload_mutates_sut_home_and_packages"] is True
    assert "--workload" in payload["command"]
    assert "ansible-install" in payload["command"]
    assert "--ansible-archive" in payload["command"]
    assert "dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz" in payload["command"]

@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_jepsen_runner_execute_requires_destructive_ack() -> None:
    proc = _run(["python3", str(SCRIPT), "--execute", "--nodes", "127.0.0.1"])
    assert proc.returncode == 2
    assert "--execute requires --allow-destructive" in proc.stderr


@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_jepsen_runner_rejects_unknown_workload() -> None:
    module = _load_module()
    args = module.parser().parse_args(["--nodes", "127.0.0.1", "--workload", "bad"])
    args.dry_run = True
    with pytest.raises(ValueError, match="unsupported workload"):
        module.build_plan(args)


@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_jepsen_project_pins_current_library_and_declares_weaverssh_contract() -> None:
    deps = (JEPSEN_ROOT / "deps.edn").read_text(encoding="utf-8")
    source = (JEPSEN_ROOT / "src" / "weaverssh" / "jepsen.clj").read_text(encoding="utf-8")
    readme = (JEPSEN_ROOT / "README.md").read_text(encoding="utf-8")

    assert 'jepsen/jepsen {:mvn/version "0.3.11"}' in deps
    for namespace in [
        "jepsen.core",
        "jepsen.client",
        "jepsen.db",
        "jepsen.generator",
        "jepsen.nemesis",
        "jepsen.checker",
    ]:
        assert namespace in source
    assert ":weaverssh/contract" in source
    assert "ansible-install" in source
    assert "install-ansible-script" in source
    assert "ansible-playbook" in source
    assert "weaverssh_archive_path" in source
    assert "--execute --allow-destructive" in readme
    assert "ansible-install" in readme


@pytest.mark.sshx11
@pytest.mark.unit
@pytest.mark.jepsen
def test_makefile_and_testbench_expose_jepsen_lane() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    bench = (REPO_ROOT / "tools" / "verification" / "build_weaverssh_test_bench.sh").read_text(encoding="utf-8")
    assert "jepsen-plan:" in makefile
    assert "jepsen-unit:" in makefile
    assert "jepsen-system:" in makefile
    assert "jepsen-ansible-install-plan:" in makefile
    assert "jepsen-ansible-install-system:" in makefile
    assert "JEPSEN_WORKLOAD" in makefile
    assert "JEPSEN_ANSIBLE_ARCHIVE" in makefile
    assert "--jepsen" in bench
    assert "run_weaverssh_jepsen.py" in bench
