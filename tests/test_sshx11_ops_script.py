from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_ops.sh"


def test_sshx11_ops_shell_syntax() -> None:
    proc = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_sshx11_ops_help() -> None:
    proc = subprocess.run([str(SCRIPT), "help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "sshx11_ops.sh - operator wrapper" in proc.stdout
    assert "test-local" in proc.stdout
    assert "bench-local" in proc.stdout
    assert "status-local" in proc.stdout
    assert "plugins-list" in proc.stdout
    assert "plugins-show" in proc.stdout
    assert "plugins-discover" in proc.stdout
    assert "native-forward-plan" in proc.stdout
    assert "dataplane-firewall" in proc.stdout
    assert "socks-fallback-start" in proc.stdout
    assert "socks-fallback-status" in proc.stdout
    assert "test-socks-local" in proc.stdout
    assert "bench-socks5" in proc.stdout
    assert "run-9p-socks" in proc.stdout
    assert "9p-start" in proc.stdout
    assert "9p-status" in proc.stdout
    assert "9p-stop" in proc.stdout
    assert "9p-image-build" in proc.stdout
    assert "9p-logs" in proc.stdout
    assert "vfs-agent-start" in proc.stdout
    assert "vfs-agent-status" in proc.stdout
    assert "vfs-registry-list" in proc.stdout
    assert "vfs-mesh-build" in proc.stdout
    assert "vfs-mesh-status" in proc.stdout
    assert "vfs-mesh-clean" in proc.stdout
    assert "verify-remote" in proc.stdout
    assert "trace-local" in proc.stdout
    assert "repl-probe" in proc.stdout
    assert "repl-shortcut" in proc.stdout
    assert "repl-vhs-probe" in proc.stdout
    assert "repl-vhs-record" in proc.stdout


def _loads_first_json_object(text: str) -> dict:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError(f"no JSON object found in output: {text}")


def _authproof_vector_public_key() -> str:
    vector = json.loads(
        (REPO_ROOT / "authproof" / "testdata" / "weaverssh_authproof_v1_vector.json").read_text(
            encoding="utf-8"
        )
    )
    return vector["public_key_base64url"]


def test_sshx11_ops_native_forward_plan_dispatches_contract_checked_json() -> None:
    proc = subprocess.run(
        [
            str(SCRIPT),
            "native-forward-plan",
            "--mode",
            "sshR",
            "--remote",
            "root@203.0.113.20",
            "--remote-port",
            "22022",
            "--target-port",
            "6017",
            "--proof-subject-id",
            "agent-linode-a",
            "--proof-public-key",
            _authproof_vector_public_key(),
            "--chain-part",
            "origin-alise",
            "--chain-part",
            "jump-a",
            "--chain-part",
            "agent-linode-a",
            "--proof-x11-cookie",
            "native-forward-cookie",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["mode"] == "sshR"
    assert payload["role"] == "managedBackhaul"
    assert payload["remote"] == "root@203.0.113.20"
    assert "-R" in payload["ssh_args"]
    assert "127.0.0.1:22022:127.0.0.1:6017" in payload["ssh_args"]
    assert "ForwardAgent=no" in payload["ssh_args"]
    assert "ForwardX11=no" in payload["ssh_args"]
    assert "GatewayPorts=no" in payload["ssh_args"]
    assert "trusted-peer-authproof-required" in payload["guardrails"]


def test_sshx11_ops_native_forward_rejects_remote_authority_material() -> None:
    proc = subprocess.run(
        [
            str(SCRIPT),
            "native-forward-plan",
            "--mode",
            "sshR",
            "--remote",
            "root@203.0.113.20",
            "--proof-subject-id",
            "agent-linode-a",
            "--proof-public-key",
            _authproof_vector_public_key(),
            "--chain-part",
            "origin-alise",
            "--chain-part",
            "jump-a",
            "--chain-part",
            "agent-linode-a",
            "--proof-x11-cookie",
            "native-forward-cookie",
            "--authority-material-on-remote",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    payload = _loads_first_json_object(proc.stderr)
    assert payload["ok"] is False
    assert payload["status"] == "rejected"
    assert "authority material" in payload["error"]


def test_sshx11_ops_dataplane_firewall_dispatches_json() -> None:
    proc = subprocess.run(
        [
            str(SCRIPT),
            "dataplane-firewall",
            "plan",
            "--include-webdav",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["policy"]["version"] == "weaverssh.dataplane.firewall.v1"
    assert any(rule["flow_id"] == "webdav_file_endpoint" for rule in payload["rules"])
    assert payload["stack"]["implemented_backend"] == "iptables-plan"


def test_sshx11_ops_9p_plan_dispatch(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    binary = tmp_path / "wv-9p"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            str(SCRIPT),
            "9p-plan",
            "--root",
            str(root),
            "--binary",
            str(binary),
            "--state-file",
            str(state),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"service": "wv-9p"' in proc.stdout
    assert '"status": "planned"' in proc.stdout
    assert state.exists()


def test_sshx11_ops_9p_container_plan_dispatch(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = tmp_path / "state.json"
    env = {
        **os.environ,
        "SSHX11_9P_RUNTIME": "docker",
        "SSHX11_9P_CONTAINER_RUNTIME_BIN": sys.executable,
        "SSHX11_9P_CONTAINER_IMAGE": "weaverssh/wv-9p:test",
    }
    proc = subprocess.run(
        [
            str(SCRIPT),
            "9p-plan",
            "--root",
            str(root),
            "--state-file",
            str(state),
            "--port",
            "5663",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert '"service_runtime": "container"' in proc.stdout
    assert '"container_runtime": "docker"' in proc.stdout
    assert '"container_image": "weaverssh/wv-9p:test"' in proc.stdout
    assert state.exists()


def test_sshx11_ops_9p_image_build_dispatch(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    env = {
        **os.environ,
        "SSHX11_9P_RUNTIME": "docker",
        "SSHX11_9P_CONTAINER_RUNTIME_BIN": sys.executable,
        "SSHX11_9P_CONTAINER_IMAGE": "weaverssh/wv-9p:test",
    }
    proc = subprocess.run(
        [
            str(SCRIPT),
            "9p-image-build",
            "--state-file",
            str(state),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert '"status": "would_build"' in proc.stdout
    assert '"container_runtime": "docker"' in proc.stdout
    assert '"container_image": "weaverssh/wv-9p:test"' in proc.stdout
    assert state.exists()


def test_sshx11_ops_plugin_discover_dispatch() -> None:
    proc = subprocess.run(
        [str(SCRIPT), "plugins-discover", "--feature", "vfs.readonly.9p"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["count"] == 1
    plugin = payload["plugins"][0]
    assert plugin["id"] == "vfs.9p"
    assert plugin["available"] is True
    assert "9p-start" in {cmd["ops_subcommand"] for cmd in plugin["commands"]}


def test_sshx11_ops_plugin_show_dispatch() -> None:
    proc = subprocess.run(
        [str(SCRIPT), "plugins-show", "vfs.9p"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    plugin = payload["plugin"]
    assert plugin["id"] == "vfs.9p"
    assert plugin["services"][0]["id"] == "wv-9p"
