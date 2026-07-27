from __future__ import annotations

from pathlib import Path
import json
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_vfs_agent.py"


def test_sshx11_vfs_agent_help() -> None:
    proc = subprocess.run(["python3", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "start" in proc.stdout
    assert "serve" in proc.stdout
    assert "stop" in proc.stdout
    assert "status" in proc.stdout
    assert "sync-once" in proc.stdout
    assert "list-registry" in proc.stdout


def test_sshx11_vfs_agent_start_dry_run(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    registry = tmp_path / "registry.json"
    token = tmp_path / "token.txt"
    pid = tmp_path / "agent.pid"
    log = tmp_path / "agent.log"
    proc = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--host-id",
            "host-a",
            "--node-endpoint",
            "ssh://host-a:22",
            "--export",
            "root=/srv/data:rw",
            "--import",
            "host-b:root=/mesh/host-b/root:ro",
            "--state-file",
            str(state),
            "--registry-file",
            str(registry),
            "--token-file",
            str(token),
            "--pid-file",
            str(pid),
            "--log-file",
            str(log),
            "--dry-run",
            "start",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "dry_run"
    assert payload["host_id"] == "host-a"
    assert payload["exports"][0]["name"] == "root"
    assert payload["imports"][0]["source_host"] == "host-b"


def test_sshx11_vfs_agent_sync_once_and_registry_list(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    registry = tmp_path / "registry.json"
    token = tmp_path / "token.txt"
    proc = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--host-id",
            "host-c",
            "--node-endpoint",
            "ssh://host-c:22",
            "--export",
            "root=/data:rw",
            "--import",
            "host-d:root=/mesh/host-d/root:ro",
            "--state-file",
            str(state),
            "--registry-file",
            str(registry),
            "--token-file",
            str(token),
            "sync-once",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    sync_payload = json.loads(proc.stdout)
    assert sync_payload["ok"] is True
    assert "host-c" in sync_payload["registry_hosts"]
    assert state.exists()
    assert registry.exists()

    proc_list = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--registry-file",
            str(registry),
            "list-registry",
        ],
        capture_output=True,
        text=True,
    )
    assert proc_list.returncode == 0, proc_list.stderr
    reg_payload = json.loads(proc_list.stdout)
    assert reg_payload["ok"] is True
    assert reg_payload["host_count"] == 1
    assert "host-c" in reg_payload["hosts"]
    assert reg_payload["hosts"]["host-c"]["status"] == "online"


def test_sshx11_vfs_mesh_materializer_build_status_and_clean(tmp_path: Path) -> None:
    mesh_script = REPO_ROOT / "tools" / "verification" / "sshx11_vfs_mesh.py"
    registry = tmp_path / "registry.json"
    token_a = tmp_path / "token-a.txt"
    token_b = tmp_path / "token-b.txt"
    state_a = tmp_path / "state-a.json"
    state_b = tmp_path / "state-b.json"
    export_a = tmp_path / "host-a-export"
    export_a.mkdir()
    (export_a / "hello.txt").write_text("hello from host-a\n", encoding="utf-8")

    for args in [
        [
            "--host-id",
            "host-a",
            "--node-endpoint",
            "ssh://host-a:22",
            "--export",
            f"root={export_a}:rw",
            "--state-file",
            str(state_a),
            "--registry-file",
            str(registry),
            "--token-file",
            str(token_a),
            "sync-once",
        ],
        [
            "--host-id",
            "host-b",
            "--node-endpoint",
            "ssh://host-b:22",
            "--export",
            "/var=/var:ro",
            "--import",
            "host-a:root=/mesh/host-a/root:ro",
            "--state-file",
            str(state_b),
            "--registry-file",
            str(registry),
            "--token-file",
            str(token_b),
            "sync-once",
        ],
    ]:
        proc = subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

    namespace = tmp_path / "namespace"
    proc = subprocess.run(
        [
            "python3",
            str(mesh_script),
            "--registry-file",
            str(registry),
            "--namespace-dir",
            str(namespace),
            "build",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "built"
    assert payload["host_count"] == 2
    assert payload["export_count"] == 2
    assert payload["import_count"] == 1
    assert payload["mount_graph_ready"] is True
    assert payload["mesh_namespace_ready"] is True
    assert payload["views_namespace_ready"] is True
    assert (namespace / ".weaverssh-vfs-namespace").exists()
    assert (namespace / "mesh" / "host-a" / "root" / ".weaverssh-export.json").exists()
    assert (namespace / "mesh" / "host-a" / "root" / "README.weaverssh.txt").exists()
    assert not (namespace / "mesh" / "host-a" / "root" / "data").exists()

    manifest = json.loads((namespace / "weaverssh_vfs_manifest.json").read_text(encoding="utf-8"))
    assert manifest["webdav_root"] == str(namespace)
    assert (namespace / "views" / "webdav_root.txt").read_text(encoding="utf-8").strip() == str(namespace)
    mount_graph = json.loads((namespace / "views" / "mount_graph.json").read_text(encoding="utf-8"))
    assert mount_graph["data_plane"] == "9P_OVER_SOCKS"
    assert mount_graph["edges"][0]["from"] == "/mesh/host-a/root"
    assert mount_graph["edges"][0]["to_host"] == "host-b"

    status = subprocess.run(
        [
            "python3",
            str(mesh_script),
            "--registry-file",
            str(registry),
            "--namespace-dir",
            str(namespace),
            "status",
        ],
        capture_output=True,
        text=True,
    )
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["status"] == "ready"

    clean = subprocess.run(
        [
            "python3",
            str(mesh_script),
            "--registry-file",
            str(registry),
            "--namespace-dir",
            str(namespace),
            "clean",
        ],
        capture_output=True,
        text=True,
    )
    assert clean.returncode == 0, clean.stderr
    assert not namespace.exists()


def test_sshx11_vfs_mesh_materializer_refuses_unmarked_directory(tmp_path: Path) -> None:
    mesh_script = REPO_ROOT / "tools" / "verification" / "sshx11_vfs_mesh.py"
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": "sshx11_vfs_registry.v1",
                "hosts": {
                    "host-a": {
                        "host_id": "host-a",
                        "status": "online",
                        "node_endpoint": "ssh://host-a:22",
                        "capability_token_sha256": "abc",
                        "exports": [{"name": "root", "path": "/srv", "mode": "ro"}],
                        "imports": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    namespace = tmp_path / "not-owned"
    namespace.mkdir()
    (namespace / "user-file.txt").write_text("do not delete\n", encoding="utf-8")

    proc = subprocess.run(
        [
            "python3",
            str(mesh_script),
            "--registry-file",
            str(registry),
            "--namespace-dir",
            str(namespace),
            "build",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert (namespace / "user-file.txt").exists()
