from __future__ import annotations

import json
import sys
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE = REPO_ROOT / "tools" / "verification" / "sshx11_9p_service.py"
WV9P = REPO_ROOT / "build" / "bin" / "wv-9p"


def _json(proc: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return json.loads(proc.stdout)


def test_sshx11_9p_service_help() -> None:
    proc = subprocess.run(["python3", str(SERVICE), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "wv-9p" in proc.stdout
    assert "plan" in proc.stdout
    assert "status" in proc.stdout
    assert "--runtime" in proc.stdout
    assert "--container-image" in proc.stdout
    assert "image-build" in proc.stdout
    assert "logs" in proc.stdout
    assert "--logs-tail" in proc.stdout


def test_sshx11_9p_service_plan_reports_missing_inputs(tmp_path: Path) -> None:
    root = tmp_path / "missing-root"
    binary = tmp_path / "missing-wv-9p"
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--root",
            str(root),
            "--binary",
            str(binary),
            "--state-file",
            str(state),
            "plan",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    payload = _json(proc)
    assert payload["ok"] is False
    assert payload["binary_exists"] is False
    assert payload["root_exists"] is False
    assert payload["build_command"] == "make build-9p"
    assert state.exists()


def test_sshx11_9p_service_status_stopped(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--root",
            str(root),
            "--binary",
            str(WV9P),
            "--pid-file",
            str(tmp_path / "missing.pid"),
            "--state-file",
            str(state),
            "--port",
            "5659",
            "status",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    payload = _json(proc)
    assert payload["ok"] is False
    assert payload["status"] == "stopped"
    assert payload["mode"] == "9p"
    assert payload["service"] == "wv-9p"
    assert payload["root_exists"] is True
    assert payload["port_open"] is False
    assert state.exists()


def test_sshx11_9p_service_start_missing_binary_fails_cleanly(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--root",
            str(root),
            "--binary",
            str(tmp_path / "missing-wv-9p"),
            "--state-file",
            str(state),
            "start",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    payload = _json(proc)
    assert payload["ok"] is False
    assert payload["reason"] == "binary_missing"
    assert payload["build_command"] == "make build-9p"


def test_sshx11_9p_service_start_missing_root_fails_cleanly(tmp_path: Path) -> None:
    binary = tmp_path / "wv-9p"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--root",
            str(tmp_path / "missing-root"),
            "--binary",
            str(binary),
            "--state-file",
            str(state),
            "start",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    payload = _json(proc)
    assert payload["ok"] is False
    assert payload["reason"] == "root_missing"
    assert "vfs-mesh-build" in payload["namespace_command"]


def test_sshx11_9p_service_container_plan_without_docker_daemon(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--runtime",
            "docker",
            "--container-runtime-bin",
            sys.executable,
            "--container-image",
            "weaverssh/wv-9p:test",
            "--container-name",
            "wv-9p-test",
            "--root",
            str(root),
            "--state-file",
            str(state),
            "--port",
            "5661",
            "plan",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = _json(proc)
    assert payload["ok"] is True
    assert payload["service_runtime"] == "container"
    assert payload["container_runtime"] == "docker"
    assert payload["container_image"] == "weaverssh/wv-9p:test"
    assert payload["container_name"] == "wv-9p-test"
    assert payload["listen"] == "127.0.0.1:5661"
    assert "run" in payload["command"]
    assert "build" in payload["build_command"]
    assert state.exists()


def test_sshx11_9p_service_container_start_dry_run(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--runtime",
            "podman",
            "--container-runtime-bin",
            sys.executable,
            "--container-image",
            "weaverssh/wv-9p:test",
            "--container-name",
            "wv-9p-dry-run",
            "--root",
            str(root),
            "--state-file",
            str(state),
            "--port",
            "5662",
            "--dry-run",
            "start",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = _json(proc)
    assert payload["ok"] is True
    assert payload["status"] == "would_start"
    assert payload["service_runtime"] == "container"
    assert payload["container_runtime"] == "podman"
    assert "run" in payload["command"]
    assert "--read-only" in payload["command"]
    assert "--cap-drop" in payload["command"]
    assert f"{root.resolve()}:/srv/weaverssh-9p-root:ro" in payload["command"]


def test_sshx11_9p_service_container_image_build_dry_run(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--runtime",
            "docker",
            "--container-runtime-bin",
            sys.executable,
            "--container-image",
            "weaverssh/wv-9p:test",
            "--state-file",
            str(state),
            "--dry-run",
            "image-build",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = _json(proc)
    assert payload["ok"] is True
    assert payload["status"] == "would_build"
    assert payload["service_runtime"] == "container"
    assert payload["container_runtime"] == "docker"
    assert payload["container_image"] == "weaverssh/wv-9p:test"
    assert "build" in payload["command"]
    assert "-t" in payload["command"]
    assert state.exists()


def test_sshx11_9p_service_host_logs_tail(tmp_path: Path) -> None:
    log_file = tmp_path / "wv-9p.log"
    log_file.write_text("first\nsecond\nthird\n", encoding="utf-8")
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--log-file",
            str(log_file),
            "--logs-tail",
            "2",
            "logs",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = _json(proc)
    assert payload["ok"] is True
    assert payload["service_runtime"] == "host"
    assert payload["exists"] is True
    assert payload["text"] == "second\nthird"


def test_sshx11_9p_service_container_logs_uses_runtime(tmp_path: Path) -> None:
    fake_runtime = tmp_path / "fake-container-runtime.py"
    fake_runtime.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if sys.argv[1:3] == ['logs', '--tail']:\n"
        "    print('tail=' + sys.argv[3])\n"
        "    print('container=' + sys.argv[4])\n"
        "    raise SystemExit(0)\n"
        "print('unexpected:' + repr(sys.argv), file=sys.stderr)\n"
        "raise SystemExit(3)\n",
        encoding="utf-8",
    )
    fake_runtime.chmod(0o755)
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [
            "python3",
            str(SERVICE),
            "--runtime",
            "docker",
            "--container-runtime-bin",
            str(fake_runtime),
            "--container-name",
            "wv-9p-log-test",
            "--state-file",
            str(state),
            "--logs-tail",
            "3",
            "logs",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = _json(proc)
    assert payload["ok"] is True
    assert payload["service_runtime"] == "container"
    assert payload["container_runtime"] == "docker"
    assert payload["container_name"] == "wv-9p-log-test"
    assert "--tail" in payload["command"]
    assert "tail=3" in payload["text"]
    assert "container=wv-9p-log-test" in payload["text"]
