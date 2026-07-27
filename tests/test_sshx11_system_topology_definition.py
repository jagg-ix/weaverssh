from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "tools/verification/tla/sshx11_workbench/compose.system.yaml"
DOCKER_FALLBACK = Path("/Applications/Docker.app/Contents/Resources/bin/docker")


def _parse_block_names(text: str, block_name: str) -> set[str]:
    names: set[str] = set()
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not in_block:
            if line == f"{block_name}:":
                in_block = True
            continue
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            names.add(line.strip()[:-1])
    return names


def _docker_bin() -> str | None:
    system = shutil.which("docker")
    if system:
        return system
    if DOCKER_FALLBACK.exists():
        return str(DOCKER_FALLBACK)
    return None


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


@pytest.mark.sshx11
@pytest.mark.system
def test_compose_system_topology_has_required_services_and_networks() -> None:
    assert COMPOSE_FILE.exists(), f"missing topology file: {COMPOSE_FILE}"
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    services = _parse_block_names(text, "services")
    networks = _parse_block_names(text, "networks")

    required_services = {
        "sshd",
        "bastion",
        "socks5",
        "websocket_gateway",
        "transport_gateway",
        "x11_probe",
    }
    required_networks = {"control_plane", "data_plane"}
    assert required_services.issubset(services), (
        f"missing services: {sorted(required_services - services)}"
    )
    assert required_networks.issubset(networks), (
        f"missing networks: {sorted(required_networks - networks)}"
    )


@pytest.mark.sshx11
@pytest.mark.system
def test_compose_system_topology_config_is_renderable() -> None:
    docker = _docker_bin()
    if not docker:
        pytest.skip("docker binary not available; cannot validate compose render")

    compose_version = _run([docker, "compose", "version"])
    if compose_version.returncode != 0:
        pytest.skip(
            "docker compose plugin unavailable; cannot validate render: "
            + compose_version.stderr.strip()
        )

    rendered = _run([docker, "compose", "-f", str(COMPOSE_FILE), "config"])
    assert rendered.returncode == 0, rendered.stderr
    assert "services:" in rendered.stdout
    assert "sshd:" in rendered.stdout
