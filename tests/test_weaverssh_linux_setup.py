from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "packaging" / "linux_setup.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("weaverssh_linux_setup", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_linux_setup_detects_keys_ssh_config_and_generates_profile_command(tmp_path: Path) -> None:
    linux_setup = _load_module()
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    key = ssh_dir / "id_ed25519"
    key.write_text("test-key", encoding="utf-8")
    cfg = ssh_dir / "config"
    cfg.write_text(
        """
Host linode-a
  HostName 203.0.113.10
  User kb
  Port 22
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump jump-a

Host *
  ForwardAgent yes
""",
        encoding="utf-8",
    )

    plan = linux_setup.build_linux_setup_plan(
        home=home,
        env={"SSH_AUTH_SOCK": "/tmp/agent.sock"},
        manager="apt",
        ssh_config_paths=[str(cfg)],
        profile_alias="linode-a",
        platform_name="linux",
    )

    assert plan.ok is True
    assert plan.package_manager == "apt"
    assert plan.ssh_agent.configured is True
    assert any(candidate.exists and candidate.path == str(key) for candidate in plan.key_candidates)
    assert plan.selected_profile is not None
    assert plan.selected_profile.alias == "linode-a"
    assert plan.selected_profile.hostname == "203.0.113.10"
    assert plan.connection_commands == [
        [
            "wv",
            "connection",
            "set",
            "linode-a",
            "--host",
            "203.0.113.10",
            "--user",
            "kb",
            "--port",
            "22",
            "--identity-file",
            "~/.ssh/id_ed25519",
            "--adapter",
            "openSSH",
            "--credential-provider",
            "sshAgent",
            "--active",
        ]
    ]
    assert "wv connection set linode-a" in plan.script


def test_linux_setup_uses_explicit_host_when_no_ssh_config_profile_exists(tmp_path: Path) -> None:
    linux_setup = _load_module()
    plan = linux_setup.build_linux_setup_plan(
        home=tmp_path,
        env={},
        manager="dnf",
        ssh_config_paths=[],
        ssh_host="example.internal",
        ssh_user="alice",
        ssh_port=2222,
        identity_file="~/.ssh/custom",
        platform_name="linux",
    )

    assert plan.ok is True
    assert plan.selected_profile is not None
    assert plan.selected_profile.alias == "example.internal"
    assert plan.selected_profile.user == "alice"
    assert plan.selected_profile.port == 2222
    joined = " ".join(plan.connection_commands[0])
    assert "--host example.internal" in joined
    assert "--identity-file ~/.ssh/custom" in joined
    assert any("no SSH agent socket detected" in note for note in plan.notes)


def test_linux_setup_cli_detect_json_and_emit_script(tmp_path: Path) -> None:
    cfg = tmp_path / "ssh_config"
    cfg.write_text(
        "Host node\n  HostName 10.0.0.5\n  User root\n",
        encoding="utf-8",
    )

    detect = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "detect",
            "--manager",
            "apt",
            "--ssh-config",
            str(cfg),
            "--profile-alias",
            "node",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert detect.returncode == 0, detect.stderr
    payload = json.loads(detect.stdout)
    assert payload["selected_profile"]["alias"] == "node"
    assert payload["connection_commands"][0][:4] == ["wv", "connection", "set", "node"]

    script = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "emit-script",
            "--manager",
            "apt",
            "--ssh-config",
            str(cfg),
            "--profile-alias",
            "node",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert script.returncode == 0, script.stderr
    assert script.stdout.startswith("#!/bin/sh\nset -eu\n")
    assert "wv connection set node" in script.stdout


def test_linux_setup_apply_requires_execute() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "apply", "--manager", "apt", "--ssh-host", "example.invalid"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "requires --execute" in proc.stderr


def test_makefile_exposes_linux_setup_targets() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "platform-setup-plan:" in makefile
    assert "platform-setup-script:" in makefile
    assert "linux-setup-plan:" in makefile
    assert "linux-setup-script:" in makefile
    assert "tools/packaging/linux_setup.py plan --platform" in makefile
    assert "tools/packaging/linux_setup.py emit-script --platform" in makefile


def test_platform_setup_wsl_scans_windows_ssh_config_when_available(tmp_path: Path) -> None:
    linux_setup = _load_module()
    home = tmp_path / "home"
    home.mkdir()
    win_cfg = tmp_path / "mnt" / "c" / "Users" / "Alise" / ".ssh" / "config"
    win_cfg.parent.mkdir(parents=True)
    win_cfg.write_text("Host win-node\n  HostName 192.0.2.10\n  User alise\n", encoding="utf-8")

    plan = linux_setup.build_platform_setup_plan(
        home=home,
        env={"WSL_DISTRO_NAME": "Ubuntu", "USERPROFILE": "C:\\Users\\Alise"},
        platform_name="linux",
        manager="apt",
        ssh_config_paths=[str(win_cfg)],
        profile_alias="win-node",
    )

    assert plan.platform == "wsl"
    assert plan.selected_profile is not None
    assert plan.selected_profile.hostname == "192.0.2.10"
    assert any("WSL route" in note for note in plan.notes)


def test_platform_setup_windows_uses_pageant_and_powershell_style_script(tmp_path: Path) -> None:
    linux_setup = _load_module()
    cfg = tmp_path / "config"
    cfg.write_text("Host win\n  HostName windows.example\n  User bob\n", encoding="utf-8")
    plan = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={"PAGEANT_SSH_AUTH_SOCK": "pageant:"},
        platform_name="windows",
        manager="winget",
        ssh_config_paths=[str(cfg)],
        profile_alias="win",
    )

    assert plan.platform == "windows"
    assert plan.package_manager == "winget"
    assert plan.ssh_agent.provider == "pageant"
    assert "--credential-provider" in plan.connection_commands[0]
    assert "pageant" in plan.connection_commands[0]
    assert plan.script.startswith("# weaverssh Windows setup script")


def test_platform_setup_macos_and_freebsd_dependency_routes(tmp_path: Path) -> None:
    linux_setup = _load_module()
    mac = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={},
        platform_name="macosx",
        manager="brew",
        ssh_host="mac.example",
    )
    assert mac.platform == "macos"
    assert mac.package_manager == "brew"
    assert any(cmd[:2] == ["brew", "install"] for cmd in mac.dependency_commands)

    freebsd = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={},
        platform_name="freebsd",
        manager="pkg",
        ssh_host="freebsd.example",
    )
    assert freebsd.platform == "freebsd"
    assert freebsd.package_manager == "pkg"
    assert freebsd.dependency_commands[0][:4] == ["sudo", "pkg", "install", "-n"]


def test_platform_setup_aix_and_zos_linux_routes(tmp_path: Path) -> None:
    linux_setup = _load_module()
    aix = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={},
        platform_name="aix",
        manager="installp",
        ssh_host="aix.example",
    )
    assert aix.platform == "aix"
    assert aix.package_manager == "installp"
    assert any("AIX package installation" in note for note in aix.notes)

    zos = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={},
        platform_name="linux-on-zos",
        manager="dnf",
        ssh_host="zos.example",
    )
    assert zos.platform == "zos-linux"
    assert zos.package_manager == "dnf"
    assert any("z/OS Linux route" in note for note in zos.notes)


def test_platform_setup_prefers_explicit_gpg_agent_socket(tmp_path: Path) -> None:
    linux_setup = _load_module()
    cfg = tmp_path / "config"
    cfg.write_text("Host gpg-node\n  HostName gpg.example\n  User alise\n", encoding="utf-8")
    plan = linux_setup.build_platform_setup_plan(
        home=tmp_path,
        env={"WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK": "/tmp/S.gpg-agent.ssh"},
        platform_name="linux",
        manager="apt",
        ssh_config_paths=[str(cfg)],
        profile_alias="gpg-node",
    )

    assert plan.ssh_agent.configured is True
    assert plan.ssh_agent.provider == "gpgAgent"
    assert plan.ssh_agent.socket == "/tmp/S.gpg-agent.ssh"
    assert plan.ssh_agent.source == "WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK"
    assert "gpgAgent" in plan.connection_commands[0]
