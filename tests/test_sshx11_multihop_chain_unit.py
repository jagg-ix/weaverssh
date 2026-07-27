from __future__ import annotations

import subprocess

import pytest

from tools.verification import sshx11_multihop_chain as chain


def test_build_proxy_jump_with_several_hops() -> None:
    proxy = chain.build_proxy_jump(
        [
            ("root", "10.10.0.1"),
            ("kb", "10.10.0.2"),
            ("ops", "10.10.0.3"),
        ]
    )
    assert proxy == "root@10.10.0.1,kb@10.10.0.2,ops@10.10.0.3"


def test_build_chain_command_contains_proxyjump_and_target() -> None:
    cmd = chain.build_chain_command(
        target_user="root",
        target_host="172.16.0.20",
        target_port=2222,
        jumps=[("root", "172.16.0.10"), ("kb", "172.16.0.11")],
        remote_command="echo CHAIN_OK",
        ssh_options=["-o", "BatchMode=yes"],
        identity_args=["-i", "/tmp/id_ed25519"],
    )
    joined = " ".join(cmd)
    assert "ProxyJump=root@172.16.0.10,kb@172.16.0.11" in joined
    assert "root@172.16.0.20" in joined
    assert "-p 2222" in joined
    assert cmd[-1] == "echo CHAIN_OK"


def test_select_chain_hosts_prefers_known_linode_chain() -> None:
    hosts = [
        ("misc-a", "198.51.100.10"),
        ("linode-a", "203.0.113.10"),
        ("linode-b", "203.0.113.20"),
        ("misc-b", "198.51.100.11"),
    ]
    chosen = chain.select_chain_hosts(hosts)
    assert chosen == [("linode-a", "203.0.113.10"), ("linode-b", "203.0.113.20")]


def test_resolve_identity_path_from_ssh_identity_args() -> None:
    path = chain.resolve_identity_path(["-o", "BatchMode=yes", "-i", "~/.ssh/id_ed25519"])
    assert path.endswith("/.ssh/id_ed25519")


def test_build_scp_chain_command_upload_and_download_contains_proxyjump() -> None:
    upload = chain.build_scp_chain_command(
        target_user="root",
        target_host="172.16.0.20",
        target_port=2222,
        jumps=[("root", "172.16.0.10"), ("kb", "172.16.0.11")],
        source_path="/tmp/local.bin",
        destination_path="/tmp/remote.bin",
        upload=True,
        scp_options=["-o", "BatchMode=yes"],
        identity_args=["-i", "/tmp/id_ed25519"],
    )
    download = chain.build_scp_chain_command(
        target_user="root",
        target_host="172.16.0.20",
        target_port=2222,
        jumps=[("root", "172.16.0.10"), ("kb", "172.16.0.11")],
        source_path="/tmp/remote.bin",
        destination_path="/tmp/local.back.bin",
        upload=False,
        scp_options=["-o", "BatchMode=yes"],
        identity_args=["-i", "/tmp/id_ed25519"],
    )

    joined_up = " ".join(upload)
    joined_down = " ".join(download)
    assert upload[0] == "scp"
    assert download[0] == "scp"
    assert "ProxyJump=root@172.16.0.10,kb@172.16.0.11" in joined_up
    assert "ProxyJump=root@172.16.0.10,kb@172.16.0.11" in joined_down
    assert upload[-1] == "root@172.16.0.20:/tmp/remote.bin"
    assert download[-2] == "root@172.16.0.20:/tmp/remote.bin"
    assert download[-1] == "/tmp/local.back.bin"


def test_run_chain_file_roundtrip_simulated_success(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    source = tmp_path / "source.bin"
    returned = tmp_path / "returned.bin"
    source.write_bytes(b"sshx11-chain-roundtrip-unit-test")

    def _fake_run(cmd: list[str], text: bool, capture_output: bool, check: bool):
        del text, capture_output, check
        if cmd[0] == "scp":
            if cmd[-2].startswith("root@"):
                returned.write_bytes(source.read_bytes())
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(cmd, 0, "CHAIN_OK\nCLEANED_REMOTE_FILE\n", "")
        return subprocess.CompletedProcess(cmd, 1, "", "unexpected command")

    monkeypatch.setattr(chain.subprocess, "run", _fake_run)
    result = chain.run_chain_file_roundtrip(
        jump_user="root",
        jump_host="172.16.0.10",
        target_user="root",
        target_host="172.16.0.20",
        local_source_path=source,
        local_return_path=returned,
        remote_path="/tmp/sshx11_test.bin",
        ssh_options=["-o", "BatchMode=yes"],
        scp_options=["-o", "BatchMode=yes"],
        identity_args=["-i", "/tmp/id_ed25519"],
        target_port=22,
        cleanup_remote=True,
    )
    assert result["ok"] is True
    assert result["upload"]["ok"] is True
    assert result["download"]["ok"] is True
    assert result["sha256"]["match"] is True
    assert result["cleanup"]["attempted"] is True
    assert result["cleanup"]["ok"] is True


def test_run_chain_file_roundtrip_missing_source_raises(tmp_path) -> None:
    missing_source = tmp_path / "missing.bin"
    returned = tmp_path / "returned.bin"
    with pytest.raises(FileNotFoundError):
        chain.run_chain_file_roundtrip(
            jump_user="root",
            jump_host="172.16.0.10",
            target_user="root",
            target_host="172.16.0.20",
            local_source_path=missing_source,
            local_return_path=returned,
        )
