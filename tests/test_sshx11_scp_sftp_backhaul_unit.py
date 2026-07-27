from __future__ import annotations

from pathlib import Path

import pytest

from tools.verification import sshx11_scp_sftp_backhaul as backhaul


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_local_sftp_sshd_config_binds_loopback_x_port() -> None:
    config = backhaul.build_local_sftp_sshd_config(
        listen_port=6017,
        host_key_path="/tmp/sshx11_backhaul/hostkey",
        authorized_keys_path="~/.ssh/authorized_keys",
        sftp_root="/tmp/sshx11_backhaul",
        pid_file="/tmp/sshx11_backhaul/sshd.pid",
    )
    assert "Port 6017" in config
    assert "ListenAddress 127.0.0.1" in config
    assert "Subsystem sftp internal-sftp" in config
    assert "PasswordAuthentication no" in config
    assert "PubkeyAuthentication yes" in config
    assert "KbdInteractiveAuthentication no" in config
    assert "PermitEmptyPasswords no" in config
    assert "AuthenticationMethods publickey" in config


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_local_sftp_sshd_config_authorization_blocks_root_when_not_authorized() -> None:
    config = backhaul.build_local_sftp_sshd_config(
        listen_port=6017,
        host_key_path="/tmp/sshx11_backhaul/hostkey",
        authorized_keys_path="~/.ssh/authorized_keys",
        sftp_root="/tmp/sshx11_backhaul",
        pid_file="/tmp/sshx11_backhaul/sshd.pid",
        authorized_users=["alise"],
        deny_users=["root"],
        enforce_publickey_only=True,
    )
    assert "AllowUsers alise" in config
    assert "DenyUsers root" in config
    assert "PermitRootLogin no" in config


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_local_sftp_sshd_config_supports_non_root_access_levels() -> None:
    config = backhaul.build_local_sftp_sshd_config(
        listen_port=6017,
        host_key_path="/tmp/sshx11_backhaul/hostkey",
        authorized_keys_path="~/.ssh/authorized_keys",
        sftp_root="/tmp/sshx11_backhaul",
        pid_file="/tmp/sshx11_backhaul/sshd.pid",
        user_access_levels={
            "alise": "read-write",
            "kb": "read-only",
            "auditor": "ro",
            "root": "deny",
        },
        enforce_publickey_only=True,
    )
    assert "AllowUsers alise kb auditor" in config
    assert "DenyUsers root" in config
    assert "Match User kb,auditor" in config
    assert "ForceCommand internal-sftp -R -d /tmp/sshx11_backhaul" in config
    assert "AllowTcpForwarding no" in config
    assert "PermitTTY no" in config


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_local_sftp_sshd_config_invalid_access_level_rejected() -> None:
    with pytest.raises(ValueError):
        backhaul.build_local_sftp_sshd_config(
            listen_port=6017,
            host_key_path="/tmp/sshx11_backhaul/hostkey",
            authorized_keys_path="~/.ssh/authorized_keys",
            sftp_root="/tmp/sshx11_backhaul",
            pid_file="/tmp/sshx11_backhaul/sshd.pid",
            user_access_levels={"kb": "superuser"},
        )


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_local_sftp_sshd_start_command_uses_config_and_logfile() -> None:
    cmd = backhaul.build_local_sftp_sshd_start_command(
        sshd_bin="/usr/sbin/sshd",
        config_path="/tmp/sshx11_backhaul/sshd.conf",
        log_file="/tmp/sshx11_backhaul/sshd.log",
        foreground=True,
    )
    assert cmd[:3] == ["/usr/sbin/sshd", "-D", "-f"]
    assert cmd[3] == "/tmp/sshx11_backhaul/sshd.conf"
    assert cmd[-2:] == ["-E", "/tmp/sshx11_backhaul/sshd.log"]


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_reverse_backhaul_start_command_uses_ops_surface_and_parameters() -> None:
    cmd = backhaul.build_reverse_backhaul_start_command(
        remote_user="root",
        remote_host="203.0.113.20",
        remote_port=22,
        remote_bind_port=22022,
        jumps=[("root", "203.0.113.10")],
        identity_file="~/.ssh/id_ed25519",
        forward_agent=True,
        insecure_hostkey=True,
    )
    joined = " ".join(cmd)
    assert cmd[:2] == ["tools/verification/sshx11_ops.sh", "reverse-socks-start"]
    assert "--host 203.0.113.20" in joined
    assert "--user root" in joined
    assert "--port 22" in joined
    assert "--remote-bind-host 127.0.0.1" in joined
    assert "--remote-socks-port 22022" in joined
    assert "--proxy-jump root@203.0.113.10" in joined
    assert "--identity-file" in cmd
    assert "--forward-agent" in cmd
    assert "--insecure-hostkey" in cmd


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_remote_push_command_targets_loopback_bind_port() -> None:
    cmd = backhaul.build_remote_push_to_alise_command(
        alise_user="alise",
        remote_bind_port=22022,
        remote_source_path="/tmp/remote_payload.txt",
        alise_destination_path="/tmp/received_on_alise.txt",
        strict_hostkey=True,
        known_hosts_path="/tmp/alise_known_hosts",
    )
    assert "scp -P 22022" in cmd
    assert "StrictHostKeyChecking=accept-new" in cmd
    assert "UserKnownHostsFile=/tmp/alise_known_hosts" in cmd
    assert "alise@127.0.0.1:/tmp/received_on_alise.txt" in cmd


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_chain_backhaul_scp_command_upload_contains_loopback_target() -> None:
    cmd = backhaul.build_chain_backhaul_scp_command(
        alise_user="alise",
        jumps=[("root", "203.0.113.10"), ("root", "203.0.113.20")],
        remote_bind_port=22022,
        source_path="/tmp/alise_source.txt",
        destination_path="/tmp/remote_seen_on_alise.txt",
        upload=True,
        identity_file="~/.ssh/id_ed25519",
        scp_options=["-o", "BatchMode=yes"],
    )
    joined = " ".join(cmd)
    assert cmd[0] == "scp"
    assert "ProxyJump=root@203.0.113.10,root@203.0.113.20" in joined
    assert "-P 22022" in joined
    assert cmd[-1] == "alise@127.0.0.1:/tmp/remote_seen_on_alise.txt"


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_backhaul_sequence_has_expected_steps_and_paths(tmp_path: Path) -> None:
    sequence = backhaul.build_backhaul_sequence(
        x_port=6019,
        remote_bind_port=23023,
        remote_user="root",
        remote_host="203.0.113.20",
        remote_ssh_port=22,
        alise_user="alise",
        jumps=[("root", "203.0.113.10")],
        state_dir=tmp_path,
        identity_file="~/.ssh/id_ed25519",
    )
    assert sequence["ok"] is True
    assert sequence["x_port"] == 6019
    assert sequence["remote_bind_port"] == 23023
    assert sequence["tunnel_proxy_jump"] == "root@203.0.113.10"
    assert sequence["loopback_scp_proxy_jump"] == "root@203.0.113.10,root@203.0.113.20"
    policy = sequence["authorization_policy"]
    assert policy["authorized_users"] == ["alise"]
    assert policy["read_only_users"] == []
    assert policy["deny_users"] == ["root"]
    assert policy["enforce_publickey_only"] is True
    assert policy["user_access_levels"] == {"alise": "read-write", "root": "deny"}
    assert sequence["paths"]["authorized_keys"].endswith(".ssh/authorized_keys")
    step_ids = [step["id"] for step in sequence["steps"]]
    assert step_ids == [
        "prepare_state",
        "generate_host_key",
        "write_sshd_config",
        "start_local_sftp_server",
        "open_reverse_backhaul",
        "check_reverse_backhaul_status",
        "remote_push_to_alise",
        "chain_scp_to_loopback_endpoint",
        "close_reverse_backhaul",
    ]
    open_step = [step for step in sequence["steps"] if step["id"] == "open_reverse_backhaul"][0]
    assert open_step["command"][:2] == ["tools/verification/sshx11_ops.sh", "reverse-socks-start"]
    status_step = [step for step in sequence["steps"] if step["id"] == "check_reverse_backhaul_status"][0]
    assert status_step["command"][:2] == ["tools/verification/sshx11_ops.sh", "reverse-socks-status"]
    stop_step = [step for step in sequence["steps"] if step["id"] == "close_reverse_backhaul"][0]
    assert stop_step["command"][:2] == ["tools/verification/sshx11_ops.sh", "reverse-socks-stop"]


@pytest.mark.sshx11
@pytest.mark.unit
def test_build_backhaul_sequence_non_root_multi_level_policy(tmp_path: Path) -> None:
    sequence = backhaul.build_backhaul_sequence(
        x_port=6019,
        remote_bind_port=23023,
        remote_user="kb",
        remote_host="203.0.113.20",
        remote_ssh_port=22,
        alise_user="alise",
        jumps=[("kb", "203.0.113.10")],
        state_dir=tmp_path,
        identity_file="~/.ssh/id_ed25519",
        user_access_levels={
            "kb": "read-write",
            "auditor": "read-only",
            "root": "deny",
        },
    )
    policy = sequence["authorization_policy"]
    assert policy["authorized_users"] == ["alise", "kb", "auditor"]
    assert policy["read_only_users"] == ["auditor"]
    assert policy["deny_users"] == ["root"]
    config_preview = [step for step in sequence["steps"] if step["id"] == "write_sshd_config"][0]["config_preview"]
    assert "AllowUsers alise kb auditor" in config_preview
    assert "DenyUsers root" in config_preview
    assert "Match User auditor" in config_preview


@pytest.mark.sshx11
@pytest.mark.unit
def test_port_validation_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        backhaul.build_reverse_backhaul_start_command(
            remote_user="root",
            remote_host="203.0.113.20",
            remote_port=22,
            remote_bind_port=0,
        )
