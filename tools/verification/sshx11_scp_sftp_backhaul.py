#!/usr/bin/env python3
from __future__ import annotations

"""Build SCP/SFTP reverse-backhaul command sequences for SSHX11 workflows."""

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Iterable, Mapping


LOOPBACK_HOST = "127.0.0.1"
ACCESS_READ_WRITE = "read-write"
ACCESS_READ_ONLY = "read-only"
ACCESS_DENY = "deny"


@dataclass(frozen=True)
class Hop:
    user: str
    host: str

    def render(self) -> str:
        user_s = str(self.user).strip()
        host_s = str(self.host).strip()
        if not host_s:
            raise ValueError("host must be non-empty")
        if user_s:
            return f"{user_s}@{host_s}"
        return host_s


def _port(port: int, *, name: str) -> int:
    value = int(port)
    if value <= 0 or value > 65535:
        raise ValueError(f"{name} must be in range 1..65535")
    return value


def _text(value: str, *, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} must be non-empty")
    return text


def _username(value: str, *, name: str) -> str:
    user = _text(value, name=name)
    if any(ch.isspace() for ch in user):
        raise ValueError(f"{name} must not contain whitespace")
    return user


def _usernames(values: Iterable[str], *, name: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        user = _username(str(raw), name=name)
        if user not in seen:
            seen.add(user)
            out.append(user)
    return out


def _access_level(value: str, *, name: str) -> str:
    raw = _text(value, name=name).lower().replace("_", "-")
    if raw in {"rw", "write", "readwrite", ACCESS_READ_WRITE}:
        return ACCESS_READ_WRITE
    if raw in {"ro", "readonly", ACCESS_READ_ONLY}:
        return ACCESS_READ_ONLY
    if raw in {"blocked", "none", ACCESS_DENY}:
        return ACCESS_DENY
    raise ValueError(f"{name} must be one of: {ACCESS_READ_WRITE}, {ACCESS_READ_ONLY}, {ACCESS_DENY}")


def _render_access_policy(
    *,
    authorized_users: Iterable[str],
    deny_users: Iterable[str],
    user_access_levels: Mapping[str, str] | None,
) -> tuple[list[str], list[str], list[str]]:
    levels: dict[str, str] = {}

    for user in _usernames((user_access_levels or {}).keys(), name="user_access_levels_user"):
        raw_level = str((user_access_levels or {}).get(user, ""))
        levels[user] = _access_level(raw_level, name=f"user_access_levels[{user}]")

    for user in _usernames(authorized_users, name="authorized_users"):
        levels.setdefault(user, ACCESS_READ_WRITE)

    for user in _usernames(deny_users, name="deny_users"):
        levels[user] = ACCESS_DENY

    allow_users = [user for user, level in levels.items() if level in {ACCESS_READ_WRITE, ACCESS_READ_ONLY}]
    deny = [user for user, level in levels.items() if level == ACCESS_DENY]
    read_only_users = [user for user, level in levels.items() if level == ACCESS_READ_ONLY]
    return allow_users, deny, read_only_users


def to_hops(values: Iterable[tuple[str, str]]) -> list[Hop]:
    return [Hop(user=str(user), host=str(host)) for user, host in values]


def build_proxy_jump(hops: Iterable[tuple[str, str]]) -> str:
    rendered = [hop.render() for hop in to_hops(hops)]
    if not rendered:
        raise ValueError("at least one hop is required")
    return ",".join(rendered)


def build_local_sftp_sshd_config(
    *,
    listen_port: int,
    host_key_path: str | Path,
    authorized_keys_path: str | Path,
    sftp_root: str | Path,
    pid_file: str | Path,
    authorized_users: Iterable[str] | None = None,
    deny_users: Iterable[str] | None = None,
    user_access_levels: Mapping[str, str] | None = None,
    enforce_publickey_only: bool = True,
) -> str:
    port = _port(listen_port, name="listen_port")
    host_key = str(Path(host_key_path).expanduser())
    authorized_keys = str(Path(authorized_keys_path).expanduser())
    root = str(Path(sftp_root).expanduser())
    pid = str(Path(pid_file).expanduser())
    if not host_key:
        raise ValueError("host_key_path must be non-empty")
    if not authorized_keys:
        raise ValueError("authorized_keys_path must be non-empty")
    if not root:
        raise ValueError("sftp_root must be non-empty")
    if not pid:
        raise ValueError("pid_file must be non-empty")
    allow_users, deny, read_only_users = _render_access_policy(
        authorized_users=authorized_users or [],
        deny_users=deny_users or [],
        user_access_levels=user_access_levels,
    )

    lines = [
        f"Port {port}",
        f"ListenAddress {LOOPBACK_HOST}",
        "Protocol 2",
        f"HostKey {host_key}",
        f"PidFile {pid}",
        "PasswordAuthentication no",
        "PubkeyAuthentication yes",
        "KbdInteractiveAuthentication no",
        "PermitEmptyPasswords no",
        f"AuthorizedKeysFile {authorized_keys}",
        "ChallengeResponseAuthentication no",
        "UsePAM no",
        "PermitRootLogin no",
        "AllowAgentForwarding yes",
        "AllowTcpForwarding yes",
        "X11Forwarding no",
        "PermitTunnel no",
        "StrictModes no",
        "PrintMotd no",
        "LogLevel VERBOSE",
        f"Subsystem sftp internal-sftp -d {shlex.quote(root)}",
    ]
    if enforce_publickey_only:
        lines.insert(lines.index(f"AuthorizedKeysFile {authorized_keys}") + 1, "AuthenticationMethods publickey")
    if deny:
        lines.insert(lines.index("PermitRootLogin no") + 1, f"DenyUsers {' '.join(deny)}")
    if allow_users:
        lines.insert(lines.index("PermitRootLogin no") + 1, f"AllowUsers {' '.join(allow_users)}")
    if read_only_users:
        lines.extend(
            [
                "",
                f"Match User {','.join(read_only_users)}",
                f"    ForceCommand internal-sftp -R -d {shlex.quote(root)}",
                "    AllowTcpForwarding no",
                "    X11Forwarding no",
                "    PermitTTY no",
            ]
        )
    return "\n".join(lines) + "\n"


def build_local_sftp_sshd_start_command(
    *,
    sshd_bin: str = "sshd",
    config_path: str | Path,
    log_file: str | Path | None = None,
    foreground: bool = True,
) -> list[str]:
    binary = _text(sshd_bin, name="sshd_bin")
    config = str(Path(config_path).expanduser())
    if not config:
        raise ValueError("config_path must be non-empty")

    cmd = [binary]
    if foreground:
        cmd.append("-D")
    cmd.extend(["-f", config])
    if log_file is not None:
        cmd.extend(["-E", str(Path(log_file).expanduser())])
    return cmd


def _build_reverse_backhaul_ops_command(
    *,
    subcommand: str,
    remote_user: str,
    remote_host: str,
    remote_port: int,
    remote_bind_port: int,
    jumps: Iterable[tuple[str, str]] | None = None,
    identity_file: str | Path | None = None,
    forward_agent: bool = True,
    insecure_hostkey: bool = False,
    ops_script: str | Path = "tools/verification/sshx11_ops.sh",
) -> list[str]:
    command_name = _text(subcommand, name="subcommand")
    if command_name not in {"reverse-socks-start", "reverse-socks-status", "reverse-socks-stop"}:
        raise ValueError("subcommand must be one of reverse-socks-start|reverse-socks-status|reverse-socks-stop")
    user = _text(remote_user, name="remote_user")
    host = _text(remote_host, name="remote_host")
    remote_ssh_port = _port(remote_port, name="remote_port")
    bind_port = _port(remote_bind_port, name="remote_bind_port")
    script = _text(str(ops_script), name="ops_script")

    cmd = [
        script,
        command_name,
        "--host",
        host,
        "--user",
        user,
        "--port",
        str(remote_ssh_port),
        "--remote-bind-host",
        LOOPBACK_HOST,
        "--remote-socks-port",
        str(bind_port),
    ]

    hops = list(jumps or [])
    if hops:
        cmd.extend(["--proxy-jump", build_proxy_jump(hops)])

    if identity_file is not None and str(identity_file).strip():
        cmd.extend(["--identity-file", str(Path(identity_file).expanduser())])

    if forward_agent:
        cmd.append("--forward-agent")
    if insecure_hostkey:
        cmd.append("--insecure-hostkey")
    return cmd


def build_reverse_backhaul_start_command(
    *,
    remote_user: str,
    remote_host: str,
    remote_port: int,
    remote_bind_port: int,
    jumps: Iterable[tuple[str, str]] | None = None,
    identity_file: str | Path | None = None,
    forward_agent: bool = True,
    insecure_hostkey: bool = False,
    ops_script: str | Path = "tools/verification/sshx11_ops.sh",
) -> list[str]:
    return _build_reverse_backhaul_ops_command(
        subcommand="reverse-socks-start",
        remote_user=remote_user,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_bind_port=remote_bind_port,
        jumps=jumps,
        identity_file=identity_file,
        forward_agent=forward_agent,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )


def build_reverse_backhaul_status_command(
    *,
    remote_user: str,
    remote_host: str,
    remote_port: int,
    remote_bind_port: int,
    jumps: Iterable[tuple[str, str]] | None = None,
    identity_file: str | Path | None = None,
    forward_agent: bool = True,
    insecure_hostkey: bool = False,
    ops_script: str | Path = "tools/verification/sshx11_ops.sh",
) -> list[str]:
    return _build_reverse_backhaul_ops_command(
        subcommand="reverse-socks-status",
        remote_user=remote_user,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_bind_port=remote_bind_port,
        jumps=jumps,
        identity_file=identity_file,
        forward_agent=forward_agent,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )


def build_reverse_backhaul_stop_command(
    *,
    remote_user: str,
    remote_host: str,
    remote_port: int,
    remote_bind_port: int,
    jumps: Iterable[tuple[str, str]] | None = None,
    identity_file: str | Path | None = None,
    forward_agent: bool = True,
    insecure_hostkey: bool = False,
    ops_script: str | Path = "tools/verification/sshx11_ops.sh",
) -> list[str]:
    return _build_reverse_backhaul_ops_command(
        subcommand="reverse-socks-stop",
        remote_user=remote_user,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_bind_port=remote_bind_port,
        jumps=jumps,
        identity_file=identity_file,
        forward_agent=forward_agent,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )


def build_reverse_tunnel_command(
    *,
    remote_user: str,
    remote_host: str,
    remote_port: int,
    remote_bind_port: int,
    local_sftp_port: int,
    jumps: Iterable[tuple[str, str]] | None = None,
    identity_file: str | Path | None = None,
    forward_agent: bool = True,
    ssh_options: list[str] | None = None,
) -> list[str]:
    # Backward-compatible wrapper: keep function name used by older tests/callers,
    # but route through the repo-managed reverse-socks ops command surface.
    _ = _port(local_sftp_port, name="local_sftp_port")
    _ = ssh_options
    return build_reverse_backhaul_start_command(
        remote_user=remote_user,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_bind_port=remote_bind_port,
        jumps=jumps,
        identity_file=identity_file,
        forward_agent=forward_agent,
    )


def build_remote_push_to_alise_command(
    *,
    alise_user: str,
    remote_bind_port: int,
    remote_source_path: str | Path,
    alise_destination_path: str | Path,
    strict_hostkey: bool = True,
    known_hosts_path: str | Path | None = None,
) -> str:
    user = _text(alise_user, name="alise_user")
    bind_port = _port(remote_bind_port, name="remote_bind_port")
    remote_source = _text(str(remote_source_path), name="remote_source_path")
    alise_dest = _text(str(alise_destination_path), name="alise_destination_path")

    opts: list[str] = []
    if strict_hostkey:
        opts.extend(["-o", "StrictHostKeyChecking=accept-new"])
    else:
        opts.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
    if known_hosts_path is not None and str(known_hosts_path).strip():
        opts.extend(["-o", f"UserKnownHostsFile={str(Path(known_hosts_path).expanduser())}"])

    parts = [
        "scp",
        "-P",
        str(bind_port),
        *opts,
        shlex.quote(remote_source),
        shlex.quote(f"{user}@{LOOPBACK_HOST}:{alise_dest}"),
    ]
    return " ".join(parts)


def build_chain_backhaul_scp_command(
    *,
    alise_user: str,
    jumps: Iterable[tuple[str, str]],
    remote_bind_port: int,
    source_path: str | Path,
    destination_path: str | Path,
    upload: bool,
    identity_file: str | Path | None = None,
    scp_options: list[str] | None = None,
) -> list[str]:
    user = _text(alise_user, name="alise_user")
    bind_port = _port(remote_bind_port, name="remote_bind_port")
    source = _text(str(source_path), name="source_path")
    destination = _text(str(destination_path), name="destination_path")

    cmd = ["scp"]
    if scp_options:
        cmd.extend(scp_options)
    if identity_file is not None and str(identity_file).strip():
        cmd.extend(["-i", str(Path(identity_file).expanduser())])
    cmd.extend(["-P", str(bind_port)])
    cmd.extend(["-o", f"ProxyJump={build_proxy_jump(jumps)}"])

    target = f"{user}@{LOOPBACK_HOST}:"
    if upload:
        cmd.extend([source, f"{target}{destination}"])
    else:
        cmd.extend([f"{target}{source}", destination])
    return cmd


def build_backhaul_sequence(
    *,
    x_port: int,
    remote_bind_port: int,
    remote_user: str,
    remote_host: str,
    remote_ssh_port: int,
    alise_user: str,
    jumps: Iterable[tuple[str, str]] | None = None,
    state_dir: str | Path = "/tmp/sshx11_scp_backhaul",
    identity_file: str | Path | None = None,
    authorized_keys_path: str | Path = "~/.ssh/authorized_keys",
    user_access_levels: Mapping[str, str] | None = None,
    insecure_hostkey: bool = False,
    ops_script: str | Path = "tools/verification/sshx11_ops.sh",
) -> dict[str, object]:
    local_x_port = _port(x_port, name="x_port")
    bind_port = _port(remote_bind_port, name="remote_bind_port")
    remote_user_s = _text(remote_user, name="remote_user")
    remote_host_s = _text(remote_host, name="remote_host")
    _port(remote_ssh_port, name="remote_ssh_port")
    alise_user_s = _text(alise_user, name="alise_user")

    state = Path(state_dir).expanduser()
    host_key = state / "alise_sshd_host_ed25519"
    config = state / "alise_sshd_config"
    pid_file = state / "alise_sshd.pid"
    log_file = state / "alise_sshd.log"
    known_hosts = state / "alise_known_hosts"
    upload_source = state / "alise_backhaul_probe.txt"
    upload_destination = "/tmp/alise_backhaul_probe.txt"
    remote_push_source = "/tmp/remote_to_alise_backhaul.txt"

    tunnel_jumps = list(jumps or [])
    loopback_scp_jumps = [*tunnel_jumps, (remote_user_s, remote_host_s)]

    keygen_cmd = [
        "ssh-keygen",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        str(host_key),
    ]
    access_levels: dict[str, str] = {
        alise_user_s: ACCESS_READ_WRITE,
        "root": ACCESS_DENY,
    }
    for user, level in (user_access_levels or {}).items():
        access_levels[_username(str(user), name="user_access_levels_user")] = _access_level(
            str(level), name=f"user_access_levels[{user}]"
        )

    config_text = build_local_sftp_sshd_config(
        listen_port=local_x_port,
        host_key_path=host_key,
        authorized_keys_path=Path(authorized_keys_path),
        sftp_root=state,
        pid_file=pid_file,
        user_access_levels=access_levels,
        enforce_publickey_only=True,
    )
    sshd_cmd = build_local_sftp_sshd_start_command(
        config_path=config,
        log_file=log_file,
        foreground=True,
    )
    reverse_start_cmd = build_reverse_backhaul_start_command(
        remote_user=remote_user_s,
        remote_host=remote_host_s,
        remote_port=remote_ssh_port,
        remote_bind_port=bind_port,
        jumps=tunnel_jumps,
        identity_file=identity_file,
        forward_agent=True,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )
    reverse_status_cmd = build_reverse_backhaul_status_command(
        remote_user=remote_user_s,
        remote_host=remote_host_s,
        remote_port=remote_ssh_port,
        remote_bind_port=bind_port,
        jumps=tunnel_jumps,
        identity_file=identity_file,
        forward_agent=True,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )
    reverse_stop_cmd = build_reverse_backhaul_stop_command(
        remote_user=remote_user_s,
        remote_host=remote_host_s,
        remote_port=remote_ssh_port,
        remote_bind_port=bind_port,
        jumps=tunnel_jumps,
        identity_file=identity_file,
        forward_agent=True,
        insecure_hostkey=insecure_hostkey,
        ops_script=ops_script,
    )
    remote_push_cmd = build_remote_push_to_alise_command(
        alise_user=alise_user_s,
        remote_bind_port=bind_port,
        remote_source_path=remote_push_source,
        alise_destination_path="/tmp/received_from_remote_via_backhaul.txt",
        strict_hostkey=True,
        known_hosts_path=known_hosts,
    )
    chain_upload_cmd = build_chain_backhaul_scp_command(
        alise_user=alise_user_s,
        jumps=loopback_scp_jumps,
        remote_bind_port=bind_port,
        source_path=upload_source,
        destination_path=upload_destination,
        upload=True,
        identity_file=identity_file,
        scp_options=["-o", "BatchMode=yes"],
    )

    steps = [
        {
            "id": "prepare_state",
            "description": "Create local state directory for temporary host keys, config, and logs.",
            "command": ["mkdir", "-p", str(state)],
        },
        {
            "id": "generate_host_key",
            "description": "Create ephemeral host key for loopback-only SCP/SFTP sshd instance.",
            "command": keygen_cmd,
        },
        {
            "id": "write_sshd_config",
            "description": "Write sshd config that binds only 127.0.0.1 on the selected X-style TCP port.",
            "command": ["cat", ">", str(config)],
            "config_preview": config_text,
        },
        {
            "id": "start_local_sftp_server",
            "description": "Start local SCP/SFTP server on Alise workstation.",
            "command": sshd_cmd,
        },
        {
            "id": "open_reverse_backhaul",
            "description": "Use SSHX11 operator infrastructure to open reverse backhaul on remote localhost:bind_port.",
            "command": reverse_start_cmd,
        },
        {
            "id": "check_reverse_backhaul_status",
            "description": "Inspect reverse backhaul status using the managed reverse-socks status command.",
            "command": reverse_status_cmd,
        },
        {
            "id": "remote_push_to_alise",
            "description": "From remote host shell, push a file to Alise over the reverse tunnel endpoint.",
            "command_shell": remote_push_cmd,
        },
        {
            "id": "chain_scp_to_loopback_endpoint",
            "description": "From Alise, run SCP through ProxyJump chain to user@127.0.0.1:bind_port.",
            "command": chain_upload_cmd,
        },
        {
            "id": "close_reverse_backhaul",
            "description": "Close reverse backhaul process cleanly through SSHX11 operator command.",
            "command": reverse_stop_cmd,
        },
    ]

    return {
        "ok": True,
        "x_port": local_x_port,
        "remote_bind_port": bind_port,
        "remote": {
            "user": remote_user_s,
            "host": remote_host_s,
            "ssh_port": int(remote_ssh_port),
        },
        "alise_user": alise_user_s,
        "reverse_backhaul_provider": "sshx11_ops_reverse_socks",
        "state_dir": str(state),
        "paths": {
            "host_key": str(host_key),
            "config": str(config),
            "pid_file": str(pid_file),
            "log_file": str(log_file),
            "known_hosts": str(known_hosts),
            "authorized_keys": str(Path(authorized_keys_path).expanduser()),
        },
        "authorization_policy": {
            "user_access_levels": access_levels,
            "authorized_users": [user for user, level in access_levels.items() if level in {ACCESS_READ_WRITE, ACCESS_READ_ONLY}],
            "read_only_users": [user for user, level in access_levels.items() if level == ACCESS_READ_ONLY],
            "deny_users": [user for user, level in access_levels.items() if level == ACCESS_DENY],
            "enforce_publickey_only": True,
            "authorized_keys_path": str(Path(authorized_keys_path).expanduser()),
        },
        "tunnel_proxy_jump": build_proxy_jump(tunnel_jumps) if tunnel_jumps else "",
        "loopback_scp_proxy_jump": build_proxy_jump(loopback_scp_jumps),
        "steps": steps,
    }
