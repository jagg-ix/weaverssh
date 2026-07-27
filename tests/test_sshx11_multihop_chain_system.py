from __future__ import annotations

import json
import time

import pytest

from tests.sshx11_remote_testlib import (
    choose_auth_for_hosts,
    discover_hosts,
    discover_users,
    identity_opt,
    remote_auth_required,
    ssh_opts,
)
from tools.verification import sshx11_multihop_chain as chain


@pytest.fixture(scope="module")
def chain_targets() -> list[tuple[str, str, str]]:
    hosts = discover_hosts()
    selected_hosts = chain.select_chain_hosts(hosts)
    if len(selected_hosts) < 2:
        pytest.skip("Need at least two discovered hosts for multi-hop chain test.")

    attempts, selected_users = choose_auth_for_hosts(selected_hosts, discover_users("root,kb"))
    resolved: list[tuple[str, str, str]] = []
    for label, host in selected_hosts:
        user = selected_users.get(host)
        if user:
            resolved.append((label, host, user))
    if len(resolved) < 2:
        msg = "Unable to authenticate both chain hosts.\n" + json.dumps(attempts, indent=2)
        if remote_auth_required():
            pytest.fail(msg)
        pytest.skip(msg)
    return resolved[:2]


@pytest.mark.sshx11
@pytest.mark.system
def test_sshx11_multihop_chain_bidirectional_with_two_linode_hosts(
    chain_targets: list[tuple[str, str, str]],
) -> None:
    first = chain_targets[0]
    second = chain_targets[1]
    directions = [
        {"jump": first, "target": second},
        {"jump": second, "target": first},
    ]

    results: list[dict[str, object]] = []
    for item in directions:
        jump_label, jump_host, jump_user = item["jump"]
        target_label, target_host, target_user = item["target"]
        remote_cmd = (
            "echo CHAIN_OK "
            f"&& echo JUMP_LABEL={jump_label} TARGET_LABEL={target_label} "
            "&& whoami && hostname"
        )
        probe = chain.run_chain_probe(
            jump_user=jump_user,
            jump_host=jump_host,
            target_user=target_user,
            target_host=target_host,
            remote_command=remote_cmd,
            ssh_options=ssh_opts(),
            identity_args=identity_opt(),
            target_port=22,
        )
        probe["jump"] = {"label": jump_label, "host": jump_host, "user": jump_user}
        probe["target_label"] = target_label
        results.append(probe)

    failures = [r for r in results if not bool(r.get("ok"))]
    assert not failures, json.dumps(results, indent=2)
    for probe in results:
        stdout = str(probe.get("stdout", ""))
        assert "CHAIN_OK" in stdout
        assert "TARGET_LABEL=" in stdout
        joined = " ".join(probe["command"])  # type: ignore[index]
        assert "ProxyJump=" in joined


@pytest.mark.sshx11
@pytest.mark.system
def test_sshx11_multihop_chain_file_roundtrip_back_to_origin(
    chain_targets: list[tuple[str, str, str]],
    tmp_path,
) -> None:
    first = chain_targets[0]
    second = chain_targets[1]
    directions = [
        {"jump": first, "target": second},
        {"jump": second, "target": first},
    ]

    source = tmp_path / "chain_roundtrip_source.json"
    source.write_text(
        json.dumps(
            {
                "kind": "sshx11_chain_roundtrip",
                "generated_at_unix": int(time.time()),
                "note": "transfer from origin to endpoint and back through ProxyJump chain",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    results: list[dict[str, object]] = []
    for item in directions:
        jump_label, jump_host, jump_user = item["jump"]
        target_label, target_host, target_user = item["target"]
        returned = tmp_path / f"chain_roundtrip_returned_{target_host.replace('.', '_')}.json"
        remote_path = f"/tmp/sshx11_chain_roundtrip_{target_host.replace('.', '_')}_{int(time.time())}.json"
        transfer = chain.run_chain_file_roundtrip(
            jump_user=jump_user,
            jump_host=jump_host,
            target_user=target_user,
            target_host=target_host,
            local_source_path=source,
            local_return_path=returned,
            remote_path=remote_path,
            ssh_options=ssh_opts(),
            scp_options=ssh_opts(),
            identity_args=identity_opt(),
            target_port=22,
            cleanup_remote=True,
        )
        transfer["jump"] = {"label": jump_label, "host": jump_host, "user": jump_user}
        transfer["target_label"] = target_label
        results.append(transfer)

    failures = [r for r in results if not bool(r.get("ok"))]
    assert not failures, json.dumps(results, indent=2)
    for transfer in results:
        assert transfer["sha256"]["match"] is True  # type: ignore[index]
        assert transfer["upload"]["ok"] is True  # type: ignore[index]
        assert transfer["download"]["ok"] is True  # type: ignore[index]
        assert transfer["cleanup"]["attempted"] is True  # type: ignore[index]
