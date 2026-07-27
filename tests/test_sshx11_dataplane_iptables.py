from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11_dataplane_iptables as fw

SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_dataplane_iptables.py"


def _args(**overrides: object) -> Namespace:
    values = {
        "host": "127.0.0.1",
        "remote_cidr": "127.0.0.1/32",
        "control_port": 8101,
        "bulk_port": 19090,
        "realtime_port": 19091,
        "socks_port": 1080,
        "webdav_port": 8780,
        "ninep_port": 5640,
        "ssh_port": 22,
        "include_webdav": False,
        "include_9p": False,
        "include_ssh_egress": False,
        "allow_non_loopback": False,
        "default_action": "drop",
        "backend": "iptables",
        "ovs_bridge": "br-weaverssh",
        "ovs_openflow_version": "OpenFlow13",
        "k8s_namespace": "weaverssh",
        "k8s_policy_name": "weaverssh-dataplane",
        "k8s_app_label": "weaverssh-data-plane",
    }
    values.update(overrides)
    return Namespace(**values)


def test_default_policy_maps_control_bulk_realtime_and_socks_flows() -> None:
    policy = fw.validate_policy(fw.default_policy(_args()))
    rules = fw.render_rules(policy)
    flow_ids = {rule.flow_id for rule in rules}
    assert {"control_plane_http", "dataplane_bulk", "dataplane_realtime", "socks_local_proxy"} <= flow_ids
    restore = fw.render_restore(policy, rules)
    assert "-A WEAVERSSH_INPUT -p tcp" in restore
    assert "--dport 19090" in restore
    assert "--dport 19091" in restore
    assert "weaverssh-default-drop -j DROP" in restore


def test_optional_file_and_vfs_flows_are_explicit() -> None:
    policy = fw.validate_policy(fw.default_policy(_args(include_webdav=True, include_9p=True)))
    ids = {flow.id for flow in policy.flows}
    assert "webdav_file_endpoint" in ids
    assert "vfs_9p_endpoint" in ids


def test_loopback_only_rejects_non_loopback_custom_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "version": fw.VERSION,
                "loopback_only": True,
                "flows": [
                    {
                        "id": "bad_remote_ingress",
                        "component": "data-plane",
                        "direction": "ingress",
                        "protocol": "tcp",
                        "src_cidr": "10.0.0.0/24",
                        "dst_cidr": "127.0.0.1/32",
                        "dst_port": 19090,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "plan", "--policy-file", str(policy_file), "--format", "json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    payload = json.loads(proc.stderr)
    assert payload["status"] == "rejected"
    assert "loopback_only" in payload["error"]


def test_cli_json_plan_includes_stack_candidates() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "plan", "--include-webdav", "--include-9p", "--format", "json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["stack"]["implemented_backend"] == "iptables-plan"
    names = {item["name"] for item in payload["stack"]["leverage_candidates"]}
    assert {"nftables", "tc/eBPF", "Open vSwitch/OpenFlow", "Kubernetes NetworkPolicy/CiliumNetworkPolicy"} <= names


def test_cli_restore_output_is_iptables_restore_shaped() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "plan", "--format", "restore"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("*filter\n")
    assert "-A INPUT -m comment --comment weaverssh-managed-ingress -j WEAVERSSH_INPUT" in proc.stdout
    assert "-A WEAVERSSH_INPUT -p tcp" in proc.stdout
    assert proc.stdout.rstrip().endswith("COMMIT")


def test_ovs_openflow_renderer_uses_bridge_setup_tables_and_profile_queues() -> None:
    policy = fw.validate_policy(fw.default_policy(_args()))
    ovs = fw.render_ovs_openflow(policy, bridge="br-test", openflow_version="OpenFlow13")
    setup_commands = [" ".join(item["command"]) for item in ovs["setup"]]
    assert "ovs-vsctl --may-exist add-br br-test" in setup_commands
    assert "ovs-vsctl set bridge br-test protocols=OpenFlow13" in setup_commands
    flows = [rule["flow"] for rule in ovs["rules"]]
    assert any("table=0" in flow and "tp_dst=19091" in flow for flow in flows)
    assert any("table=10" in flow and "tp_dst=19091" in flow for flow in flows)
    assert any("table=20" in flow and "set_queue:1,NORMAL" in flow for flow in flows)
    assert any("table=20" in flow and "set_queue:2,NORMAL" in flow for flow in flows)
    assert any("priority=0,actions=drop" in flow for flow in flows)


def test_cli_ovs_json_backend_contains_openflow_payload() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "ovs-openflow",
            "--ovs-bridge",
            "br-test",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["backend"] == "ovs-openflow"
    assert payload["stack"]["implemented_backend"] == "ovs-openflow-plan"
    assert payload["ovs_openflow"]["bridge"] == "br-test"
    assert any(rule["table"] == 20 for rule in payload["ovs_openflow"]["rules"])


def test_cli_ovs_openflow_format_prints_flow_lines_only() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "ovs-openflow",
            "--format",
            "openflow",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ovs-ofctl" not in proc.stdout
    assert "table=0" in proc.stdout
    assert "table=20" in proc.stdout
    assert "actions=drop" in proc.stdout


def test_cli_ovs_shell_format_prints_review_only_commands() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "ovs-openflow",
            "--ovs-bridge",
            "br-test",
            "--format",
            "shell",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "review before running with OVS privileges" in proc.stdout
    assert "ovs-vsctl --may-exist add-br br-test" in proc.stdout
    assert "ovs-ofctl -O OpenFlow13 add-flow br-test" in proc.stdout


def test_cilium_networkpolicy_renderer_maps_ingress_ports_to_manifest() -> None:
    policy = fw.validate_policy(fw.default_policy(_args(include_webdav=True)))
    rendered = fw.render_cilium_networkpolicy(
        policy,
        namespace="weaverssh",
        name="weaverssh-dataplane",
        app_label="weaverssh-data-plane",
    )
    manifest = rendered["manifest"]
    assert manifest["apiVersion"] == "cilium.io/v2"
    assert manifest["kind"] == "CiliumNetworkPolicy"
    assert manifest["metadata"]["namespace"] == "weaverssh"
    assert manifest["spec"]["endpointSelector"]["matchLabels"]["app.kubernetes.io/name"] == "weaverssh-data-plane"
    ingress_ports = {
        port["port"]
        for entry in manifest["spec"]["ingress"]
        for to_ports in entry["toPorts"]
        for port in to_ports["ports"]
    }
    assert {"8101", "19090", "19091", "1080", "8780"} <= ingress_ports
    assert "kind: CiliumNetworkPolicy" in rendered["yaml"]


def test_cli_cilium_json_backend_contains_manifest() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "cilium-networkpolicy",
            "--include-webdav",
            "--k8s-namespace",
            "weaverssh",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["backend"] == "cilium-networkpolicy"
    assert payload["stack"]["implemented_backend"] == "cilium-networkpolicy-plan"
    assert payload["cilium_networkpolicy"]["manifest"]["kind"] == "CiliumNetworkPolicy"
    assert "webdav_file_endpoint" in {flow["id"] for flow in payload["policy"]["flows"]}


def test_cli_cilium_yaml_format_prints_manifest_only() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "cilium-networkpolicy",
            "--format",
            "yaml",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("apiVersion: cilium.io/v2\n")
    assert "kind: CiliumNetworkPolicy" in proc.stdout
    assert 'port: "19090"' in proc.stdout
    assert "kubectl apply" not in proc.stdout


def test_cli_cilium_shell_format_prints_kubectl_apply_plan() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "plan",
            "--backend",
            "cilium-networkpolicy",
            "--format",
            "shell",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "review before applying to a Kubernetes cluster" in proc.stdout
    assert "kubectl apply -f -" in proc.stdout
    assert "kind: CiliumNetworkPolicy" in proc.stdout
