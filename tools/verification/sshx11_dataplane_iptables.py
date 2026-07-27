#!/usr/bin/env python3
from __future__ import annotations

"""Describe dataplane connection/dataflow control rules for weaverssh.

The tool is intentionally non-destructive: it renders policy and backend command
plans, but never applies rules itself.
"""

import argparse
import ipaddress
import json
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

VERSION = "weaverssh.dataplane.firewall.v1"
DEFAULT_INPUT_CHAIN = "WEAVERSSH_INPUT"
DEFAULT_OUTPUT_CHAIN = "WEAVERSSH_OUTPUT"
DEFAULT_FORWARD_CHAIN = "WEAVERSSH_FORWARD"
VALID_DIRECTIONS = {"ingress", "egress", "forward"}
VALID_PROTOCOLS = {"tcp", "udp"}
VALID_ACTIONS = {"accept", "drop", "reject"}
VALID_BACKENDS = {"iptables", "ovs-openflow", "cilium-networkpolicy"}
OVS_COOKIE_BASE = 0x5756534800000000


@dataclass(frozen=True)
class DataplaneFlow:
    id: str
    component: str
    direction: str
    protocol: str
    dst_port: int
    action: str = "accept"
    src_cidr: str = "127.0.0.1/32"
    dst_cidr: str = "127.0.0.1/32"
    profile: str = "control"
    comment: str = ""


@dataclass(frozen=True)
class FirewallPolicy:
    version: str = VERSION
    default_action: str = "drop"
    input_chain: str = DEFAULT_INPUT_CHAIN
    output_chain: str = DEFAULT_OUTPUT_CHAIN
    forward_chain: str = DEFAULT_FORWARD_CHAIN
    allow_established: bool = True
    loopback_only: bool = True
    flows: list[DataplaneFlow] = field(default_factory=list)


@dataclass(frozen=True)
class RenderedRule:
    flow_id: str
    table: str
    chain: str
    command: list[str]
    restore_line: str
    description: str


@dataclass(frozen=True)
class RenderedOpenFlowRule:
    flow_id: str
    table: int
    priority: int
    command: list[str]
    flow: str
    description: str


def _chain_for(policy: FirewallPolicy, direction: str) -> str:
    if direction == "egress":
        return policy.output_chain
    if direction == "forward":
        return policy.forward_chain
    return policy.input_chain


def _base_chain_for(direction: str) -> str:
    if direction == "egress":
        return "OUTPUT"
    if direction == "forward":
        return "FORWARD"
    return "INPUT"


def _iptables_action(action: str) -> str:
    return {"accept": "ACCEPT", "drop": "DROP", "reject": "REJECT"}[action]


def _quote_comment(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._:-/" else "_" for ch in value).strip("_")
    return safe[:240] if safe else "weaverssh dataplane rule"


def _normalize_cidr(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("CIDR value cannot be empty")
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        ip = ipaddress.ip_address(raw)
        suffix = 32 if ip.version == 4 else 128
        return f"{ip}/{suffix}"


def _is_loopback_cidr(value: str) -> bool:
    network = ipaddress.ip_network(value, strict=False)
    return bool(network.is_loopback)


def _validate_name(value: str, *, field_name: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field_name} cannot be empty")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    if any(ch not in allowed for ch in raw):
        raise ValueError(f"{field_name} contains unsupported characters: {raw!r}")
    return raw


def _flow_from_dict(payload: dict[str, Any]) -> DataplaneFlow:
    return DataplaneFlow(
        id=str(payload.get("id", "")).strip(),
        component=str(payload.get("component", "dataplane")).strip(),
        direction=str(payload.get("direction", "ingress")).strip().lower(),
        protocol=str(payload.get("protocol", "tcp")).strip().lower(),
        dst_port=int(payload.get("dst_port", 0)),
        action=str(payload.get("action", "accept")).strip().lower(),
        src_cidr=str(payload.get("src_cidr", "127.0.0.1/32")).strip(),
        dst_cidr=str(payload.get("dst_cidr", "127.0.0.1/32")).strip(),
        profile=str(payload.get("profile", "control")).strip(),
        comment=str(payload.get("comment", "")).strip(),
    )


def _policy_from_dict(payload: dict[str, Any]) -> FirewallPolicy:
    return FirewallPolicy(
        version=str(payload.get("version", VERSION)).strip(),
        default_action=str(payload.get("default_action", "drop")).strip().lower(),
        input_chain=str(payload.get("input_chain", DEFAULT_INPUT_CHAIN)).strip(),
        output_chain=str(payload.get("output_chain", DEFAULT_OUTPUT_CHAIN)).strip(),
        forward_chain=str(payload.get("forward_chain", DEFAULT_FORWARD_CHAIN)).strip(),
        allow_established=bool(payload.get("allow_established", True)),
        loopback_only=bool(payload.get("loopback_only", True)),
        flows=[_flow_from_dict(item) for item in payload.get("flows", [])],
    )


def validate_policy(policy: FirewallPolicy, *, allow_non_loopback: bool = False) -> FirewallPolicy:
    if policy.version != VERSION:
        raise ValueError(f"unsupported policy version {policy.version!r}")
    if policy.default_action not in {"drop", "reject", "accept"}:
        raise ValueError("default_action must be drop, reject, or accept")
    _validate_name(policy.input_chain, field_name="input_chain")
    _validate_name(policy.output_chain, field_name="output_chain")
    _validate_name(policy.forward_chain, field_name="forward_chain")
    seen: set[str] = set()
    normalized: list[DataplaneFlow] = []
    for flow in policy.flows:
        fid = _validate_name(flow.id, field_name="flow.id")
        if fid in seen:
            raise ValueError(f"duplicate flow id: {fid}")
        seen.add(fid)
        if flow.direction not in VALID_DIRECTIONS:
            raise ValueError(f"flow {fid}: direction must be ingress, egress, or forward")
        if flow.protocol not in VALID_PROTOCOLS:
            raise ValueError(f"flow {fid}: protocol must be tcp or udp")
        if flow.action not in VALID_ACTIONS:
            raise ValueError(f"flow {fid}: action must be accept, drop, or reject")
        if int(flow.dst_port) <= 0 or int(flow.dst_port) > 65535:
            raise ValueError(f"flow {fid}: dst_port out of range")
        src = _normalize_cidr(flow.src_cidr)
        dst = _normalize_cidr(flow.dst_cidr)
        if policy.loopback_only and not allow_non_loopback:
            if not _is_loopback_cidr(src) or not _is_loopback_cidr(dst):
                raise ValueError(f"flow {fid}: loopback_only policy rejects non-loopback CIDR")
        normalized.append(
            DataplaneFlow(
                id=fid,
                component=_validate_name(flow.component, field_name=f"flow {fid} component"),
                direction=flow.direction,
                protocol=flow.protocol,
                dst_port=int(flow.dst_port),
                action=flow.action,
                src_cidr=src,
                dst_cidr=dst,
                profile=_validate_name(flow.profile or "default", field_name=f"flow {fid} profile"),
                comment=flow.comment,
            )
        )
    return FirewallPolicy(
        version=policy.version,
        default_action=policy.default_action,
        input_chain=policy.input_chain,
        output_chain=policy.output_chain,
        forward_chain=policy.forward_chain,
        allow_established=bool(policy.allow_established),
        loopback_only=bool(policy.loopback_only),
        flows=normalized,
    )


def default_policy(args: argparse.Namespace) -> FirewallPolicy:
    host = str(args.host)
    local_cidr = _normalize_cidr(host)
    remote_cidr = _normalize_cidr(str(args.remote_cidr))
    flows = [
        DataplaneFlow(
            id="control_plane_http",
            component="control-plane",
            direction="ingress",
            protocol="tcp",
            src_cidr=local_cidr,
            dst_cidr=local_cidr,
            dst_port=int(args.control_port),
            profile="control",
            comment="control plane health policy state endpoints",
        ),
        DataplaneFlow(
            id="dataplane_bulk",
            component="data-plane",
            direction="ingress",
            protocol="tcp",
            src_cidr=local_cidr,
            dst_cidr=local_cidr,
            dst_port=int(args.bulk_port),
            profile="bulk",
            comment="bulk relay profile",
        ),
        DataplaneFlow(
            id="dataplane_realtime",
            component="data-plane",
            direction="ingress",
            protocol="tcp",
            src_cidr=local_cidr,
            dst_cidr=local_cidr,
            dst_port=int(args.realtime_port),
            profile="realtime",
            comment="realtime relay profile",
        ),
        DataplaneFlow(
            id="socks_local_proxy",
            component="socks-proxy",
            direction="ingress",
            protocol="tcp",
            src_cidr=local_cidr,
            dst_cidr=local_cidr,
            dst_port=int(args.socks_port),
            profile="socks",
            comment="local SOCKS proxy endpoint",
        ),
    ]
    if bool(args.include_webdav):
        flows.append(
            DataplaneFlow(
                id="webdav_file_endpoint",
                component="webdav",
                direction="ingress",
                protocol="tcp",
                src_cidr=local_cidr,
                dst_cidr=local_cidr,
                dst_port=int(args.webdav_port),
                profile="file-transfer",
                comment="optional WebDAV file endpoint",
            )
        )
    if bool(args.include_9p):
        flows.append(
            DataplaneFlow(
                id="vfs_9p_endpoint",
                component="vfs-9p",
                direction="ingress",
                protocol="tcp",
                src_cidr=local_cidr,
                dst_cidr=local_cidr,
                dst_port=int(args.ninep_port),
                profile="vfs",
                comment="optional read-only 9P VFS endpoint",
            )
        )
    if bool(args.include_ssh_egress):
        flows.append(
            DataplaneFlow(
                id="ssh_chain_egress",
                component="ssh-chain",
                direction="egress",
                protocol="tcp",
                src_cidr=local_cidr,
                dst_cidr=remote_cidr,
                dst_port=int(args.ssh_port),
                profile="ssh-chain",
                comment="controlled SSH chain egress",
            )
        )
    return FirewallPolicy(default_action=str(args.default_action), loopback_only=not bool(args.allow_non_loopback), flows=flows)


def render_rules(policy: FirewallPolicy) -> list[RenderedRule]:
    rules: list[RenderedRule] = []
    for flow in policy.flows:
        chain = _chain_for(policy, flow.direction)
        target = _iptables_action(flow.action)
        comment = _quote_comment(f"weaverssh:{flow.id}:{flow.component}:{flow.profile} {flow.comment}")
        command = [
            "iptables",
            "-A",
            chain,
            "-p",
            flow.protocol,
            "-s",
            flow.src_cidr,
            "-d",
            flow.dst_cidr,
            "--dport",
            str(flow.dst_port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            target,
        ]
        restore_line = " ".join(command[1:])
        rules.append(
            RenderedRule(
                flow_id=flow.id,
                table="filter",
                chain=chain,
                command=command,
                restore_line=restore_line,
                description=f"{flow.direction} {flow.protocol}/{flow.dst_port} {flow.src_cidr}->{flow.dst_cidr} {target}",
            )
        )
    return rules


def render_restore(policy: FirewallPolicy, rules: list[RenderedRule]) -> str:
    chains = [policy.input_chain, policy.output_chain, policy.forward_chain]
    lines = ["*filter"]
    for chain in chains:
        lines.append(f":{chain} - [0:0]")
    for direction, chain in (("ingress", policy.input_chain), ("egress", policy.output_chain), ("forward", policy.forward_chain)):
        base = _base_chain_for(direction)
        lines.append(f"-A {base} -m comment --comment weaverssh-managed-{direction} -j {chain}")
        if policy.allow_established:
            lines.append(f"-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    for rule in rules:
        lines.append(rule.restore_line)
    if policy.default_action in {"drop", "reject"}:
        target = _iptables_action(policy.default_action)
        for chain in chains:
            lines.append(f"-A {chain} -m comment --comment weaverssh-default-{policy.default_action} -j {target}")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def render_idempotent_shell(policy: FirewallPolicy, rules: list[RenderedRule]) -> list[str]:
    lines = ["# generated by sshx11_dataplane_iptables.py; review before running as root"]
    for direction, chain in (("ingress", policy.input_chain), ("egress", policy.output_chain), ("forward", policy.forward_chain)):
        base = _base_chain_for(direction)
        lines.append(f"iptables -N {chain} 2>/dev/null || true")
        lines.append(f"iptables -F {chain}")
        jump = f"-m comment --comment weaverssh-managed-{direction} -j {chain}"
        lines.append(f"iptables -C {base} {jump} 2>/dev/null || iptables -I {base} 1 {jump}")
        if policy.allow_established:
            lines.append(f"iptables -A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    for rule in rules:
        lines.append(" ".join(rule.command))
    if policy.default_action in {"drop", "reject"}:
        target = _iptables_action(policy.default_action)
        for chain in (policy.input_chain, policy.output_chain, policy.forward_chain):
            lines.append(f"iptables -A {chain} -m comment --comment weaverssh-default-{policy.default_action} -j {target}")
    return lines


def _ovs_profile_queue(profile: str) -> int:
    return {
        "realtime": 1,
        "bulk": 2,
        "control": 3,
        "socks": 4,
        "file-transfer": 5,
        "vfs": 6,
        "ssh-chain": 7,
    }.get(str(profile or "").strip().lower(), 9)


def _ovs_cookie(index: int) -> str:
    return f"0x{OVS_COOKIE_BASE + max(0, int(index)):016x}"


def _ovs_match(flow: DataplaneFlow) -> str:
    src = ipaddress.ip_network(flow.src_cidr, strict=False)
    dst = ipaddress.ip_network(flow.dst_cidr, strict=False)
    if src.version != 4 or dst.version != 4:
        raise ValueError(f"flow {flow.id}: ovs-openflow renderer currently supports IPv4 CIDRs only")
    return ",".join(
        [
            flow.protocol,
            f"nw_src={src}",
            f"nw_dst={dst}",
            f"tp_dst={int(flow.dst_port)}",
        ]
    )


def render_ovs_openflow(
    policy: FirewallPolicy,
    *,
    bridge: str = "br-weaverssh",
    openflow_version: str = "OpenFlow13",
) -> dict[str, Any]:
    bridge = _validate_name(bridge, field_name="ovs_bridge")
    openflow_version = _validate_name(openflow_version, field_name="ovs_openflow_version")
    setup = [
        {
            "description": "create OVS bridge if missing",
            "command": ["ovs-vsctl", "--may-exist", "add-br", bridge],
        },
        {
            "description": "enable requested OpenFlow protocol on bridge",
            "command": ["ovs-vsctl", "set", "bridge", bridge, f"protocols={openflow_version}"],
        },
        {
            "description": "remove previously generated weaverssh OpenFlow entries by cookie mask",
            "command": [
                "ovs-ofctl",
                "-O",
                openflow_version,
                "del-flows",
                bridge,
                f"cookie={_ovs_cookie(0)}/0xffffffff00000000",
            ],
        },
    ]
    rules: list[RenderedOpenFlowRule] = []
    for idx, flow in enumerate(policy.flows, start=1):
        match = _ovs_match(flow)
        cookie = _ovs_cookie(idx)
        classify = f"cookie={cookie},table=0,priority=200,{match},actions=resubmit(,10)"
        authorize = f"cookie={cookie},table=10,priority=200,{match},actions=resubmit(,20)"
        action = "drop"
        if flow.action == "accept":
            action = f"set_queue:{_ovs_profile_queue(flow.profile)},NORMAL"
        enforce = f"cookie={cookie},table=20,priority=200,{match},actions={action}"
        for table, flow_text, description in (
            (0, classify, f"classify {flow.id} as {flow.profile}"),
            (10, authorize, f"authorize {flow.id} by CIDR and port"),
            (20, enforce, f"enforce {flow.id} action {flow.action}"),
        ):
            rules.append(
                RenderedOpenFlowRule(
                    flow_id=flow.id,
                    table=table,
                    priority=200,
                    command=["ovs-ofctl", "-O", openflow_version, "add-flow", bridge, flow_text],
                    flow=flow_text,
                    description=description,
                )
            )
    default_action = "drop" if policy.default_action in {"drop", "reject"} else "NORMAL"
    for table in (0, 10, 20):
        flow_text = f"cookie={_ovs_cookie(0)},table={table},priority=0,actions={default_action}"
        rules.append(
            RenderedOpenFlowRule(
                flow_id=f"default_{policy.default_action}_table_{table}",
                table=table,
                priority=0,
                command=["ovs-ofctl", "-O", openflow_version, "add-flow", bridge, flow_text],
                flow=flow_text,
                description=f"default {policy.default_action} for table {table}",
            )
        )
    return {
        "bridge": bridge,
        "openflow_version": openflow_version,
        "setup": setup,
        "rules": [asdict(rule) for rule in rules],
        "shell": render_ovs_shell(setup, rules),
    }


def render_ovs_shell(setup: list[dict[str, Any]], rules: list[RenderedOpenFlowRule]) -> list[str]:
    lines = ["# generated by sshx11_dataplane_iptables.py; review before running with OVS privileges"]
    for item in setup:
        lines.append(" ".join(str(part) for part in item["command"]))
    for rule in rules:
        lines.append(" ".join(rule.command))
    return lines


def _yaml_scalar(value: object) -> str:
    text = str(value)
    if text == "":
        return '""'
    if text.isdigit():
        return json.dumps(text)
    if any(ch in text for ch in ":#{}[],&*?|-<>=!%@`\"'\\n") or text.lower() in {"true", "false", "null"}:
        return json.dumps(text)
    return text


def _cilium_direction_key(direction: str, action: str) -> str:
    if direction == "egress":
        return "egressDeny" if action in {"drop", "reject"} else "egress"
    return "ingressDeny" if action in {"drop", "reject"} else "ingress"


def _cilium_entry(flow: DataplaneFlow) -> dict[str, Any]:
    proto = flow.protocol.upper()
    if flow.direction == "forward":
        raise ValueError(f"flow {flow.id}: cilium-networkpolicy does not support forward direction")
    if flow.direction == "egress":
        return {
            "toCIDRSet": [{"cidr": flow.dst_cidr}],
            "toPorts": [{"ports": [{"port": str(flow.dst_port), "protocol": proto}]}],
        }
    return {
        "fromCIDRSet": [{"cidr": flow.src_cidr}],
        "toPorts": [{"ports": [{"port": str(flow.dst_port), "protocol": proto}]}],
    }


def _render_yaml_value(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.extend(_render_yaml_value(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                if not item:
                    lines.append(f"{pad}- {{}}")
                    continue
                first = True
                for key, nested in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    if isinstance(nested, (dict, list)):
                        lines.append(f"{prefix}{key}:")
                        lines.extend(_render_yaml_value(nested, indent + 4))
                    else:
                        lines.append(f"{prefix}{key}: {_yaml_scalar(nested)}")
                    first = False
            elif isinstance(item, list):
                lines.append(f"{pad}-")
                lines.extend(_render_yaml_value(item, indent + 2))
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return lines
    return [f"{pad}{_yaml_scalar(value)}"]


def render_cilium_networkpolicy(
    policy: FirewallPolicy,
    *,
    namespace: str = "weaverssh",
    name: str = "weaverssh-dataplane",
    app_label: str = "weaverssh-data-plane",
) -> dict[str, Any]:
    namespace = _validate_name(namespace, field_name="k8s_namespace")
    name = _validate_name(name, field_name="k8s_policy_name")
    app_label = _validate_name(app_label, field_name="k8s_app_label")
    sections: dict[str, list[dict[str, Any]]] = {"ingress": [], "egress": [], "ingressDeny": [], "egressDeny": []}
    for flow in policy.flows:
        sections[_cilium_direction_key(flow.direction, flow.action)].append(_cilium_entry(flow))
    spec: dict[str, Any] = {
        "endpointSelector": {
            "matchLabels": {
                "app.kubernetes.io/name": app_label,
            }
        }
    }
    for key in ("ingress", "egress", "ingressDeny", "egressDeny"):
        if sections[key]:
            spec[key] = sections[key]
    manifest = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }
    yaml = "\n".join(_render_yaml_value(manifest)) + "\n"
    return {
        "namespace": namespace,
        "name": name,
        "app_label": app_label,
        "manifest": manifest,
        "yaml": yaml,
        "shell": [
            "# generated by sshx11_dataplane_iptables.py; review before applying to a Kubernetes cluster",
            "cat <<'YAML' | kubectl apply -f -",
            yaml.rstrip(),
            "YAML",
        ],
    }


def stack_inspection() -> dict[str, Any]:
    backends = {
        "iptables": shutil.which("iptables"),
        "iptables_restore": shutil.which("iptables-restore"),
        "nftables": shutil.which("nft"),
        "tc": shutil.which("tc"),
        "bpftool": shutil.which("bpftool"),
        "ovs_vsctl": shutil.which("ovs-vsctl"),
        "ovs_ofctl": shutil.which("ovs-ofctl"),
        "kubectl": shutil.which("kubectl"),
        "cilium": shutil.which("cilium"),
    }
    return {
        "ok": True,
        "implemented_backends": ["iptables-plan", "ovs-openflow-plan", "cilium-networkpolicy-plan"],
        "implemented_backend": "iptables-plan",
        "available_tools": {key: bool(value) for key, value in backends.items()},
        "paths": {key: str(value or "") for key, value in backends.items()},
        "leverage_candidates": [
            {
                "name": "nftables",
                "fit": "high",
                "use": "atomic ruleset replacement, maps/sets for many peers, JSON/libnftables backend",
                "status": "recommended next renderer",
            },
            {
                "name": "tc/eBPF",
                "fit": "medium-high",
                "use": "high-rate profile marking, per-flow counters, XDP/tc prefiltering near the dataplane",
                "status": "future backend after policy schema stabilizes",
            },
            {
                "name": "Open vSwitch/OpenFlow",
                "fit": "medium",
                "use": "VM/lab bridge and virtual switch control for chained hosts or nested virtualization",
                "status": "implemented renderer for review-only command plans",
            },
            {
                "name": "Kubernetes NetworkPolicy/CiliumNetworkPolicy",
                "fit": "medium-high",
                "use": "pod/namespace-scoped policy for Kubernetes troubleshooting workflows",
                "status": "implemented CiliumNetworkPolicy renderer; Kubernetes NetworkPolicy renderer remains future work",
            },
            {
                "name": "Rego/Cedar-style policy language",
                "fit": "medium",
                "use": "higher-level authorization decisions compiled down to this flow schema",
                "status": "control-plane policy input, not packet filter backend",
            },
        ],
    }


def policy_payload(
    policy: FirewallPolicy,
    rules: list[RenderedRule],
    *,
    backend: str = "iptables",
    ovs_bridge: str = "br-weaverssh",
    ovs_openflow_version: str = "OpenFlow13",
    k8s_namespace: str = "weaverssh",
    k8s_policy_name: str = "weaverssh-dataplane",
    k8s_app_label: str = "weaverssh-data-plane",
) -> dict[str, Any]:
    if backend not in VALID_BACKENDS:
        raise ValueError(f"unsupported backend: {backend}")
    payload = {
        "ok": True,
        "backend": backend,
        "policy": asdict(policy),
        "rules": [asdict(rule) for rule in rules],
        "iptables_restore": render_restore(policy, rules),
        "iptables_shell": render_idempotent_shell(policy, rules),
        "stack": stack_inspection(),
    }
    if backend == "ovs-openflow":
        payload["stack"]["implemented_backend"] = "ovs-openflow-plan"
        payload["ovs_openflow"] = render_ovs_openflow(
            policy,
            bridge=ovs_bridge,
            openflow_version=ovs_openflow_version,
        )
    if backend == "cilium-networkpolicy":
        payload["stack"]["implemented_backend"] = "cilium-networkpolicy-plan"
        payload["cilium_networkpolicy"] = render_cilium_networkpolicy(
            policy,
            namespace=k8s_namespace,
            name=k8s_policy_name,
            app_label=k8s_app_label,
        )
    return payload


def load_policy(path: Path) -> FirewallPolicy:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy file must contain a JSON object")
    return _policy_from_dict(data)


def write_output(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if fmt == "restore":
        if payload.get("backend") != "iptables":
            raise ValueError("--format restore is only valid with --backend iptables")
        print(str(payload["iptables_restore"]), end="")
        return
    if fmt == "shell":
        shell = payload.get("iptables_shell")
        if payload.get("backend") == "ovs-openflow":
            shell = payload["ovs_openflow"]["shell"]
        if payload.get("backend") == "cilium-networkpolicy":
            shell = payload["cilium_networkpolicy"]["shell"]
        print("\n".join(str(line) for line in shell))
        return
    if fmt == "yaml":
        if payload.get("backend") != "cilium-networkpolicy":
            raise ValueError("--format yaml requires --backend cilium-networkpolicy")
        print(str(payload["cilium_networkpolicy"]["yaml"]), end="")
        return
    if fmt == "openflow":
        if payload.get("backend") != "ovs-openflow":
            raise ValueError("--format openflow requires --backend ovs-openflow")
        for rule in payload["ovs_openflow"]["rules"]:
            print(rule["flow"])
        return
    if fmt == "text":
        policy = payload["policy"]
        print("status=planned")
        print(f"backend={payload.get('backend', 'iptables')}")
        print(f"version={policy['version']}")
        print(f"default_action={policy['default_action']}")
        print(f"loopback_only={policy['loopback_only']}")
        if payload.get("backend") == "ovs-openflow":
            ovs = payload["ovs_openflow"]
            print(f"ovs_bridge={ovs['bridge']}")
            print(f"openflow_rules={len(ovs['rules'])}")
            for rule in ovs["rules"]:
                print(f"openflow={rule['flow_id']} table={rule['table']} {rule['description']}")
        elif payload.get("backend") == "cilium-networkpolicy":
            cilium = payload["cilium_networkpolicy"]
            print(f"k8s_namespace={cilium['namespace']}")
            print(f"k8s_policy_name={cilium['name']}")
            print("manifest_kind=CiliumNetworkPolicy")
        else:
            print(f"rules={len(payload['rules'])}")
            for rule in payload["rules"]:
                print(f"rule={rule['flow_id']} {rule['description']}")
        return
    raise ValueError(f"unsupported format: {fmt}")


def add_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-file", type=Path, default=None)
    parser.add_argument("--backend", choices=sorted(VALID_BACKENDS), default="iptables")
    parser.add_argument("--format", choices=["text", "json", "restore", "shell", "openflow", "yaml"], default="text")
    parser.add_argument("--ovs-bridge", default="br-weaverssh")
    parser.add_argument("--ovs-openflow-version", default="OpenFlow13")
    parser.add_argument("--k8s-namespace", default="weaverssh")
    parser.add_argument("--k8s-policy-name", default="weaverssh-dataplane")
    parser.add_argument("--k8s-app-label", default="weaverssh-data-plane")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--remote-cidr", default="127.0.0.1/32")
    parser.add_argument("--control-port", type=int, default=8101)
    parser.add_argument("--bulk-port", type=int, default=19090)
    parser.add_argument("--realtime-port", type=int, default=19091)
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--webdav-port", type=int, default=8780)
    parser.add_argument("--ninep-port", type=int, default=5640)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--include-webdav", action="store_true")
    parser.add_argument("--include-9p", action="store_true")
    parser.add_argument("--include-ssh-egress", action="store_true")
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--default-action", choices=["drop", "reject", "accept"], default="drop")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd")
    plan = sub.add_parser("plan", help="render dataplane firewall policy")
    add_plan_args(plan)
    inspect = sub.add_parser("inspect-stack", help="inspect available software-defined networking backends")
    inspect.add_argument("--format", choices=["text", "json"], default="text")
    example = sub.add_parser("example-policy", help="print example JSON policy")
    example.add_argument("--format", choices=["json"], default="json")
    add_plan_args(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    cmd = str(args.cmd or "plan")
    try:
        if cmd == "inspect-stack":
            payload = stack_inspection()
            if args.format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print("status=inspected")
                for name, present in payload["available_tools"].items():
                    print(f"tool={name} available={str(bool(present)).lower()}")
                print("recommended_next_backend=nftables")
            return 0
        if cmd == "example-policy":
            policy = validate_policy(default_policy(args), allow_non_loopback=bool(args.allow_non_loopback))
            print(json.dumps(asdict(policy), indent=2, sort_keys=True))
            return 0
        policy = load_policy(args.policy_file) if args.policy_file else default_policy(args)
        policy = validate_policy(policy, allow_non_loopback=bool(args.allow_non_loopback))
        rules = render_rules(policy)
        write_output(
            policy_payload(
                policy,
                rules,
                backend=str(args.backend),
                ovs_bridge=str(args.ovs_bridge),
                ovs_openflow_version=str(args.ovs_openflow_version),
                k8s_namespace=str(args.k8s_namespace),
                k8s_policy_name=str(args.k8s_policy_name),
                k8s_app_label=str(args.k8s_app_label),
            ),
            str(args.format),
        )
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc), "status": "rejected"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
