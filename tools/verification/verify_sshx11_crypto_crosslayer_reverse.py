#!/usr/bin/env python3
from __future__ import annotations

"""
Cross-layer cryptographic interaction verifier for SSH X11 forwarding.

This tool consumes a parse-friendly TLA+ contract describing:
- interaction nodes across software/network/crypto layers,
- prerequisite edges,
- canonical happy-path sequence,
- reverse goal path sequence,
- trusted-forwarding rejection sequence.

It verifies both forward and reverse logical consistency, checks layer coverage,
cross-checks runtime verifier output, and emits machine/human artifacts.
"""

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class InteractionNode:
    node_id: str
    layer: str
    actor: str
    event: str
    expected_outcome: str


Obligation = Tuple[str, str, str]


def _strip_tla_comments(text: str) -> str:
    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)
    text = re.sub(r"(?m)^\s*\\\*.*$", "", text)
    return text


def _get_tla_def(text: str, name: str) -> Optional[str]:
    pattern = re.compile(
        rf"(?m)^\s*{re.escape(name)}\s*==\s*(.*?)(?=^\s*[A-Za-z0-9_]+\s*==|^\s*=+|\Z)",
        re.DOTALL,
    )
    m = pattern.search(text)
    return m.group(1).strip() if m else None


def _parse_string_set(defn: str) -> set[str]:
    return set(re.findall(r'"([^"]+)"', defn))


def _parse_string_seq(defn: str) -> List[str]:
    return list(re.findall(r'"([^"]+)"', defn))


def _parse_tuple_set(defn: str) -> List[Tuple[str, ...]]:
    tuples: List[Tuple[str, ...]] = []
    for body in re.findall(r"<<\s*(.*?)\s*>>", defn, flags=re.DOTALL):
        fields = tuple(re.findall(r'"([^"]+)"', body))
        if fields:
            tuples.append(fields)
    return tuples


def _parse_nodes(defn: str) -> Dict[str, InteractionNode]:
    nodes: Dict[str, InteractionNode] = {}
    for row in _parse_tuple_set(defn):
        if len(row) != 5:
            raise ValueError(f"invalid InteractionNodes tuple shape: {row}")
        node = InteractionNode(
            node_id=row[0],
            layer=row[1],
            actor=row[2],
            event=row[3],
            expected_outcome=row[4],
        )
        if node.node_id in nodes:
            raise ValueError(f"duplicate node id: {node.node_id}")
        nodes[node.node_id] = node
    return nodes


def _parse_obligations(defn: str) -> List[Obligation]:
    obligations: List[Obligation] = []
    for row in _parse_tuple_set(defn):
        if len(row) != 3:
            raise ValueError(f"invalid CrossLayerObligations tuple shape: {row}")
        obligations.append((row[0], row[1], row[2]))
    return obligations


def load_contract(path: Path) -> Dict[str, Any]:
    text = _strip_tla_comments(path.read_text(encoding="utf-8"))
    names = [
        "InteractionNodes",
        "NodeDescriptions",
        "PrerequisiteEdges",
        "CrossLayerObligations",
        "RequiredLayers",
        "CanonicalHappyPathSequence",
        "ReverseGoalPathSequence",
        "TrustedForwardingRejectedSequence",
        "FinalGoalNode",
    ]
    defs: Dict[str, str] = {}
    for name in names:
        definition = _get_tla_def(text, name)
        if definition is None:
            raise ValueError(f"missing TLA definition: {name}")
        defs[name] = definition

    nodes = _parse_nodes(defs["InteractionNodes"])
    descriptions = {}
    for row in _parse_tuple_set(defs["NodeDescriptions"]):
        if len(row) == 2:
            descriptions[row[0]] = row[1]
    edges = {(src, dst) for src, dst in _parse_tuple_set(defs["PrerequisiteEdges"])}
    obligations = _parse_obligations(defs["CrossLayerObligations"])
    required_layers = _parse_string_set(defs["RequiredLayers"])
    happy_path = _parse_string_seq(defs["CanonicalHappyPathSequence"])
    reverse_path = _parse_string_seq(defs["ReverseGoalPathSequence"])
    y_reject = _parse_string_seq(defs["TrustedForwardingRejectedSequence"])
    final_goal = _parse_string_seq(defs["FinalGoalNode"])[0]

    return {
        "nodes": nodes,
        "descriptions": descriptions,
        "edges": edges,
        "obligations": obligations,
        "required_layers": required_layers,
        "happy_path": happy_path,
        "reverse_path": reverse_path,
        "y_reject_path": y_reject,
        "final_goal": final_goal,
    }


def _validate_path_nodes_exist(nodes: Dict[str, InteractionNode], path: Sequence[str]) -> List[str]:
    return [node_id for node_id in path if node_id not in nodes]


def _validate_forward_path(edges: set[Tuple[str, str]], path: Sequence[str]) -> Dict[str, Any]:
    missing_edges: List[Tuple[str, str]] = []
    for idx in range(len(path) - 1):
        pair = (path[idx], path[idx + 1])
        if pair not in edges:
            missing_edges.append(pair)
    return {"ok": len(missing_edges) == 0, "missing_edges": missing_edges}


def _validate_reverse_path(
    edges: set[Tuple[str, str]],
    happy_path: Sequence[str],
    reverse_path: Sequence[str],
    final_goal: str,
) -> Dict[str, Any]:
    issues: List[str] = []
    missing_edges: List[Tuple[str, str]] = []
    if not reverse_path:
        issues.append("reverse path is empty")
    else:
        if reverse_path[0] != final_goal:
            issues.append(f"reverse first node must be final goal {final_goal}, got {reverse_path[0]}")
    expected = list(reversed(happy_path))
    if list(reverse_path) != expected:
        issues.append("reverse path is not exact reverse of canonical happy path")
    for idx in range(len(reverse_path) - 1):
        current = reverse_path[idx]
        prerequisite = reverse_path[idx + 1]
        required_edge = (prerequisite, current)
        if required_edge not in edges:
            missing_edges.append(required_edge)
    return {
        "ok": len(issues) == 0 and len(missing_edges) == 0,
        "issues": issues,
        "missing_prerequisite_edges": missing_edges,
    }


def _validate_layer_coverage(
    nodes: Dict[str, InteractionNode],
    required_layers: set[str],
    happy_path: Sequence[str],
) -> Dict[str, Any]:
    covered = {nodes[node_id].layer for node_id in happy_path if node_id in nodes}
    missing = sorted(required_layers - covered)
    return {
        "ok": len(missing) == 0,
        "required_layers": sorted(required_layers),
        "covered_layers": sorted(covered),
        "missing_layers": missing,
    }


def _validate_obligations(
    obligations: Sequence[Obligation],
    happy_path: Sequence[str],
    reverse_path: Sequence[str],
) -> Dict[str, Any]:
    h_index = {node_id: idx for idx, node_id in enumerate(happy_path)}
    r_index = {node_id: idx for idx, node_id in enumerate(reverse_path)}
    checks: List[Dict[str, Any]] = []
    ok = True
    for src, dst, reason in obligations:
        present = src in h_index and dst in h_index and src in r_index and dst in r_index
        forward_order = present and h_index[src] < h_index[dst]
        reverse_order = present and r_index[dst] < r_index[src]
        item_ok = present and forward_order and reverse_order
        if not item_ok:
            ok = False
        checks.append(
            {
                "source": src,
                "target": dst,
                "reason": reason,
                "present_in_paths": present,
                "forward_order_ok": forward_order,
                "reverse_order_ok": reverse_order,
                "ok": item_ok,
            }
        )
    return {"ok": ok, "checks": checks}


def _validate_y_rejection(
    nodes: Dict[str, InteractionNode],
    y_path: Sequence[str],
) -> Dict[str, Any]:
    missing_nodes = _validate_path_nodes_exist(nodes, y_path)
    if missing_nodes:
        return {"ok": False, "missing_nodes": missing_nodes}
    outcomes = [nodes[node_id].expected_outcome for node_id in y_path]
    has_y_request = any(nodes[node_id].event == "requestX11ForwardY" for node_id in y_path)
    blocked_terminal = len(y_path) > 0 and nodes[y_path[-1]].expected_outcome == "blocked"
    return {
        "ok": has_y_request and blocked_terminal,
        "has_y_request": has_y_request,
        "terminal_blocked": blocked_terminal,
        "outcomes": outcomes,
    }


def _build_forward_rows(
    nodes: Dict[str, InteractionNode],
    descriptions: Dict[str, str],
    happy_path: Sequence[str],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, node_id in enumerate(happy_path):
        node = nodes[node_id]
        rows.append(
            {
                "index": idx,
                "node_id": node.node_id,
                "layer": node.layer,
                "actor": node.actor,
                "event": node.event,
                "expected_outcome": node.expected_outcome,
                "description": descriptions.get(node.node_id, ""),
                "next_target": happy_path[idx + 1] if idx + 1 < len(happy_path) else None,
            }
        )
    return rows


def _build_reverse_rows(
    nodes: Dict[str, InteractionNode],
    descriptions: Dict[str, str],
    reverse_path: Sequence[str],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, node_id in enumerate(reverse_path):
        node = nodes[node_id]
        prerequisite = reverse_path[idx + 1] if idx + 1 < len(reverse_path) else None
        rows.append(
            {
                "index": idx,
                "goal_node": node.node_id,
                "goal_layer": node.layer,
                "goal_actor": node.actor,
                "goal_event": node.event,
                "goal_description": descriptions.get(node.node_id, ""),
                "required_previous_step": prerequisite,
                "required_previous_description": descriptions.get(prerequisite or "", ""),
            }
        )
    return rows


def _runtime_crosscheck(
    repo_root: Path,
    nodes: Dict[str, InteractionNode],
    happy_path: Sequence[str],
) -> Dict[str, Any]:
    module_path = repo_root / "tools" / "verification" / "verify_sshx11_fsm_python_tla.py"
    spec = importlib.util.spec_from_file_location("verify_sshx11_fsm_python_tla", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load runtime verifier module from {module_path}")
    base_verifier = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = base_verifier
    spec.loader.exec_module(base_verifier)

    tla_path = repo_root / "verification" / "tla" / "SSHX11CryptoCrossLayerContract.tla"
    report = base_verifier.run_verification(tla_path=tla_path)

    canonical = report["python"]["trace_results"]["canonicalSystemTrace"]
    step_events = [
        (step["event"][0], step["event"][1])
        for step in canonical.get("steps", [])
    ]
    matched: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    for node_id in happy_path:
        node = nodes[node_id]
        key = (node.actor, node.event)
        if key in step_events:
            matched.append({"node_id": node_id, "actor": node.actor, "event": node.event})
        else:
            missing.append({"node_id": node_id, "actor": node.actor, "event": node.event})

    x11_security = report.get("x11_security", {})
    x_ok = bool(x11_security.get("sshX_verification", {}).get("ok"))
    y_ok = bool(x11_security.get("sshY_verification", {}).get("ok"))
    return {
        "ok": report.get("ok", False) and len(missing) == 0 and x_ok and y_ok,
        "base_verifier_ok": report.get("ok", False),
        "matched_nodes": matched,
        "missing_nodes": missing,
        "x11_security": {
            "overall_ok": x11_security.get("ok", False),
            "sshX_verification_ok": x_ok,
            "sshY_rejection_ok": y_ok,
        },
        "base_output_path": "verification_results/stack_audits/sshx11_fsm_python_tla_validation.json",
    }


def build_interaction_payload(contract: Dict[str, Any]) -> Dict[str, Any]:
    nodes: Dict[str, InteractionNode] = contract["nodes"]
    descriptions: Dict[str, str] = contract["descriptions"]
    happy_path: List[str] = contract["happy_path"]
    reverse_path: List[str] = contract["reverse_path"]
    return {
        "contract": {
            "final_goal": contract["final_goal"],
            "required_layers": sorted(contract["required_layers"]),
            "happy_path_length": len(happy_path),
            "reverse_path_length": len(reverse_path),
        },
        "forward_interactions": _build_forward_rows(nodes, descriptions, happy_path),
        "reverse_goal_walk": _build_reverse_rows(nodes, descriptions, reverse_path),
        "trusted_forwarding_rejection_path": [
            {
                "node_id": node_id,
                "layer": nodes[node_id].layer,
                "actor": nodes[node_id].actor,
                "event": nodes[node_id].event,
                "expected_outcome": nodes[node_id].expected_outcome,
                "description": descriptions.get(node_id, ""),
            }
            for node_id in contract["y_reject_path"]
        ],
        "cross_layer_obligations": [
            {"source": src, "target": dst, "reason": reason}
            for src, dst, reason in contract["obligations"]
        ],
    }


def run_validation(contract: Dict[str, Any], crosscheck_runtime: bool, repo_root: Path) -> Dict[str, Any]:
    nodes: Dict[str, InteractionNode] = contract["nodes"]
    edges: set[Tuple[str, str]] = contract["edges"]
    happy_path: List[str] = contract["happy_path"]
    reverse_path: List[str] = contract["reverse_path"]
    y_reject_path: List[str] = contract["y_reject_path"]
    final_goal: str = contract["final_goal"]

    happy_missing = _validate_path_nodes_exist(nodes, happy_path)
    reverse_missing = _validate_path_nodes_exist(nodes, reverse_path)
    y_missing = _validate_path_nodes_exist(nodes, y_reject_path)

    forward_check = _validate_forward_path(edges, happy_path)
    reverse_check = _validate_reverse_path(edges, happy_path, reverse_path, final_goal)
    coverage_check = _validate_layer_coverage(nodes, contract["required_layers"], happy_path)
    obligation_check = _validate_obligations(contract["obligations"], happy_path, reverse_path)
    y_reject_check = _validate_y_rejection(nodes, y_reject_path)

    runtime_check = {"ok": True, "skipped": True}
    if crosscheck_runtime:
        runtime_check = _runtime_crosscheck(repo_root=repo_root, nodes=nodes, happy_path=happy_path)
        runtime_check["skipped"] = False

    ok = (
        len(happy_missing) == 0
        and len(reverse_missing) == 0
        and len(y_missing) == 0
        and forward_check["ok"]
        and reverse_check["ok"]
        and coverage_check["ok"]
        and obligation_check["ok"]
        and y_reject_check["ok"]
        and runtime_check["ok"]
    )

    return {
        "ok": ok,
        "missing_nodes": {
            "happy_path": happy_missing,
            "reverse_path": reverse_missing,
            "trusted_forwarding_rejection_path": y_missing,
        },
        "forward": forward_check,
        "reverse": reverse_check,
        "coverage": coverage_check,
        "cross_layer_obligations": obligation_check,
        "trusted_forwarding_rejection": y_reject_check,
        "runtime_crosscheck": runtime_check,
    }


def _to_markdown(interactions: Dict[str, Any], validation: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# SSHX11 Cross-Layer Crypto Interaction Validation")
    lines.append("")
    lines.append(f"- overall_ok: `{validation['ok']}`")
    lines.append(f"- final_goal: `{interactions['contract']['final_goal']}`")
    lines.append(
        f"- path_lengths: forward={interactions['contract']['happy_path_length']}, "
        f"reverse={interactions['contract']['reverse_path_length']}"
    )
    lines.append("")
    lines.append("## Forward Interaction Path")
    lines.append("")
    lines.append("| idx | node | layer | actor | event | outcome | next |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for row in interactions["forward_interactions"]:
        lines.append(
            f"| {row['index']} | {row['node_id']} | {row['layer']} | {row['actor']} | "
            f"{row['event']} | {row['expected_outcome']} | {row['next_target'] or '-'} |"
        )
    lines.append("")
    lines.append("## Reverse Goal Walk (End -> Start)")
    lines.append("")
    lines.append("| idx | goal | goal event | prerequisite step |")
    lines.append("| --- | --- | --- | --- |")
    for row in interactions["reverse_goal_walk"]:
        lines.append(
            f"| {row['index']} | {row['goal_node']} | {row['goal_event']} | "
            f"{row['required_previous_step'] or '-'} |"
        )
    lines.append("")
    lines.append("## Coverage + Obligation Checks")
    lines.append("")
    lines.append(f"- forward_ok: `{validation['forward']['ok']}`")
    lines.append(f"- reverse_ok: `{validation['reverse']['ok']}`")
    lines.append(f"- required_layer_coverage_ok: `{validation['coverage']['ok']}`")
    lines.append(
        f"- cross_layer_obligations_ok: `{validation['cross_layer_obligations']['ok']}`"
    )
    lines.append(
        f"- trusted_forwarding_rejection_ok: `{validation['trusted_forwarding_rejection']['ok']}`"
    )
    lines.append(
        f"- runtime_crosscheck_ok: `{validation['runtime_crosscheck'].get('ok', False)}`"
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_outputs(
    validation: Dict[str, Any],
    interactions: Dict[str, Any],
    output_json: Path,
    output_md: Path,
    interaction_json: Path,
    interaction_md: Path,
) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    interaction_json.parent.mkdir(parents=True, exist_ok=True)
    interaction_md.parent.mkdir(parents=True, exist_ok=True)

    output_json.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
    output_md.write_text(_to_markdown(interactions, validation), encoding="utf-8")
    interaction_json.write_text(json.dumps(interactions, indent=2) + "\n", encoding="utf-8")
    interaction_md.write_text(_to_markdown(interactions, validation), encoding="utf-8")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Validate SSHX11 cross-layer cryptographic interaction contract (forward + reverse).",
    )
    parser.add_argument(
        "--contract",
        type=Path,
        default=repo_root / "verification" / "tla" / "SSHX11CryptoCrossLayerContract.tla",
        help="Path to TLA+ interaction contract.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=repo_root
        / "verification_results"
        / "stack_audits"
        / "sshx11_crypto_crosslayer_reverse_validation.json",
        help="Validation JSON output path.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=repo_root
        / "verification_results"
        / "stack_audits"
        / "sshx11_crypto_crosslayer_reverse_validation.md",
        help="Validation markdown output path.",
    )
    parser.add_argument(
        "--interaction-json",
        type=Path,
        default=repo_root
        / "verification_results"
        / "stack_audits"
        / "sshx11_crypto_crosslayer_interactions.json",
        help="Structured interaction description JSON.",
    )
    parser.add_argument(
        "--interaction-md",
        type=Path,
        default=repo_root
        / "verification_results"
        / "stack_audits"
        / "sshx11_crypto_crosslayer_interactions.md",
        help="Human-readable interaction description markdown.",
    )
    parser.add_argument(
        "--skip-runtime-crosscheck",
        action="store_true",
        help="Skip runtime FSM cross-check against verify_sshx11_fsm_python_tla.py.",
    )
    args = parser.parse_args()

    contract = load_contract(args.contract)
    interactions = build_interaction_payload(contract)
    validation = run_validation(
        contract=contract,
        crosscheck_runtime=not args.skip_runtime_crosscheck,
        repo_root=repo_root,
    )
    write_outputs(
        validation=validation,
        interactions=interactions,
        output_json=args.output_json,
        output_md=args.output_md,
        interaction_json=args.interaction_json,
        interaction_md=args.interaction_md,
    )

    print(f"ok={validation['ok']}")
    print(f"contract={args.contract}")
    print(f"output_json={args.output_json}")
    print(f"output_md={args.output_md}")
    print(f"interaction_json={args.interaction_json}")
    print(f"interaction_md={args.interaction_md}")
    print(f"runtime_crosscheck_ok={validation['runtime_crosscheck'].get('ok', False)}")
    return 0 if validation["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
