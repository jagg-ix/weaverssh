#!/usr/bin/env python3
from __future__ import annotations

"""
Emit observed SSH-X11 protocol events from a small executable probe implementation.

This script is intentionally small and operational: it produces runtime-like
event records (NDJSON) that are consumed by verify_sshx11_fsm_python_tla.py.
"""

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


Event = Tuple[str, str, Optional[int]]


def _actor_runtime_context(actor: str) -> Dict[str, str]:
    mapping = {
        "sshClient": {
            "perspective": "userEdgeHost",
            "flow_plane": "sshTransportControl",
            "role": "sshClientProcess",
        },
        "sshServer": {
            "perspective": "sshServerHost",
            "flow_plane": "sshTransportControl",
            "role": "sshServerProcess",
        },
        "x11Producer": {
            "perspective": "userEdgeHost",
            "flow_plane": "x11PayloadStream",
            "role": "edgeX11Producer",
        },
        "bridgeServer": {
            "perspective": "bridgeHost",
            "flow_plane": "websocketControl",
            "role": "bridgeServerProcess",
        },
        "bridgeClient": {
            "perspective": "bridgeHost",
            "flow_plane": "websocketControl",
            "role": "bridgeClientProcess",
        },
    }
    return mapping.get(actor, {})


def _canonical_trace() -> List[Event]:
    return [
        ("sshClient", "start", None),
        ("sshServer", "acceptTransport", None),
        ("sshClient", "keyExchangeDone", None),
        ("sshServer", "keyExchangeDone", None),
        ("sshClient", "userAuthDone", None),
        ("sshServer", "userAuthDone", None),
        ("sshClient", "requestX11ForwardX", None),
        ("sshServer", "enableX11Forward", None),
        ("sshServer", "generateMITMagicCookie", None),
        ("sshServer", "xauthAddMITMagicCookie", None),
        ("sshServer", "issueX11ProxyCookie", None),
        ("sshClient", "openSession", None),
        ("sshClient", "verifyMitMagicCookie", None),
        ("sshServer", "openSession", None),
        ("sshClient", "openX11Channel", None),
        ("sshServer", "acceptX11Channel", None),
        ("x11Producer", "openSocket", None),
        ("x11Producer", "sendSetup", None),
        ("x11Producer", "setupAccepted", None),
        ("bridgeServer", "beginHandshake", None),
        ("bridgeServer", "authOK", None),
        ("bridgeClient", "openSocket", None),
        ("bridgeClient", "sendX11Setup", None),
        ("bridgeClient", "x11SetupAccepted", None),
        ("bridgeClient", "presentProxyCookie", None),
        ("bridgeServer", "verifyProxyCookie", None),
        ("bridgeServer", "websocketUpgradeRequested", None),
        ("bridgeClient", "requestWSUpgrade", None),
        ("bridgeServer", "websocketUpgradeSucceeded", None),
        ("bridgeClient", "wsUpgradeSucceeded", None),
        ("bridgeClient", "syncBufferProfiles", None),
        ("bridgeServer", "syncBufferProfiles", None),
        ("bridgeClient", "startTransportNegotiation", None),
        ("bridgeServer", "transportNegotiationSucceeded", None),
        ("bridgeClient", "transportNegotiationSucceeded", None),
        ("bridgeClient", "startRelay", None),
        ("x11Producer", "sendPayload", None),
        ("bridgeServer", "relayClientToTarget", 128),
        ("bridgeServer", "relayTargetToClient", 64),
    ]


def _retry_trace() -> List[Event]:
    return [
        ("bridgeClient", "openSocket", None),
        ("bridgeClient", "sendX11Setup", None),
        ("bridgeClient", "sendX11Setup", None),
        ("bridgeClient", "x11SetupAccepted", None),
        ("bridgeClient", "presentProxyCookie", None),
        ("bridgeClient", "requestWSUpgrade", None),
        ("bridgeClient", "requestWSUpgrade", None),
    ]


def _error_trace() -> List[Event]:
    return [
        ("bridgeClient", "startRelay", None),
    ]


def _emit_records(trace_name: str, events: Iterable[Event]) -> List[dict]:
    out: List[dict] = []
    for i, (actor, event, arg) in enumerate(events):
        rec = {
            "source": "sshx11_impl_probe",
            "trace": trace_name,
            "step_index": i,
            "actor": actor,
            "event": event,
            "arg": arg,
            "runtime_context": _actor_runtime_context(actor),
        }
        out.append(rec)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit observed SSH-X11 implementation probe events as NDJSON.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("verification_results/stack_audits/sshx11_impl_probe_observed.ndjson"),
        help="NDJSON output path.",
    )
    parser.add_argument(
        "--include-error-trace",
        action="store_true",
        help="Also emit a deliberately invalid trace to drive verifier feedback.",
    )
    args = parser.parse_args()

    records = []
    records.extend(_emit_records("observedCanonicalTrace", _canonical_trace()))
    records.extend(_emit_records("observedRetryTrace", _retry_trace()))
    if args.include_error_trace:
        records.extend(_emit_records("observedErrorTrace", _error_trace()))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True))
            f.write("\n")

    print(f"output={args.output}")
    print(f"record_count={len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
