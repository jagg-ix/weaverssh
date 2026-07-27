#!/usr/bin/env python3
from __future__ import annotations

"""CLI client for SSHX11 control-plane daemon."""

import argparse
import json
from pathlib import Path
import urllib.error
import urllib.request


def _url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}{path}"


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read()
    payload = json.loads(raw.decode("utf-8"))
    return payload if isinstance(payload, dict) else {"ok": False, "error": "invalid_json"}


def _http_post_json(url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            status = int(resp.status)
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        data = {"ok": False, "error": "invalid_json"}
    return status, data if isinstance(data, dict) else {"ok": False, "error": "invalid_json"}


def _parse_kv(values: list[str]) -> dict:
    out = {}
    for item in values:
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8101)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    sub.add_parser("state")
    sub.add_parser("policy")
    tr = sub.add_parser("transport-route")
    tr.add_argument("--bytes", type=int, required=True)
    tr.add_argument("--hint", default="")
    ccmd = sub.add_parser("command")
    ccmd.add_argument("name")
    ccmd.add_argument("args", nargs="*")
    sync = sub.add_parser("sync-buffers")
    sync.add_argument("--ssh-buffer-kb", type=int, required=True)
    sync.add_argument("--x11-buffer-kb", type=int, required=True)
    sync.add_argument("--ws-buffer-kb", type=int, required=True)
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    try:
        if args.cmd == "health":
            payload = _http_get_json(_url(base, "/health"))
            print(json.dumps(payload, indent=2))
            return 0 if payload.get("ok") else 1
        if args.cmd == "state":
            payload = _http_get_json(_url(base, "/state"))
            print(json.dumps(payload, indent=2))
            return 0 if payload.get("ok") else 1
        if args.cmd == "policy":
            payload = _http_get_json(_url(base, "/policy"))
            print(json.dumps(payload, indent=2))
            return 0 if payload.get("ok") else 1
        if args.cmd == "transport-route":
            payload = _http_get_json(_url(base, f"/transport-route?bytes={int(args.bytes)}&hint={str(args.hint)}"))
            print(json.dumps(payload, indent=2))
            return 0 if payload.get("ok") else 1
        if args.cmd == "sync-buffers":
            status, payload = _http_post_json(
                _url(base, "/sync-buffers"),
                {
                    "ssh_buffer_kb": int(args.ssh_buffer_kb),
                    "x11_buffer_kb": int(args.x11_buffer_kb),
                    "ws_buffer_kb": int(args.ws_buffer_kb),
                },
            )
            print(json.dumps({"http_status": status, "payload": payload}, indent=2))
            return 0 if status < 400 and payload.get("ok") else 1
        if args.cmd == "command":
            kv = _parse_kv(list(args.args))
            status, payload = _http_post_json(
                _url(base, "/command"),
                {"command": str(args.name), "args": kv},
            )
            print(json.dumps({"http_status": status, "payload": payload}, indent=2))
            return 0 if status < 400 and payload.get("ok") else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
