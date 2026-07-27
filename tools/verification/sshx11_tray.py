#!/usr/bin/env python3
from __future__ import annotations

"""System tray app (macOS menu bar / Windows tray) for sshx11d."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any
from urllib import request as urlrequest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11d


def _load_pystray():
    try:
        import pystray  # type: ignore
        from PIL import Image, ImageDraw  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "pystray + pillow are required for tray mode. Install with: pip3 install pystray pillow"
        ) from exc
    return pystray, Image, ImageDraw


class SSHX11DaemonClient:
    def __init__(self, endpoint_file: Path) -> None:
        self.endpoint_file = endpoint_file
        self.endpoint: dict[str, Any] = {}
        self.token = ""
        self.base_url = ""
        self.reload()

    def reload(self) -> dict[str, Any]:
        loaded = sshx11d.load_endpoint_descriptor(self.endpoint_file)
        if not bool(loaded.get("ok")):
            self.endpoint = {}
            self.token = ""
            self.base_url = ""
            return loaded

        endpoint = loaded.get("endpoint", {})
        if not isinstance(endpoint, dict):
            return {"ok": False, "error": "endpoint_shape_invalid"}

        token_file = Path(str(endpoint.get("token_file", "")).strip())
        token = ""
        if token_file.exists():
            token = token_file.read_text(encoding="utf-8", errors="replace").strip()

        self.endpoint = endpoint
        self.token = token
        self.base_url = str(endpoint.get("base_url", "")).rstrip("/")
        return {"ok": True, "base_url": self.base_url, "endpoint_file": str(self.endpoint_file)}

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None, timeout_s: float = 4.0) -> dict[str, Any]:
        if not self.base_url:
            return {"ok": False, "error": "endpoint_not_loaded", "endpoint_file": str(self.endpoint_file)}
        url = f"{self.base_url}{path}"
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(url=url, method=method.upper(), data=body)
        req.add_header("Accept", "application/json")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urlrequest.urlopen(req, timeout=max(0.2, float(timeout_s))) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return {"ok": False, "error": str(exc), "url": url}
        try:
            parsed = json.loads(raw)
        except Exception:
            return {"ok": False, "error": "invalid_json", "raw": raw[-500:], "url": url}
        if not isinstance(parsed, dict):
            return {"ok": False, "error": "invalid_json_shape", "url": url}
        return parsed

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health", payload=None)

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/settingsSnapshot", payload=None)

    def ui_actions(self) -> dict[str, Any]:
        return self._request("GET", "/v1/uiActions", payload=None)

    def run_ui_action(self, name: str, request_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"name": str(name)}
        if request_payload:
            payload["request"] = request_payload
        return self._request("POST", "/v1/runUiAction", payload=payload)

    def run_named(self, name: str, request_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.run_ui_action(name, request_payload=request_payload)


def _open_path(path: Path) -> None:
    target = str(path)
    if sys.platform == "darwin":
        subprocess.run(["open", target], check=False)
        return
    if os.name.lower() == "nt":
        try:
            os.startfile(target)  # type: ignore[attr-defined]
            return
        except Exception:
            pass
    subprocess.run(["xdg-open", target], check=False)


def _make_icon_image(Image, ImageDraw):
    image = Image.new("RGBA", (64, 64), (9, 16, 33, 255))
    draw = ImageDraw.Draw(image)
    draw.rectangle((6, 6, 58, 58), outline=(120, 200, 255, 255), width=3)
    draw.line((14, 20, 50, 20), fill=(120, 220, 255, 255), width=3)
    draw.line((14, 32, 42, 32), fill=(80, 180, 255, 255), width=3)
    draw.line((14, 44, 36, 44), fill=(80, 180, 255, 255), width=3)
    return image


class TrayApp:
    def __init__(self, client: SSHX11DaemonClient, poll_seconds: float = 8.0) -> None:
        self.client = client
        self.poll_seconds = max(2.0, float(poll_seconds))
        self._lock = threading.Lock()
        self._running = True
        self._status = "unknown"
        self._last_error = ""
        self._icon = None

    def _notify(self, title: str, message: str) -> None:
        icon = self._icon
        if icon is None:
            return
        try:
            icon.notify(str(message), str(title))
        except Exception:
            pass

    def _set_status(self, status: str, error: str = "") -> None:
        with self._lock:
            self._status = str(status)
            self._last_error = str(error)
        if self._icon is not None:
            self._icon.title = f"SSHX11: {self._status}"
            try:
                self._icon.update_menu()
            except Exception:
                pass

    def _refresh_status(self) -> dict[str, Any]:
        out = self.client.health()
        if bool(out.get("ok")):
            self._set_status("ready", "")
        else:
            self._set_status("degraded", str(out.get("error", "health_failed")))
        return out

    def _background_poll(self) -> None:
        while self._running:
            try:
                self._refresh_status()
            except Exception as exc:
                self._set_status("degraded", str(exc))
            for _ in range(int(self.poll_seconds * 10)):
                if not self._running:
                    return
                time.sleep(0.1)

    def _menu_status(self, *_args) -> str:
        with self._lock:
            if self._last_error:
                return f"SSHX11: {self._status} ({self._last_error})"
            return f"SSHX11: {self._status}"

    def _action(self, label: str, fn) -> None:
        out = fn()
        ok = bool(out.get("ok"))
        self._notify("SSHX11", f"{label}: {'ok' if ok else 'failed'}")
        if not ok:
            self._set_status("degraded", str(out.get("error", "operation_failed")))
        else:
            self._refresh_status()

    def run(self) -> int:
        pystray, Image, ImageDraw = _load_pystray()
        icon_image = _make_icon_image(Image, ImageDraw)

        menu = pystray.Menu(
            pystray.MenuItem(self._menu_status, lambda *_: None, enabled=False),
            pystray.MenuItem("Refresh Endpoint", lambda *_: self._action("reload", self.client.reload)),
            pystray.MenuItem("Refresh Status", lambda *_: self._action("status", self._refresh_status)),
            pystray.MenuItem("Connect (Start Services)", lambda *_: self._action("startServices", lambda: self.client.run_named("startServices"))),
            pystray.MenuItem("Disconnect (Stop Services)", lambda *_: self._action("stopServices", lambda: self.client.run_named("stopServices"))),
            pystray.MenuItem("Verify Extension Hosts", lambda *_: self._action("verifyExtensionHosts", lambda: self.client.run_named("verifyExtensionHosts"))),
            pystray.MenuItem("Reverse SOCKS Smoke", lambda *_: self._action("reverseSocksSmoke", lambda: self.client.run_named("reverseSocksSmoke"))),
            pystray.MenuItem("Open Events Log", lambda *_: _open_path(Path(str(self.client.endpoint.get("events_file", self.client.endpoint_file))))),
            pystray.MenuItem("Open Endpoint JSON", lambda *_: _open_path(self.client.endpoint_file)),
            pystray.MenuItem("Quit", lambda icon, _item: icon.stop()),
        )

        self._icon = pystray.Icon("sshx11-tray", icon_image, "SSHX11", menu)
        poller = threading.Thread(target=self._background_poll, daemon=True)
        poller.start()
        try:
            self._icon.run()
        finally:
            self._running = False
        return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--endpoint-file", default=str(sshx11d.default_state_dir() / "endpoint.json"))
    p.add_argument("--poll-seconds", type=float, default=8.0)
    p.add_argument("--once", action="store_true", default=False, help="Run one status probe and exit (no tray UI).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    endpoint_file = Path(str(args.endpoint_file)).expanduser()
    client = SSHX11DaemonClient(endpoint_file=endpoint_file)

    if bool(args.once):
        payload = {
            "endpoint": client.reload(),
            "health": client.health(),
            "settings": client.status(),
            "ui_actions": client.ui_actions(),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if bool(payload.get("health", {}).get("ok")) else 1

    app = TrayApp(client=client, poll_seconds=float(args.poll_seconds))
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
