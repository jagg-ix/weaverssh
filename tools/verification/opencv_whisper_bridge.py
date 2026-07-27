#!/usr/bin/env python3
"""OpenCV <-> Whisper bridge service.

This script connects computer-vision events (OpenCV) and speech-recognition events
(whisper.cpp) through a shared in-process state + JSONL event stream.

Two-way exchange:
1) OpenCV -> Whisper context:
   Every transcript event includes the latest vision context (brightness/motion/frame id).
2) Whisper -> OpenCV control:
   If transcript text includes snapshot keywords, the vision loop saves a frame.

Examples:
  # Real mode (requires model + incoming wav files)
  python3 tools/verification/opencv_whisper_bridge.py \
    --model /path/to/ggml-base.bin \
    --audio-glob '/tmp/voice-in/*.wav' \
    --video-source 0

  # Dry run (no model needed)
  python3 tools/verification/opencv_whisper_bridge.py \
    --video-source synthetic \
    --dry-run-whisper \
    --max-runtime-sec 20
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import cv2  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"OpenCV import failed (cv2): {exc}")

try:
    import numpy as np  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"NumPy import failed: {exc}")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SharedState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_vision: dict[str, Any] = field(default_factory=dict)
    last_transcript: dict[str, Any] = field(default_factory=dict)
    snapshot_requested: bool = False
    snapshot_request_text: str = ""

    def update_vision(self, payload: dict[str, Any]) -> None:
        with self.lock:
            self.last_vision = dict(payload)

    def get_vision(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.last_vision)

    def update_transcript(self, payload: dict[str, Any]) -> None:
        with self.lock:
            self.last_transcript = dict(payload)

    def get_transcript(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.last_transcript)

    def request_snapshot(self, text: str) -> None:
        with self.lock:
            self.snapshot_requested = True
            self.snapshot_request_text = text

    def consume_snapshot_request(self) -> tuple[bool, str]:
        with self.lock:
            flag = self.snapshot_requested
            text = self.snapshot_request_text
            self.snapshot_requested = False
            self.snapshot_request_text = ""
            return flag, text

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "last_vision": dict(self.last_vision),
                "last_transcript": dict(self.last_transcript),
                "snapshot_requested": bool(self.snapshot_requested),
                "snapshot_request_text": str(self.snapshot_request_text),
            }


class EventWriter:
    def __init__(self, out_path: Path):
        self.out_path = out_path
        self.q: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="event-writer", daemon=True)
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._listeners_lock = threading.Lock()

    def start(self) -> None:
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self.stop_event.set()
        self.thread.join(timeout=timeout)

    def emit(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", utc_now_iso())
        self.q.put(event)

    def subscribe(self, listener: Callable[[dict[str, Any]], None]) -> None:
        with self._listeners_lock:
            self._listeners.append(listener)

    def _run(self) -> None:
        with self.out_path.open("a", encoding="utf-8") as fh:
            while not self.stop_event.is_set() or not self.q.empty():
                try:
                    ev = self.q.get(timeout=0.2)
                except queue.Empty:
                    continue
                fh.write(json.dumps(ev, ensure_ascii=True) + "\n")
                fh.flush()
                with self._listeners_lock:
                    listeners = list(self._listeners)
                for listener in listeners:
                    try:
                        listener(dict(ev))
                    except Exception:
                        continue


@dataclass
class FrameHub:
    lock: threading.Lock = field(default_factory=threading.Lock)
    latest_frame: Optional[np.ndarray] = None
    latest_frame_id: int = 0
    latest_ts: str = ""

    def update(self, frame: np.ndarray, frame_id: int) -> None:
        with self.lock:
            self.latest_frame = frame.copy()
            self.latest_frame_id = int(frame_id)
            self.latest_ts = utc_now_iso()

    def snapshot(self) -> tuple[Optional[np.ndarray], int, str]:
        with self.lock:
            if self.latest_frame is None:
                return None, int(self.latest_frame_id), str(self.latest_ts)
            return self.latest_frame.copy(), int(self.latest_frame_id), str(self.latest_ts)


def parse_video_source(raw: str) -> Any:
    value = str(raw or "").strip()
    lowered = value.lower()
    if lowered in {"synthetic", "flameshot"}:
        return lowered
    if raw.isdigit():
        return int(raw)
    return raw


def _json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _region_from_xywh(x: int, y: int, w: int, h: int) -> Optional[str]:
    try:
        xi = int(round(float(x)))
        yi = int(round(float(y)))
        wi = int(round(float(w)))
        hi = int(round(float(h)))
    except Exception:
        return None
    if wi <= 1 or hi <= 1:
        return None
    return f"{wi}x{hi}+{xi}+{yi}"


def _select_window_candidates(
    windows: list[dict[str, Any]],
    *,
    title_contains: str,
    owner_contains: str,
) -> list[dict[str, Any]]:
    title_filter = str(title_contains or "").strip().lower()
    owner_filter = str(owner_contains or "").strip().lower()
    out: list[dict[str, Any]] = []
    for w in windows:
        if not isinstance(w, dict):
            continue
        owner = str(w.get("kCGWindowOwnerName", "")).strip()
        title = str(w.get("kCGWindowName", "")).strip()
        if owner_filter and owner_filter not in owner.lower():
            continue
        if title_filter and title_filter not in title.lower():
            continue
        out.append(w)
    return out


def resolve_macos_window_track(
    *,
    title_contains: str,
    owner_contains: str,
) -> dict[str, Any]:
    try:
        import Quartz  # type: ignore
    except Exception as exc:
        return {
            "ok": False,
            "state": "unsupported",
            "reliability": "low",
            "note": f"Quartz unavailable: {exc}",
            "region": None,
        }

    # NOTE: We inspect all windows to distinguish:
    # - visible/onscreen (trackable)
    # - known but not currently rendered onscreen (not capturable at final composite layer)
    try:
        raw = Quartz.CGWindowListCopyWindowInfo(Quartz.kCGWindowListOptionAll, Quartz.kCGNullWindowID)
        windows = list(raw or [])
    except Exception as exc:
        return {
            "ok": False,
            "state": "error",
            "reliability": "low",
            "note": f"CGWindowListCopyWindowInfo failed: {exc}",
            "region": None,
        }

    matches = _select_window_candidates(
        windows,
        title_contains=str(title_contains or ""),
        owner_contains=str(owner_contains or ""),
    )
    if not matches:
        return {
            "ok": False,
            "state": "not_found",
            "reliability": "low",
            "note": "No matching window found",
            "region": None,
        }

    visible: list[dict[str, Any]] = []
    for w in matches:
        onscreen = bool(w.get("kCGWindowIsOnscreen", False))
        layer = int(w.get("kCGWindowLayer", 0) or 0)
        alpha = float(w.get("kCGWindowAlpha", 0.0) or 0.0)
        b = w.get("kCGWindowBounds", {}) or {}
        width = float(b.get("Width", 0.0) or 0.0)
        height = float(b.get("Height", 0.0) or 0.0)
        if onscreen and layer == 0 and alpha > 0.0 and width > 1.0 and height > 1.0:
            visible.append(w)

    if not visible:
        # Window exists but currently not onscreen/rendered in compositor output.
        # We cannot reliably capture final pixels for it at this moment.
        probe = matches[0]
        return {
            "ok": False,
            "state": "exists_not_onscreen",
            "reliability": "low",
            "note": "Window exists but is not onscreen/rendered",
            "region": None,
            "window_id": int(probe.get("kCGWindowNumber", 0) or 0),
            "owner": str(probe.get("kCGWindowOwnerName", "")),
            "title": str(probe.get("kCGWindowName", "")),
        }

    def _score(w: dict[str, Any]) -> float:
        b = w.get("kCGWindowBounds", {}) or {}
        width = float(b.get("Width", 0.0) or 0.0)
        height = float(b.get("Height", 0.0) or 0.0)
        return width * height

    best = sorted(visible, key=_score, reverse=True)[0]
    b = best.get("kCGWindowBounds", {}) or {}
    x = int(round(float(b.get("X", 0.0) or 0.0)))
    y = int(round(float(b.get("Y", 0.0) or 0.0)))
    w = int(round(float(b.get("Width", 0.0) or 0.0)))
    h = int(round(float(b.get("Height", 0.0) or 0.0)))
    region = _region_from_xywh(x, y, w, h)
    if not region:
        return {
            "ok": False,
            "state": "bad_bounds",
            "reliability": "low",
            "note": "Selected window has invalid bounds",
            "region": None,
        }
    return {
        "ok": True,
        "state": "tracking",
        "reliability": "high",
        "note": "Window tracked from compositor bounds",
        "region": region,
        "window_id": int(best.get("kCGWindowNumber", 0) or 0),
        "owner": str(best.get("kCGWindowOwnerName", "")),
        "title": str(best.get("kCGWindowName", "")),
        "bounds": {"x": x, "y": y, "w": w, "h": h},
    }


def _load_fastmcp_class():
    from mcp.server.fastmcp import FastMCP

    return FastMCP


def resolve_default_flameshot_bin() -> Optional[Path]:
    env = os.environ.get("FLAMESHOT_BIN")
    if env:
        p = Path(env)
        if p.exists():
            return p
    candidates = [
        Path("/tmp/flameshot/build/src/flameshot.app/Contents/MacOS/flameshot"),
        Path("/Applications/Flameshot.app/Contents/MacOS/flameshot"),
    ]
    for c in candidates:
        if c.exists():
            return c
    found = shutil.which("flameshot")
    if found:
        return Path(found)
    return None


def _tail_events(path: Path, lines: int = 50) -> list[dict[str, Any]]:
    if lines <= 0:
        return []
    if not path.exists():
        return []
    raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    picked = raw_lines[-int(lines) :]
    out: list[dict[str, Any]] = []
    for line in picked:
        txt = str(line).strip()
        if not txt:
            continue
        try:
            parsed = json.loads(txt)
            if isinstance(parsed, dict):
                out.append(parsed)
        except Exception:
            out.append({"type": "raw", "line": txt})
    return out


def capture_frame_from_flameshot(
    *,
    flameshot_bin: Path,
    mode: str,
    screen_number: int,
    region: Optional[str],
    delay_ms: int,
    timeout_sec: float,
) -> tuple[Optional[np.ndarray], str]:
    cmd = [str(flameshot_bin), str(mode).strip().lower()]
    if cmd[-1] not in {"screen", "full"}:
        return None, f"unsupported flameshot mode: {mode}"
    if cmd[-1] == "screen":
        cmd.extend(["-n", str(int(screen_number))])
        if str(region or "").strip():
            cmd.extend(["--region", str(region).strip()])
    if int(delay_ms) > 0:
        cmd.extend(["-d", str(int(delay_ms))])
    cmd.append("-r")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=max(float(timeout_sec), 0.5),
            check=False,
        )
    except Exception as exc:
        return None, f"flameshot subprocess failed: {exc}"

    if int(proc.returncode) != 0:
        stderr = proc.stderr.decode("utf-8", errors="ignore").strip()
        return None, f"flameshot rc={proc.returncode} stderr={stderr[:400]}"
    if not proc.stdout:
        stderr = proc.stderr.decode("utf-8", errors="ignore").strip()
        return None, f"flameshot returned empty image data; stderr={stderr[:400]}"

    arr = np.frombuffer(proc.stdout, dtype=np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if frame is None:
        return None, "failed to decode PNG from flameshot raw output"
    return frame, ""


def _load_webrtc_sdk() -> dict[str, Any]:
    try:
        from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack  # type: ignore
        from aiortc.contrib.signaling import BYE, TcpSocketSignaling  # type: ignore
        from av import VideoFrame  # type: ignore
    except Exception as exc:
        raise RuntimeError("WebRTC dependencies missing. Install `aiortc` (and `av`).") from exc
    return {
        "RTCPeerConnection": RTCPeerConnection,
        "RTCSessionDescription": RTCSessionDescription,
        "VideoStreamTrack": VideoStreamTrack,
        "TcpSocketSignaling": TcpSocketSignaling,
        "BYE": BYE,
        "VideoFrame": VideoFrame,
    }


def _queue_get_timeout(q: "queue.Queue[dict[str, Any]]", timeout: float) -> Optional[dict[str, Any]]:
    try:
        item = q.get(timeout=max(float(timeout), 0.01))
        return item if isinstance(item, dict) else None
    except queue.Empty:
        return None


def _handle_webrtc_control_message(
    *,
    message: Any,
    state: SharedState,
    desktop_action_queue: "queue.Queue[dict[str, Any]]",
    writer: EventWriter,
) -> None:
    txt = ""
    if isinstance(message, bytes):
        try:
            txt = message.decode("utf-8", errors="ignore").strip()
        except Exception:
            txt = ""
    else:
        txt = str(message or "").strip()
    if not txt:
        return

    parsed: dict[str, Any] = {}
    try:
        obj = json.loads(txt)
        if isinstance(obj, dict):
            parsed = obj
    except Exception:
        parsed = {}

    if parsed:
        typ = str(parsed.get("type", "")).strip().lower()
        if typ in {"snapshot", "snapshot_request"}:
            reason = str(parsed.get("reason", "webrtc-request"))
            state.request_snapshot(reason)
            writer.emit({"type": "command", "source": "webrtc", "command": "snapshot", "reason": reason})
            return
        if typ in {"desktop_action", "desktop_command"}:
            cmd = str(parsed.get("command", "")).strip()
            if not cmd:
                return
            act = parse_desktop_action(cmd)
            if act is None:
                writer.emit({"type": "desktop_action_rejected", "source": "webrtc", "command": cmd})
                return
            desktop_action_queue.put(
                {
                    "action": act,
                    "source": "webrtc",
                    "actor": str(parsed.get("actor", "webrtc")),
                    "raw_text": cmd,
                }
            )
            writer.emit({"type": "desktop_action_queued", "source": "webrtc", "action": act, "text": cmd})
            return

    if contains_snapshot_command(txt):
        state.request_snapshot(txt)
        writer.emit({"type": "command", "source": "webrtc", "command": "snapshot", "text": txt})
        return

    act = parse_desktop_action(txt)
    if act is None:
        writer.emit({"type": "webrtc_message_ignored", "source": "webrtc", "text": txt[:200]})
        return
    desktop_action_queue.put(
        {
            "action": act,
            "source": "webrtc",
            "actor": "webrtc",
            "raw_text": txt,
        }
    )
    writer.emit({"type": "desktop_action_queued", "source": "webrtc", "action": act, "text": txt})


async def run_webrtc_bridge(
    *,
    state: SharedState,
    writer: EventWriter,
    stop_event: threading.Event,
    frame_hub: FrameHub,
    event_queue: "queue.Queue[dict[str, Any]]",
    desktop_action_queue: "queue.Queue[dict[str, Any]]",
    signaling_host: str,
    signaling_port: int,
    role: str,
    channel_label: str,
    max_fps: float,
) -> None:
    sdk = _load_webrtc_sdk()
    RTCPeerConnection = sdk["RTCPeerConnection"]
    RTCSessionDescription = sdk["RTCSessionDescription"]
    VideoStreamTrack = sdk["VideoStreamTrack"]
    TcpSocketSignaling = sdk["TcpSocketSignaling"]
    BYE = sdk["BYE"]
    VideoFrame = sdk["VideoFrame"]

    class BridgeVideoTrack(VideoStreamTrack):  # type: ignore[misc]
        def __init__(self, frame_hub_obj: FrameHub, target_fps: float):
            super().__init__()
            self._frame_hub = frame_hub_obj
            self._period = 1.0 / max(float(target_fps), 1.0)
            self._next_deadline = 0.0

        async def recv(self):  # type: ignore[override]
            now = time.time()
            if self._next_deadline > now:
                await asyncio.sleep(self._next_deadline - now)
            self._next_deadline = time.time() + self._period

            frame_np, frame_id, _ = self._frame_hub.snapshot()
            if frame_np is None:
                frame_np = np.zeros((360, 640, 3), dtype=np.uint8)
                cv2.putText(
                    frame_np,
                    "waiting for bridge frame",
                    (16, 28),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    (255, 255, 255),
                    2,
                )
            cv2.putText(
                frame_np,
                f"frame:{int(frame_id)}",
                (16, max(40, frame_np.shape[0] - 16)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (0, 230, 255),
                2,
            )
            vf = VideoFrame.from_ndarray(frame_np, format="bgr24")
            pts, time_base = await self.next_timestamp()
            vf.pts = pts
            vf.time_base = time_base
            return vf

    pc = RTCPeerConnection()
    signaling = TcpSocketSignaling(str(signaling_host), int(signaling_port))
    role_norm = str(role or "offer").strip().lower()
    channel_ref: dict[str, Any] = {"channel": None}

    def bind_channel(ch: Any) -> None:
        channel_ref["channel"] = ch

        @ch.on("open")
        def _on_open() -> None:
            writer.emit(
                {
                    "type": "webrtc_datachannel_open",
                    "source": "webrtc",
                    "label": str(getattr(ch, "label", "")),
                }
            )

        @ch.on("message")
        def _on_message(message: Any) -> None:
            _handle_webrtc_control_message(
                message=message,
                state=state,
                desktop_action_queue=desktop_action_queue,
                writer=writer,
            )

        @ch.on("close")
        def _on_close() -> None:
            writer.emit({"type": "webrtc_datachannel_close", "source": "webrtc"})

    @pc.on("connectionstatechange")
    async def _on_conn_state() -> None:
        writer.emit(
            {
                "type": "webrtc_connection_state",
                "source": "webrtc",
                "state": str(getattr(pc, "connectionState", "")),
            }
        )

    @pc.on("datachannel")
    def _on_datachannel(ch: Any) -> None:
        bind_channel(ch)

    pc.addTrack(BridgeVideoTrack(frame_hub, target_fps=max(float(max_fps), 1.0)))

    async def _event_sender_loop() -> None:
        while not stop_event.is_set():
            ev = await asyncio.to_thread(_queue_get_timeout, event_queue, 0.25)
            if ev is None:
                continue
            ch = channel_ref.get("channel")
            if ch is None or str(getattr(ch, "readyState", "")).lower() != "open":
                continue
            try:
                payload = {"type": "bridge_event", "event": ev}
                ch.send(json.dumps(payload, ensure_ascii=True))
            except Exception as exc:
                writer.emit({"type": "webrtc_send_error", "source": "webrtc", "message": str(exc)})

    sender_task: Optional[asyncio.Task[Any]] = None
    try:
        await signaling.connect()
        writer.emit(
            {
                "type": "webrtc_signaling_ready",
                "source": "webrtc",
                "host": str(signaling_host),
                "port": int(signaling_port),
                "role": role_norm,
                "channel_label": str(channel_label),
            }
        )

        if role_norm == "offer":
            bind_channel(pc.createDataChannel(str(channel_label or "bridge-events")))
            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)
            await signaling.send(pc.localDescription)
            writer.emit({"type": "webrtc_offer_sent", "source": "webrtc"})
            ans = await asyncio.wait_for(signaling.receive(), timeout=120.0)
            if isinstance(ans, RTCSessionDescription):
                await pc.setRemoteDescription(ans)
                writer.emit({"type": "webrtc_answer_received", "source": "webrtc"})
            else:
                writer.emit({"type": "error", "source": "webrtc", "message": "invalid or missing answer"})
                return
        else:
            incoming = await asyncio.wait_for(signaling.receive(), timeout=120.0)
            if incoming is BYE:
                writer.emit({"type": "webrtc_bye_before_offer", "source": "webrtc"})
                return
            if not isinstance(incoming, RTCSessionDescription):
                writer.emit({"type": "error", "source": "webrtc", "message": "invalid or missing offer"})
                return
            await pc.setRemoteDescription(incoming)
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)
            await signaling.send(pc.localDescription)
            writer.emit({"type": "webrtc_answer_sent", "source": "webrtc"})

        sender_task = asyncio.create_task(_event_sender_loop())
        while not stop_event.is_set():
            st = str(getattr(pc, "connectionState", "")).lower()
            if st in {"failed", "closed"}:
                break
            await asyncio.sleep(0.25)
    except Exception as exc:
        writer.emit({"type": "error", "source": "webrtc", "message": f"webrtc failure: {exc}"})
    finally:
        if sender_task is not None:
            sender_task.cancel()
            try:
                await sender_task
            except BaseException:
                pass
        try:
            await pc.close()
        except Exception:
            pass
        try:
            await signaling.close()
        except Exception:
            pass
        writer.emit({"type": "webrtc_stop", "source": "webrtc"})


def create_mcp_server(
    *,
    name: str,
    host: str,
    port: int,
    state: SharedState,
    stop_event: threading.Event,
    events_path: Path,
    output_dir: Path,
    video_source: str,
    desktop_action_queue: "queue.Queue[dict[str, Any]]",
):
    try:
        fastmcp_cls = _load_fastmcp_class()
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("MCP SDK not available. Install with `pip install mcp`.") from exc

    app = fastmcp_cls(
        name=name,
        host=host,
        port=int(port),
        streamable_http_path="/mcp",
        mount_path="/",
    )

    @app.tool(name="vision_whisper.status")
    def _tool_status() -> dict[str, Any]:
        return {
            "ok": True,
            "running": not stop_event.is_set(),
            "pid": os.getpid(),
            "video_source": str(video_source),
            "events_path": str(events_path),
            "output_dir": str(output_dir),
            "state": state.status(),
        }

    @app.tool(name="vision_whisper.latest_vision")
    def _tool_latest_vision() -> dict[str, Any]:
        return {"ok": True, "vision": state.get_vision()}

    @app.tool(name="vision_whisper.latest_transcript")
    def _tool_latest_transcript() -> dict[str, Any]:
        return {"ok": True, "transcript": state.get_transcript()}

    @app.tool(name="vision_whisper.tail_events")
    def _tool_tail_events(lines: int = 50) -> dict[str, Any]:
        return {"ok": True, "events": _tail_events(events_path, lines=max(int(lines), 1))}

    @app.tool(name="vision_whisper.request_snapshot")
    def _tool_request_snapshot(reason: str = "mcp-request") -> dict[str, Any]:
        state.request_snapshot(str(reason or "mcp-request"))
        return {"ok": True, "queued": True, "reason": str(reason or "mcp-request")}

    @app.tool(name="vision_whisper.stop")
    def _tool_stop() -> dict[str, Any]:
        stop_event.set()
        return {"ok": True, "stopping": True}

    @app.tool(name="vision_whisper.desktop_action")
    def _tool_desktop_action(command: str, actor: str = "mcp") -> dict[str, Any]:
        action = parse_desktop_action(command)
        if action is None:
            return {"ok": False, "error": "unrecognized_command", "command": str(command)}
        payload = {
            "action": action,
            "source": "mcp",
            "actor": str(actor or "mcp"),
            "raw_text": str(command),
        }
        desktop_action_queue.put(payload)
        return {"ok": True, "queued": True, "action": action}

    return app


def contains_snapshot_command(text: str) -> bool:
    t = text.lower()
    keywords = [
        "snapshot",
        "take snapshot",
        "capture",
        "captura",
        "tomar captura",
        "foto",
        "pantallazo",
    ]
    return any(k in t for k in keywords)


def parse_desktop_action(text: str) -> Optional[dict[str, Any]]:
    raw = str(text or "").strip()
    if not raw:
        return None
    t = raw.lower().strip()

    # Optional wake prefix for safer operation.
    wake_prefixes = ("desktop ", "agent ", "accion ", "acción ")
    for p in wake_prefixes:
        if t.startswith(p):
            t = t[len(p) :].strip()
            break

    if t in {"click", "clic"}:
        return {"action": "click"}
    if t in {"double click", "doble clic"}:
        return {"action": "double_click"}
    if t in {"right click", "clic derecho"}:
        return {"action": "right_click"}
    if t in {"middle click", "clic medio"}:
        return {"action": "middle_click"}

    m = re.match(r"^(?:move mouse|mover mouse)\s+(-?\d+)\s+(-?\d+)$", t)
    if m:
        return {"action": "move", "x": int(m.group(1)), "y": int(m.group(2))}

    m = re.match(r"^(?:scroll|desplazar)\s+(-?\d+)$", t)
    if m:
        return {"action": "scroll", "amount": int(m.group(1))}

    m = re.match(r"^(?:type|escribir)\s+(.+)$", t)
    if m:
        return {"action": "type", "text": m.group(1)}

    m = re.match(r"^(?:press|presionar)\s+([a-z0-9_\\-]+)$", t)
    if m:
        return {"action": "press", "key": m.group(1)}

    m = re.match(r"^(?:hotkey|atajo)\s+([-a-z0-9_+ ]+)$", t)
    if m:
        keys = [k.strip() for k in re.split(r"[+ ]+", m.group(1)) if k.strip()]
        if keys:
            return {"action": "hotkey", "keys": keys}

    return None


def execute_desktop_action(
    *,
    action: dict[str, Any],
    pyautogui_mod: Any,
    dry_run: bool,
    move_duration_sec: float,
    type_interval_sec: float,
) -> tuple[bool, str]:
    a = str(action.get("action", "")).strip()
    if not a:
        return False, "missing action"

    if dry_run:
        return True, f"dry-run:{a}"

    try:
        if a == "click":
            pyautogui_mod.click()
        elif a == "double_click":
            pyautogui_mod.doubleClick()
        elif a == "right_click":
            pyautogui_mod.click(button="right")
        elif a == "middle_click":
            pyautogui_mod.click(button="middle")
        elif a == "move":
            pyautogui_mod.moveTo(int(action["x"]), int(action["y"]), duration=max(float(move_duration_sec), 0.0))
        elif a == "scroll":
            pyautogui_mod.scroll(int(action["amount"]))
        elif a == "type":
            pyautogui_mod.write(str(action["text"]), interval=max(float(type_interval_sec), 0.0))
        elif a == "press":
            pyautogui_mod.press(str(action["key"]))
        elif a == "hotkey":
            keys = [str(k) for k in (action.get("keys") or []) if str(k).strip()]
            if not keys:
                return False, "hotkey missing keys"
            pyautogui_mod.hotkey(*keys)
        else:
            return False, f"unsupported action: {a}"
        return True, "executed"
    except Exception as exc:
        return False, f"pyautogui execution failed: {exc}"


def compute_motion_score(prev_gray: Optional[np.ndarray], gray: np.ndarray) -> float:
    if prev_gray is None:
        return 0.0
    diff = cv2.absdiff(prev_gray, gray)
    return float(np.mean(diff))


def build_overlay_text(transcript: dict[str, Any]) -> str:
    txt = str(transcript.get("text", "")).strip()
    if not txt:
        return ""
    txt = re.sub(r"\s+", " ", txt)
    return txt[:96]


def vision_loop(
    *,
    state: SharedState,
    writer: EventWriter,
    stop_event: threading.Event,
    video_source: Any,
    sample_every_ms: int,
    show_window: bool,
    snapshots_dir: Path,
    flameshot_bin: Optional[Path],
    flameshot_mode: str,
    flameshot_screen_number: int,
    flameshot_region: Optional[str],
    flameshot_delay_ms: int,
    flameshot_timeout_sec: float,
    gst_in_pipeline: Optional[str],
    gst_out_pipeline: Optional[str],
    gst_out_fps: float,
    frame_hub: Optional[FrameHub],
    window_stick_enable: bool,
    window_stick_title_contains: str,
    window_stick_owner_contains: str,
    window_stick_refresh_ms: int,
    window_stick_missing_policy: str,
) -> None:
    cap: Optional[cv2.VideoCapture] = None
    gst_writer: Optional[cv2.VideoWriter] = None
    gst_in_raw = str(gst_in_pipeline or "").strip()
    gst_out_raw = str(gst_out_pipeline or "").strip()
    gst_in_mode_enabled = bool(gst_in_raw)
    synthetic_mode = (not gst_in_mode_enabled) and video_source == "synthetic"
    flameshot_mode_enabled = (not gst_in_mode_enabled) and video_source == "flameshot"

    if flameshot_mode_enabled and (flameshot_bin is None or not flameshot_bin.exists()):
        writer.emit(
            {
                "type": "error",
                "source": "opencv",
                "message": f"flameshot binary not found: {flameshot_bin}",
            }
        )
        return

    if gst_in_mode_enabled:
        cap = cv2.VideoCapture(gst_in_raw, cv2.CAP_GSTREAMER)
        if not cap.isOpened():
            writer.emit(
                {
                    "type": "error",
                    "source": "opencv",
                    "message": "Unable to open GStreamer input pipeline",
                    "gst_in_pipeline": gst_in_raw,
                }
            )
            return
        writer.emit(
            {
                "type": "gst_input_ready",
                "source": "opencv",
                "gst_in_pipeline": gst_in_raw,
            }
        )
    elif not synthetic_mode and not flameshot_mode_enabled:
        cap = cv2.VideoCapture(video_source)
        if not cap.isOpened():
            writer.emit(
                {
                    "type": "error",
                    "source": "opencv",
                    "message": f"Unable to open video source: {video_source}",
                }
            )
            return

    prev_gray: Optional[np.ndarray] = None
    frame_id = 0
    last_emit = 0.0
    last_window_refresh = 0.0
    active_flameshot_region = str(flameshot_region or "").strip() or None
    window_stick_active = bool(flameshot_mode_enabled and window_stick_enable)
    window_track: dict[str, Any] = {
        "enabled": bool(window_stick_active),
        "state": ("disabled" if not window_stick_active else "init"),
        "reliability": ("high" if not window_stick_active else "medium"),
        "note": (
            "static region or full-screen mode"
            if not window_stick_active
            else "awaiting first refresh"
        ),
        "region": active_flameshot_region,
    }
    last_window_track_sig = ""

    while not stop_event.is_set():
        now = time.time()
        if window_stick_active:
            refresh_sec = max(float(window_stick_refresh_ms) / 1000.0, 0.05)
            if (now - last_window_refresh) >= refresh_sec:
                tr = resolve_macos_window_track(
                    title_contains=str(window_stick_title_contains or ""),
                    owner_contains=str(window_stick_owner_contains or ""),
                )
                window_track = dict(tr)
                window_track["enabled"] = True
                window_track["ts"] = utc_now_iso()
                last_window_refresh = now

                if bool(tr.get("ok")) and str(tr.get("region") or "").strip():
                    active_flameshot_region = str(tr.get("region")).strip()
                else:
                    policy = str(window_stick_missing_policy or "hold-last-region").strip().lower()
                    if policy == "pause-capture":
                        window_track["note"] = f"{window_track.get('note', '')}; pause-capture"
                        sig = _json_dumps(
                            {
                                "state": window_track.get("state"),
                                "region": active_flameshot_region,
                                "policy": policy,
                                "note": window_track.get("note"),
                            }
                        )
                        if sig != last_window_track_sig:
                            writer.emit({"type": "window_track", "source": "flameshot", "track": dict(window_track)})
                            last_window_track_sig = sig
                        time.sleep(refresh_sec)
                        continue
                    if policy == "capture-without-region":
                        active_flameshot_region = None
                        window_track["note"] = f"{window_track.get('note', '')}; capture-without-region"
                    else:
                        window_track["note"] = f"{window_track.get('note', '')}; hold-last-region"
                        if active_flameshot_region:
                            window_track["reliability"] = "medium"

                sig = _json_dumps(
                    {
                        "state": window_track.get("state"),
                        "region": active_flameshot_region,
                        "window_id": window_track.get("window_id", 0),
                        "policy": str(window_stick_missing_policy or ""),
                        "reliability": window_track.get("reliability"),
                    }
                )
                if sig != last_window_track_sig:
                    writer.emit({"type": "window_track", "source": "flameshot", "track": dict(window_track)})
                    last_window_track_sig = sig

        if synthetic_mode:
            # Synthetic frame for no-camera environments.
            frame = np.zeros((480, 640, 3), dtype=np.uint8)
            x = (frame_id * 7) % 640
            cv2.rectangle(frame, (x, 120), (min(x + 120, 639), 220), (0, 255, 90), -1)
            cv2.putText(frame, "synthetic", (12, 32), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (255, 255, 255), 2)
            ok = True
        elif flameshot_mode_enabled:
            assert flameshot_bin is not None
            capture_mode = str(flameshot_mode)
            # flameshot applies --region on `screen`; auto-switch when region watch is active.
            if active_flameshot_region and capture_mode.strip().lower() == "full":
                capture_mode = "screen"
            frame, err = capture_frame_from_flameshot(
                flameshot_bin=flameshot_bin,
                mode=capture_mode,
                screen_number=flameshot_screen_number,
                region=active_flameshot_region,
                delay_ms=flameshot_delay_ms,
                timeout_sec=flameshot_timeout_sec,
            )
            if frame is None:
                writer.emit({"type": "warning", "source": "opencv", "message": f"flameshot capture failed: {err}"})
                time.sleep(max(sample_every_ms / 1000.0, 0.2))
                continue
            ok = True
        else:
            assert cap is not None
            ok, frame = cap.read()
            if not ok:
                writer.emit({"type": "warning", "source": "opencv", "message": "No frame read"})
                time.sleep(0.1)
                continue

        now = time.time()
        if now - last_emit < sample_every_ms / 1000.0:
            if show_window:
                cv2.imshow("opencv-whisper-bridge", frame)
                cv2.waitKey(1)
            frame_id += 1
            time.sleep(0.01)
            continue

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness = float(np.mean(gray))
        motion = compute_motion_score(prev_gray, gray)
        prev_gray = gray

        transcript = state.get_transcript()
        overlay = build_overlay_text(transcript)
        if overlay:
            cv2.putText(frame, overlay, (12, 460), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 220, 255), 2)
        if frame_hub is not None:
            frame_hub.update(frame, frame_id)

        if gst_out_raw:
            if gst_writer is None:
                h, w = frame.shape[:2]
                auto_fps = max(1.0, 1000.0 / max(float(sample_every_ms), 1.0))
                target_fps = float(gst_out_fps) if float(gst_out_fps) > 0.0 else auto_fps
                gst_writer = cv2.VideoWriter(
                    gst_out_raw,
                    cv2.CAP_GSTREAMER,
                    0,
                    float(target_fps),
                    (int(w), int(h)),
                    True,
                )
                if not gst_writer.isOpened():
                    writer.emit(
                        {
                            "type": "error",
                            "source": "opencv",
                            "message": "Unable to open GStreamer output pipeline",
                            "gst_out_pipeline": gst_out_raw,
                            "width": int(w),
                            "height": int(h),
                            "fps": float(target_fps),
                        }
                    )
                    gst_writer = None
                else:
                    writer.emit(
                        {
                            "type": "gst_output_ready",
                            "source": "opencv",
                            "gst_out_pipeline": gst_out_raw,
                            "width": int(w),
                            "height": int(h),
                            "fps": float(target_fps),
                        }
                    )
            if gst_writer is not None:
                gst_writer.write(frame)

        ev = {
            "type": "vision",
            "source": "opencv",
            "frame_id": frame_id,
            "brightness": round(brightness, 3),
            "motion": round(motion, 3),
            "video_source": str(video_source),
            "capture_backend": (
                "gstreamer"
                if gst_in_mode_enabled
                else ("flameshot" if flameshot_mode_enabled else ("synthetic" if synthetic_mode else "opencv"))
            ),
            "watch_region": str(active_flameshot_region or ""),
            "window_track_state": str(window_track.get("state", "disabled")),
            "capture_reliability": str(window_track.get("reliability", "high")),
        }
        if window_stick_active:
            ev["window_track"] = {
                "state": str(window_track.get("state", "")),
                "reliability": str(window_track.get("reliability", "")),
                "note": str(window_track.get("note", "")),
                "window_id": int(window_track.get("window_id", 0) or 0),
                "owner": str(window_track.get("owner", "")),
                "title": str(window_track.get("title", "")),
                "region": str(active_flameshot_region or ""),
            }
        state.update_vision(ev)
        writer.emit(ev)
        last_emit = now

        req, req_text = state.consume_snapshot_request()
        if req:
            snapshots_dir.mkdir(parents=True, exist_ok=True)
            shot = snapshots_dir / f"snapshot_{int(time.time() * 1000)}.png"
            cv2.imwrite(str(shot), frame)
            writer.emit(
                {
                    "type": "snapshot_saved",
                    "source": "opencv",
                    "path": str(shot),
                    "trigger_text": req_text,
                    "frame_id": frame_id,
                }
            )

        if show_window:
            cv2.imshow("opencv-whisper-bridge", frame)
            key = cv2.waitKey(1) & 0xFF
            if key == ord("q"):
                stop_event.set()
                break

        frame_id += 1

    if cap is not None:
        cap.release()
    if gst_writer is not None:
        gst_writer.release()
    if show_window:
        cv2.destroyAllWindows()


def run_whisper_cli(whisper_cli: Path, model: Path, audio_file: Path, out_base: Path, language: str) -> tuple[int, str, str]:
    cmd = [
        str(whisper_cli),
        "-m",
        str(model),
        "-f",
        str(audio_file),
        "-l",
        language,
        "-nt",
        "-np",
        "-otxt",
        "-of",
        str(out_base),
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    text_path = Path(str(out_base) + ".txt")
    transcript = text_path.read_text(encoding="utf-8", errors="ignore").strip() if text_path.exists() else ""
    return proc.returncode, transcript, proc.stderr.strip()


def whisper_loop(
    *,
    state: SharedState,
    writer: EventWriter,
    stop_event: threading.Event,
    whisper_cli: Optional[Path],
    model: Optional[Path],
    audio_glob: Optional[str],
    language: str,
    poll_sec: float,
    output_dir: Path,
    dry_run: bool,
    pyautogui_enabled: bool,
    desktop_action_queue: "queue.Queue[dict[str, Any]]",
) -> None:
    seen: set[str] = set()

    if dry_run:
        samples = [
            "hello world from whisper bridge",
            "captura por favor",
            "desktop click",
            "there is motion in camera zone A",
            "accion escribir hola mundo",
            "take snapshot now",
            "estado estable sin cambios",
        ]
        i = 0
        while not stop_event.is_set():
            text = samples[i % len(samples)]
            i += 1
            vision_ctx = state.get_vision()
            ev = {
                "type": "transcript",
                "source": "whisper-dry-run",
                "audio_file": "<synthetic>",
                "text": text,
                "vision_context": vision_ctx,
            }
            state.update_transcript(ev)
            writer.emit(ev)
            if contains_snapshot_command(text):
                state.request_snapshot(text)
                writer.emit({"type": "command", "source": "whisper-dry-run", "command": "snapshot", "text": text})
            if pyautogui_enabled:
                act = parse_desktop_action(text)
                if act is not None:
                    desktop_action_queue.put(
                        {
                            "action": act,
                            "source": "whisper-dry-run",
                            "actor": "whisper",
                            "raw_text": text,
                        }
                    )
                    writer.emit(
                        {
                            "type": "desktop_action_queued",
                            "source": "whisper-dry-run",
                            "action": act,
                            "text": text,
                        }
                    )
            time.sleep(max(poll_sec, 0.5))
        return

    if whisper_cli is None or model is None or not audio_glob:
        writer.emit(
            {
                "type": "error",
                "source": "whisper",
                "message": "real whisper mode requires --whisper-cli, --model, and --audio-glob",
            }
        )
        return

    while not stop_event.is_set():
        files = sorted(glob.glob(audio_glob))
        for raw in files:
            if stop_event.is_set():
                break
            if raw in seen:
                continue

            audio_file = Path(raw)
            seen.add(raw)
            out_base = output_dir / "transcripts" / audio_file.stem
            out_base.parent.mkdir(parents=True, exist_ok=True)

            rc, text, err = run_whisper_cli(whisper_cli, model, audio_file, out_base, language)
            vision_ctx = state.get_vision()

            ev = {
                "type": "transcript",
                "source": "whisper-cli",
                "audio_file": str(audio_file),
                "returncode": rc,
                "text": text,
                "stderr": err,
                "vision_context": vision_ctx,
            }
            state.update_transcript(ev)
            writer.emit(ev)

            if contains_snapshot_command(text):
                state.request_snapshot(text)
                writer.emit({"type": "command", "source": "whisper-cli", "command": "snapshot", "text": text})
            if pyautogui_enabled:
                act = parse_desktop_action(text)
                if act is not None:
                    desktop_action_queue.put(
                        {
                            "action": act,
                            "source": "whisper-cli",
                            "actor": "whisper",
                            "raw_text": text,
                        }
                    )
                    writer.emit(
                        {
                            "type": "desktop_action_queued",
                            "source": "whisper-cli",
                            "action": act,
                            "text": text,
                        }
                    )

        time.sleep(poll_sec)


def desktop_action_loop(
    *,
    stop_event: threading.Event,
    writer: EventWriter,
    desktop_action_queue: "queue.Queue[dict[str, Any]]",
    pyautogui_mod: Any,
    pyautogui_dry_run: bool,
    move_duration_sec: float,
    type_interval_sec: float,
) -> None:
    while not stop_event.is_set():
        try:
            payload = desktop_action_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        action = payload.get("action") or {}
        ok, msg = execute_desktop_action(
            action=action if isinstance(action, dict) else {},
            pyautogui_mod=pyautogui_mod,
            dry_run=bool(pyautogui_dry_run),
            move_duration_sec=float(move_duration_sec),
            type_interval_sec=float(type_interval_sec),
        )
        writer.emit(
            {
                "type": "desktop_action_result",
                "source": str(payload.get("source", "unknown")),
                "actor": str(payload.get("actor", "")),
                "raw_text": str(payload.get("raw_text", "")),
                "action": action if isinstance(action, dict) else {},
                "ok": bool(ok),
                "message": str(msg),
                "dry_run": bool(pyautogui_dry_run),
            }
        )


def resolve_default_whisper_cli() -> Optional[Path]:
    env = os.environ.get("WHISPER_CLI")
    if env:
        p = Path(env)
        if p.exists():
            return p
    candidates = [
        Path("/tmp/voice-ai/whisper.cpp/build/bin/whisper-cli"),
        Path("/usr/local/bin/whisper-cli"),
        Path("/opt/homebrew/bin/whisper-cli"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bridge OpenCV and whisper.cpp with shared events/state")
    parser.add_argument(
        "--video-source",
        default="0",
        help="OpenCV source: camera index, file path, 'synthetic', or 'flameshot'",
    )
    parser.add_argument("--sample-every-ms", type=int, default=500, help="Vision event cadence in ms")
    parser.add_argument("--show-window", action="store_true", help="Show preview window (press 'q' to quit)")
    parser.add_argument("--flameshot-bin", default=None, help="Path to flameshot binary")
    parser.add_argument("--flameshot-mode", default="full", choices=("full", "screen"))
    parser.add_argument("--flameshot-screen-number", type=int, default=0)
    parser.add_argument("--flameshot-region", default=None, help="Region syntax: WxH+X+Y")
    parser.add_argument("--watch-region", default=None, help="Alias of --flameshot-region for continuous region watch")
    parser.add_argument("--flameshot-delay-ms", type=int, default=0)
    parser.add_argument("--flameshot-timeout-sec", type=float, default=10.0)
    parser.add_argument("--gst-in-pipeline", default=None, help="GStreamer input pipeline (appsink)")
    parser.add_argument("--gst-out-pipeline", default=None, help="GStreamer output pipeline (appsrc)")
    parser.add_argument(
        "--gst-out-fps",
        type=float,
        default=0.0,
        help="Target FPS for GStreamer output (0 = auto from sample cadence)",
    )
    parser.add_argument(
        "--window-stick-enable",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Track a target window bounds and keep watch-region attached to it (macOS Quartz backend)",
    )
    parser.add_argument("--window-stick-title-contains", default="", help="Case-insensitive title substring filter")
    parser.add_argument("--window-stick-owner-contains", default="", help="Case-insensitive app/owner substring filter")
    parser.add_argument("--window-stick-refresh-ms", type=int, default=600, help="Window bounds refresh period")
    parser.add_argument(
        "--window-stick-missing-policy",
        default="hold-last-region",
        choices=("hold-last-region", "pause-capture", "capture-without-region"),
        help="Behavior when target window is not currently onscreen/rendered",
    )

    parser.add_argument("--whisper-cli", default=None, help="Path to whisper-cli binary")
    parser.add_argument("--model", default=None, help="Path to whisper ggml model")
    parser.add_argument("--audio-glob", default=None, help="Glob to watch audio files (e.g. /tmp/in/*.wav)")
    parser.add_argument("--language", default="auto", help="Whisper language (auto, en, es, ...)")
    parser.add_argument("--poll-sec", type=float, default=1.0, help="Polling interval for audio glob")
    parser.add_argument("--dry-run-whisper", action="store_true", help="Generate synthetic transcript events")

    parser.add_argument("--output-dir", default="/tmp/opencv-whisper-bridge", help="Output dir for events/transcripts/snapshots")
    parser.add_argument("--max-runtime-sec", type=int, default=0, help="Stop automatically after N seconds (0 = run forever)")
    parser.add_argument("--mcp-enable", action="store_true", help="Expose MCP-compatible API for this long-running bridge")
    parser.add_argument("--mcp-name", default="opencv-whisper-bridge-mcp")
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8788)
    parser.add_argument("--mcp-transport", default="streamable-http", choices=("stdio", "sse", "streamable-http"))
    parser.add_argument("--pyautogui-enable", action="store_true", help="Enable desktop action execution from transcript commands")
    parser.add_argument(
        "--pyautogui-dry-run",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="When enabled, logs desktop actions without injecting real OS events",
    )
    parser.add_argument("--pyautogui-failsafe", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--pyautogui-pause-sec", type=float, default=0.05)
    parser.add_argument("--pyautogui-move-duration-sec", type=float, default=0.1)
    parser.add_argument("--pyautogui-type-interval-sec", type=float, default=0.01)
    parser.add_argument("--webrtc-enable", action="store_true", help="Enable WebRTC video/data-channel bridge (aiortc)")
    parser.add_argument("--webrtc-signaling-host", default="127.0.0.1", help="TCP signaling host for aiortc TcpSocketSignaling")
    parser.add_argument("--webrtc-signaling-port", type=int, default=8766, help="TCP signaling port for aiortc")
    parser.add_argument("--webrtc-role", default="offer", choices=("offer", "answer"))
    parser.add_argument("--webrtc-channel-label", default="bridge-events")
    parser.add_argument("--webrtc-max-fps", type=float, default=12.0, help="WebRTC outbound video max fps")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if str(args.watch_region or "").strip() and not str(args.flameshot_region or "").strip():
        args.flameshot_region = str(args.watch_region).strip()
    gst_in_pipeline = str(args.gst_in_pipeline or "").strip()
    gst_out_pipeline = str(args.gst_out_pipeline or "").strip()
    video_source = parse_video_source(args.video_source)
    if gst_in_pipeline:
        video_source = "gstreamer"
    flameshot_bin = Path(args.flameshot_bin) if args.flameshot_bin else resolve_default_flameshot_bin()
    if video_source == "flameshot" and (flameshot_bin is None or not flameshot_bin.exists()):
        print("[bridge][error] video-source=flameshot but flameshot binary not found. Use --flameshot-bin.")
        return 2

    whisper_cli = Path(args.whisper_cli) if args.whisper_cli else resolve_default_whisper_cli()
    if not args.dry_run_whisper:
        if whisper_cli is None or not whisper_cli.exists():
            print("[bridge][error] whisper-cli not found. Use --whisper-cli or set WHISPER_CLI.")
            return 2
        if args.model is None or not Path(args.model).exists():
            print("[bridge][error] --model is required in real mode and must exist.")
            return 2

    state = SharedState()
    frame_hub = FrameHub()
    writer = EventWriter(out_dir / "events.jsonl")
    stop_event = threading.Event()
    desktop_action_queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
    pyautogui_mod: Any = None
    desktop_action_t: Optional[threading.Thread] = None
    webrtc_t: Optional[threading.Thread] = None

    def _handle_signal(signum: int, _frame: Any) -> None:
        writer.emit({"type": "signal", "source": "process", "signal": signum})
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    writer.start()
    writer.emit(
        {
            "type": "bridge_start",
            "source": "process",
            "pid": os.getpid(),
            "argv": shlex.join(os.sys.argv),
            "output_dir": str(out_dir),
            "video_source": str(video_source),
            "dry_run_whisper": bool(args.dry_run_whisper),
            "whisper_cli": str(whisper_cli) if whisper_cli else "",
            "flameshot_bin": str(flameshot_bin) if flameshot_bin else "",
            "watch_region": str(args.flameshot_region or ""),
            "gst_in_pipeline": gst_in_pipeline,
            "gst_out_pipeline": gst_out_pipeline,
            "gst_out_fps": float(args.gst_out_fps),
            "webrtc_enable": bool(args.webrtc_enable),
            "webrtc_signaling_host": str(args.webrtc_signaling_host),
            "webrtc_signaling_port": int(args.webrtc_signaling_port),
            "webrtc_role": str(args.webrtc_role),
            "webrtc_channel_label": str(args.webrtc_channel_label),
            "webrtc_max_fps": float(args.webrtc_max_fps),
            "window_stick_enable": bool(args.window_stick_enable),
            "window_stick_title_contains": str(args.window_stick_title_contains or ""),
            "window_stick_owner_contains": str(args.window_stick_owner_contains or ""),
            "window_stick_refresh_ms": int(args.window_stick_refresh_ms),
            "window_stick_missing_policy": str(args.window_stick_missing_policy),
            "mcp_enabled": bool(args.mcp_enable),
            "pyautogui_enabled": bool(args.pyautogui_enable),
            "pyautogui_dry_run": bool(args.pyautogui_dry_run),
            "mcp_endpoint": (
                f"http://{args.mcp_host}:{int(args.mcp_port)}/mcp"
                if bool(args.mcp_enable) and str(args.mcp_transport) == "streamable-http"
                else ""
            ),
        }
    )

    if bool(args.webrtc_enable):
        try:
            _load_webrtc_sdk()
        except Exception as exc:
            writer.emit({"type": "error", "source": "webrtc", "message": str(exc)})
            writer.stop(timeout=1.5)
            print(f"[bridge][error] {exc}")
            return 2
        webrtc_event_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=2048)

        def _webrtc_listener(ev: dict[str, Any]) -> None:
            try:
                webrtc_event_queue.put_nowait(dict(ev))
            except queue.Full:
                try:
                    webrtc_event_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    webrtc_event_queue.put_nowait(dict(ev))
                except queue.Full:
                    pass

        writer.subscribe(_webrtc_listener)

        def _run_webrtc() -> None:
            try:
                asyncio.run(
                    run_webrtc_bridge(
                        state=state,
                        writer=writer,
                        stop_event=stop_event,
                        frame_hub=frame_hub,
                        event_queue=webrtc_event_queue,
                        desktop_action_queue=desktop_action_queue,
                        signaling_host=str(args.webrtc_signaling_host),
                        signaling_port=int(args.webrtc_signaling_port),
                        role=str(args.webrtc_role),
                        channel_label=str(args.webrtc_channel_label),
                        max_fps=float(args.webrtc_max_fps),
                    )
                )
            except Exception as exc:
                writer.emit({"type": "error", "source": "webrtc", "message": f"webrtc thread failed: {exc}"})

        webrtc_t = threading.Thread(
            target=_run_webrtc,
            name="webrtc-bridge",
            daemon=True,
        )
        webrtc_t.start()
        writer.emit(
            {
                "type": "webrtc_start",
                "source": "process",
                "signaling_host": str(args.webrtc_signaling_host),
                "signaling_port": int(args.webrtc_signaling_port),
                "role": str(args.webrtc_role),
                "channel_label": str(args.webrtc_channel_label),
                "max_fps": float(args.webrtc_max_fps),
            }
        )

    if bool(args.pyautogui_enable):
        try:
            import pyautogui as _pg  # type: ignore

            pyautogui_mod = _pg
            pyautogui_mod.FAILSAFE = bool(args.pyautogui_failsafe)
            pyautogui_mod.PAUSE = max(float(args.pyautogui_pause_sec), 0.0)
            writer.emit(
                {
                    "type": "desktop_action_layer_ready",
                    "source": "process",
                    "dry_run": bool(args.pyautogui_dry_run),
                    "failsafe": bool(args.pyautogui_failsafe),
                    "pause_sec": float(args.pyautogui_pause_sec),
                }
            )
            desktop_action_t = threading.Thread(
                target=desktop_action_loop,
                kwargs={
                    "stop_event": stop_event,
                    "writer": writer,
                    "desktop_action_queue": desktop_action_queue,
                    "pyautogui_mod": pyautogui_mod,
                    "pyautogui_dry_run": bool(args.pyautogui_dry_run),
                    "move_duration_sec": float(args.pyautogui_move_duration_sec),
                    "type_interval_sec": float(args.pyautogui_type_interval_sec),
                },
                name="desktop-action-loop",
                daemon=True,
            )
            desktop_action_t.start()
        except Exception as exc:
            writer.emit(
                {
                    "type": "error",
                    "source": "desktop-action",
                    "message": f"pyautogui not available: {exc}",
                }
            )
            print(f"[bridge][error] pyautogui not available: {exc}")
            return 2

    mcp_t: Optional[threading.Thread] = None
    if bool(args.mcp_enable):
        mcp_app = create_mcp_server(
            name=str(args.mcp_name),
            host=str(args.mcp_host),
            port=int(args.mcp_port),
            state=state,
            stop_event=stop_event,
            events_path=out_dir / "events.jsonl",
            output_dir=out_dir,
            video_source=str(video_source),
            desktop_action_queue=desktop_action_queue,
        )

        def _run_mcp() -> None:
            try:
                mcp_app.run(transport=str(args.mcp_transport))  # type: ignore[call-arg]
            except TypeError:
                mcp_app.run()

        mcp_t = threading.Thread(target=_run_mcp, name="mcp-server", daemon=True)
        mcp_t.start()
        writer.emit(
            {
                "type": "mcp_start",
                "source": "process",
                "transport": str(args.mcp_transport),
                "host": str(args.mcp_host),
                "port": int(args.mcp_port),
                "endpoint": f"http://{args.mcp_host}:{int(args.mcp_port)}/mcp",
            }
        )

    vision_t = threading.Thread(
        target=vision_loop,
        kwargs={
            "state": state,
            "writer": writer,
            "stop_event": stop_event,
            "video_source": video_source,
            "sample_every_ms": args.sample_every_ms,
            "show_window": args.show_window,
            "snapshots_dir": out_dir / "snapshots",
            "flameshot_bin": flameshot_bin,
            "flameshot_mode": str(args.flameshot_mode),
            "flameshot_screen_number": int(args.flameshot_screen_number),
            "flameshot_region": args.flameshot_region,
            "flameshot_delay_ms": int(args.flameshot_delay_ms),
            "flameshot_timeout_sec": float(args.flameshot_timeout_sec),
            "gst_in_pipeline": gst_in_pipeline,
            "gst_out_pipeline": gst_out_pipeline,
            "gst_out_fps": float(args.gst_out_fps),
            "frame_hub": frame_hub,
            "window_stick_enable": bool(args.window_stick_enable),
            "window_stick_title_contains": str(args.window_stick_title_contains),
            "window_stick_owner_contains": str(args.window_stick_owner_contains),
            "window_stick_refresh_ms": int(args.window_stick_refresh_ms),
            "window_stick_missing_policy": str(args.window_stick_missing_policy),
        },
        name="vision-loop",
        daemon=True,
    )

    whisper_t = threading.Thread(
        target=whisper_loop,
        kwargs={
            "state": state,
            "writer": writer,
            "stop_event": stop_event,
            "whisper_cli": whisper_cli,
            "model": Path(args.model) if args.model else None,
            "audio_glob": args.audio_glob,
            "language": args.language,
            "poll_sec": args.poll_sec,
            "output_dir": out_dir,
            "dry_run": bool(args.dry_run_whisper),
            "pyautogui_enabled": bool(args.pyautogui_enable),
            "desktop_action_queue": desktop_action_queue,
        },
        name="whisper-loop",
        daemon=True,
    )

    vision_t.start()
    whisper_t.start()

    started = time.time()
    try:
        while not stop_event.is_set():
            if args.max_runtime_sec > 0 and (time.time() - started) >= args.max_runtime_sec:
                stop_event.set()
                break
            time.sleep(0.2)
    finally:
        stop_event.set()
        vision_t.join(timeout=3.0)
        whisper_t.join(timeout=3.0)
        if desktop_action_t is not None:
            desktop_action_t.join(timeout=2.0)
        if webrtc_t is not None:
            webrtc_t.join(timeout=2.0)
        if mcp_t is not None:
            mcp_t.join(timeout=1.0)
        writer.emit({"type": "bridge_stop", "source": "process"})
        writer.stop(timeout=3.0)

    if not (bool(args.mcp_enable) and str(args.mcp_transport) == "stdio"):
        try:
            print(f"[bridge] done. events: {out_dir / 'events.jsonl'}")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
