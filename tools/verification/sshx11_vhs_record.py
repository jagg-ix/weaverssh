#!/usr/bin/env python3
from __future__ import annotations

"""VHS recorder/publisher for sshx11 collaborative terminal sessions."""

import argparse
from datetime import datetime, timezone
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SESS_ROOT = REPO_ROOT / "verification_results" / "runtime" / "collab_terminal"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "verification_results" / "runtime" / "collab_terminal_recordings"
DEFAULT_PUBLISH_DIR = REPO_ROOT / "verification_results" / "published" / "vhs"


def _now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _is_exec(name: str) -> bool:
    return bool(shutil.which(str(name)))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_recent_commands(session_root: Path, session: str, limit: int) -> list[str]:
    cmdlog = session_root / session / "commands.ndjson"
    if not cmdlog.exists():
        return []
    cmds: list[str] = []
    for raw in cmdlog.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if row.get("kind") != "input":
            continue
        text = str(row.get("text", "")).strip()
        if text:
            cmds.append(text)
    return cmds[-max(1, int(limit)) :]


def _escape_tape_text(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _build_tape(
    *,
    output_gif: Path,
    commands: list[str],
    shell_cmd: str,
    theme: str,
    width: int,
    height: int,
    font_size: int,
    typing_speed_ms: int,
    sleep_ms: int,
) -> str:
    lines: list[str] = []
    lines.append(f"Output {output_gif}")
    lines.append(f'Set Theme "{_escape_tape_text(theme)}"')
    lines.append(f"Set Width {int(width)}")
    lines.append(f"Set Height {int(height)}")
    lines.append(f"Set FontSize {int(font_size)}")
    lines.append(f'Set Shell "{_escape_tape_text(shell_cmd)}"')
    lines.append(f"Set TypingSpeed {max(0, int(typing_speed_ms))}ms")
    lines.append("")
    lines.append(f'Type "printf \\"[sshx11-collab-vhs]\\n\\""')
    lines.append("Enter")
    lines.append(f"Sleep {max(0, int(sleep_ms))}ms")
    for cmd in commands:
        lines.append(f'Type "{_escape_tape_text(cmd)}"')
        lines.append("Enter")
        lines.append(f"Sleep {max(0, int(sleep_ms))}ms")
    return "\n".join(lines).strip() + "\n"


def probe(*, as_json: bool) -> int:
    payload = {
        "ok": True,
        "tools": {
            "vhs": _is_exec("vhs"),
            "bash": _is_exec("bash"),
            "tmux": _is_exec("tmux"),
            "screen": _is_exec("screen"),
            "git": _is_exec("git"),
        },
        "defaults": {
            "session_root": str(DEFAULT_SESS_ROOT),
            "output_dir": str(DEFAULT_OUTPUT_DIR),
            "publish_dir": str(DEFAULT_PUBLISH_DIR),
        },
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for k, v in payload.items():
            if isinstance(v, dict):
                print(f"{k}={json.dumps(v, ensure_ascii=True)}")
            else:
                print(f"{k}={v}")
    return 0


def render(
    *,
    session: str,
    session_root: Path,
    output_dir: Path,
    publish_dir: Path | None,
    public_base_url: str,
    scp_target: str,
    tail_commands: int,
    command: list[str],
    theme: str,
    width: int,
    height: int,
    font_size: int,
    typing_speed_ms: int,
    sleep_ms: int,
    dry_run: bool,
    as_json: bool,
) -> int:
    meta_path = session_root / session / "session.json"
    meta = _read_json(meta_path)
    if not meta and not command:
        out = {"ok": False, "error": "session_meta_not_found", "session": session, "meta_path": str(meta_path)}
        print(json.dumps(out, indent=2))
        return 1

    commands = list(command or [])
    if not commands:
        commands = _load_recent_commands(session_root, session, tail_commands)
    if not commands:
        commands = [f"python3 tools/verification/sshx11_collab_terminal.py status --session {session} --json"]

    shell_cmd = str(meta.get("resolved_shell") or "bash")
    if not shell_cmd:
        shell_cmd = "bash"

    ts = _now_tag()
    output_dir.mkdir(parents=True, exist_ok=True)
    base = f"{session}_{ts}"
    tape_path = output_dir / f"{base}.tape"
    gif_path = output_dir / f"{base}.gif"
    meta_out_path = output_dir / f"{base}.json"

    tape_text = _build_tape(
        output_gif=gif_path,
        commands=commands,
        shell_cmd=shell_cmd,
        theme=theme,
        width=width,
        height=height,
        font_size=font_size,
        typing_speed_ms=typing_speed_ms,
        sleep_ms=sleep_ms,
    )
    tape_path.write_text(tape_text, encoding="utf-8")

    vhs_ok = _is_exec("vhs")
    run_ok = True
    render_stderr = ""
    render_stdout = ""
    if not dry_run:
        if not vhs_ok:
            run_ok = False
            render_stderr = "vhs binary not found; install vhs or run --dry-run"
        else:
            p = subprocess.run(["vhs", str(tape_path)], capture_output=True, text=True, check=False)
            run_ok = int(p.returncode) == 0
            render_stdout = p.stdout or ""
            render_stderr = p.stderr or ""

    publish_payload: dict[str, Any] = {"ok": False, "published": False}
    if run_ok and gif_path.exists():
        pub_gif = gif_path
        pub_tape = tape_path
        if publish_dir is not None:
            publish_dir.mkdir(parents=True, exist_ok=True)
            pub_gif = publish_dir / gif_path.name
            pub_tape = publish_dir / tape_path.name
            shutil.copy2(gif_path, pub_gif)
            shutil.copy2(tape_path, pub_tape)
        rel = pub_gif.relative_to(REPO_ROOT) if str(pub_gif).startswith(str(REPO_ROOT)) else pub_gif
        url = f"{public_base_url.rstrip('/')}/{pub_gif.name}" if public_base_url else str(rel)
        publish_payload = {
            "ok": True,
            "published": publish_dir is not None,
            "publish_dir": str(publish_dir) if publish_dir is not None else "",
            "gif_path": str(pub_gif),
            "tape_path": str(pub_tape),
            "url": str(url),
        }
        if scp_target:
            p_scp = subprocess.run(
                ["scp", str(pub_gif), str(pub_tape), str(scp_target)],
                capture_output=True,
                text=True,
                check=False,
            )
            publish_payload["scp_target"] = str(scp_target)
            publish_payload["scp_ok"] = int(p_scp.returncode) == 0
            publish_payload["scp_stdout"] = p_scp.stdout or ""
            publish_payload["scp_stderr"] = p_scp.stderr or ""

    payload = {
        "ok": bool(run_ok),
        "session": str(session),
        "session_meta_path": str(meta_path),
        "commands_count": len(commands),
        "commands": commands,
        "dry_run": bool(dry_run),
        "vhs_available": bool(vhs_ok),
        "tape_path": str(tape_path),
        "gif_path": str(gif_path),
        "render_stdout": render_stdout,
        "render_stderr": render_stderr,
        "publish": publish_payload,
    }
    meta_out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    payload["artifact_path"] = str(meta_out_path)

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for k, v in payload.items():
            if isinstance(v, (dict, list)):
                print(f"{k}={json.dumps(v, ensure_ascii=True)}")
            else:
                print(f"{k}={v}")
    return 0 if run_ok else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_probe = sub.add_parser("probe", help="Probe VHS/tmux/screen/bash availability")
    p_probe.add_argument("--json", action="store_true")

    p_render = sub.add_parser("render", help="Generate tape and render GIF from collab session")
    p_render.add_argument("--session", required=True)
    p_render.add_argument("--session-root", default=str(DEFAULT_SESS_ROOT))
    p_render.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p_render.add_argument("--tail-commands", type=int, default=24)
    p_render.add_argument("--command", action="append", default=[])
    p_render.add_argument("--theme", default="Catppuccin Mocha")
    p_render.add_argument("--width", type=int, default=1200)
    p_render.add_argument("--height", type=int, default=700)
    p_render.add_argument("--font-size", type=int, default=14)
    p_render.add_argument("--typing-speed-ms", type=int, default=12)
    p_render.add_argument("--sleep-ms", type=int, default=500)
    p_render.add_argument("--dry-run", action="store_true")
    p_render.add_argument("--json", action="store_true")

    p_render_pub = sub.add_parser("render-publish", help="Render GIF then publish into local publish dir")
    p_render_pub.add_argument("--session", required=True)
    p_render_pub.add_argument("--session-root", default=str(DEFAULT_SESS_ROOT))
    p_render_pub.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p_render_pub.add_argument("--publish-dir", default=str(DEFAULT_PUBLISH_DIR))
    p_render_pub.add_argument("--public-base-url", default="")
    p_render_pub.add_argument("--scp-target", default="")
    p_render_pub.add_argument("--tail-commands", type=int, default=24)
    p_render_pub.add_argument("--command", action="append", default=[])
    p_render_pub.add_argument("--theme", default="Catppuccin Mocha")
    p_render_pub.add_argument("--width", type=int, default=1200)
    p_render_pub.add_argument("--height", type=int, default=700)
    p_render_pub.add_argument("--font-size", type=int, default=14)
    p_render_pub.add_argument("--typing-speed-ms", type=int, default=12)
    p_render_pub.add_argument("--sleep-ms", type=int, default=500)
    p_render_pub.add_argument("--dry-run", action="store_true")
    p_render_pub.add_argument("--json", action="store_true")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "probe":
        return probe(as_json=bool(args.json))

    session = str(args.session)
    session_root = Path(str(args.session_root)).expanduser().resolve()
    output_dir = Path(str(args.output_dir)).expanduser().resolve()
    publish_dir: Path | None = None
    public_base_url = ""
    scp_target = ""
    if args.cmd == "render-publish":
        publish_dir = Path(str(args.publish_dir)).expanduser().resolve()
        public_base_url = str(args.public_base_url or "")
        scp_target = str(args.scp_target or "")
    return render(
        session=session,
        session_root=session_root,
        output_dir=output_dir,
        publish_dir=publish_dir,
        public_base_url=public_base_url,
        scp_target=scp_target,
        tail_commands=int(args.tail_commands),
        command=list(args.command or []),
        theme=str(args.theme),
        width=int(args.width),
        height=int(args.height),
        font_size=int(args.font_size),
        typing_speed_ms=int(args.typing_speed_ms),
        sleep_ms=int(args.sleep_ms),
        dry_run=bool(args.dry_run),
        as_json=bool(args.json),
    )


if __name__ == "__main__":
    raise SystemExit(main())
