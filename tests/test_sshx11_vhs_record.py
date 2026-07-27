from __future__ import annotations

from pathlib import Path
import json
import subprocess
import uuid


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_vhs_record.py"


def test_sshx11_vhs_record_help() -> None:
    proc = subprocess.run(["python3", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "render-publish" in proc.stdout


def test_sshx11_vhs_record_probe_json() -> None:
    proc = subprocess.run(["python3", str(SCRIPT), "probe", "--json"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert "tools" in payload
    assert "vhs" in payload["tools"]


def test_sshx11_vhs_record_render_publish_dry_run(tmp_path: Path) -> None:
    session = f"collab-{uuid.uuid4().hex[:8]}"
    session_root = tmp_path / "sessions"
    sdir = session_root / session
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "session.json").write_text(
        json.dumps({"session": session, "resolved_shell": "/bin/bash", "backend": "fifo"}) + "\n",
        encoding="utf-8",
    )
    ndjson = [
        json.dumps({"kind": "session_start", "session": session}),
        json.dumps({"kind": "input", "session": session, "text": "echo HELLO"}),
        json.dumps({"kind": "input", "session": session, "text": "pwd"}),
    ]
    (sdir / "commands.ndjson").write_text("\n".join(ndjson) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    pub_dir = tmp_path / "pub"
    proc = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "render-publish",
            "--session",
            session,
            "--session-root",
            str(session_root),
            "--output-dir",
            str(out_dir),
            "--publish-dir",
            str(pub_dir),
            "--dry-run",
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["dry_run"] is True
    assert Path(payload["tape_path"]).exists()
    assert Path(payload["artifact_path"]).exists()
