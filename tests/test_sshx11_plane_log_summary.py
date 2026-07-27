from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_log_summary_script_outputs_json(tmp_path: Path) -> None:
    control = tmp_path / "control.ndjson"
    data = tmp_path / "data.ndjson"
    state = tmp_path / "state.json"
    output = tmp_path / "summary.json"

    control.write_text(
        "\n".join(
            [
                json.dumps({"event": "service_start"}),
                json.dumps({"event": "command_applied"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    data.write_text(
        "\n".join(
            [
                json.dumps({"event": "service_start"}),
                json.dumps({"event": "packet_relayed"}),
                json.dumps({"event": "packet_relayed"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    state.write_text(json.dumps({"relay_enabled": True}) + "\n", encoding="utf-8")

    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "verification" / "sshx11_plane_log_summary.py"),
        "--control-log",
        str(control),
        "--data-log",
        str(data),
        "--state-file",
        str(state),
        "--output",
        str(output),
    ]
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["control_event_count"] == 2
    assert payload["data_event_count"] == 3
    assert payload["data_events"]["packet_relayed"] == 2
