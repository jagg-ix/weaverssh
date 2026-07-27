from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = REPO_ROOT / "docs" / "debug" / "weaverssh_debug_kb.sqlite3"
REGISTRY_PATH = REPO_ROOT / "docs" / "debug" / "weaverssh_error_registry.json"
RESOURCE_REGISTRY_PATH = REPO_ROOT / "python" / "weaverssh_support" / "resources" / "weaverssh_error_registry.json"
EXPORTER = REPO_ROOT / "tools" / "verification" / "export_weaverssh_error_registry.py"


def _db_codes() -> dict[str, sqlite3.Row]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    with conn:
        rows = conn.execute("SELECT code, subsystem, severity, title FROM error_codes ORDER BY code").fetchall()
    return {str(row["code"]): row for row in rows}


def _registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_registry_json_matches_sqlite_debug_kb() -> None:
    db_codes = _db_codes()
    registry = _registry()
    registry_codes = {item["code"]: item for item in registry["codes"]}

    assert registry["version"] == "weaverssh.error_registry.v1"
    assert set(registry_codes) == set(db_codes)
    for code, row in db_codes.items():
        item = registry_codes[code]
        assert item["subsystem"] == row["subsystem"]
        assert item["severity"] == row["severity"]
        assert item["title"] == row["title"]
        assert item["kind"] in {"error", "fault"}
        assert isinstance(item["retryable"], bool)
        assert code in registry["components"][row["subsystem"]]


def test_python_error_module_uses_packaged_registry() -> None:
    sys.path.insert(0, str(REPO_ROOT / "python"))
    from weaverssh_support.errors import WeaversshError, code_of, known_code, to_event

    err = WeaversshError(
        code="WV-SSH-001",
        component="ssh",
        operation="connect",
        message="remote login failed",
    ).with_field("host", "203.0.113.10")

    event = to_event(err)
    assert known_code("WV-SSH-001")
    assert code_of(err) == "WV-SSH-001"
    assert event["subsystem"] == "ssh"
    assert event["retryable"] is True
    assert event["fields"]["host"] == "203.0.113.10"


def test_exporter_rebuilds_docs_and_package_resource(tmp_path: Path) -> None:
    docs_out = tmp_path / "registry.json"
    resource_out = tmp_path / "resource.json"
    subprocess.run(
        [
            sys.executable,
            str(EXPORTER),
            "--db",
            str(DB_PATH),
            "--output",
            str(docs_out),
            "--package-resource",
            str(resource_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    docs_data = json.loads(docs_out.read_text(encoding="utf-8"))
    resource_data = json.loads(resource_out.read_text(encoding="utf-8"))
    assert docs_data == resource_data
    assert {item["code"] for item in docs_data["codes"]} == set(_db_codes())


def test_packaged_registry_copy_exists() -> None:
    assert REGISTRY_PATH.exists()
    assert RESOURCE_REGISTRY_PATH.exists()
    assert json.loads(REGISTRY_PATH.read_text(encoding="utf-8")) == json.loads(
        RESOURCE_REGISTRY_PATH.read_text(encoding="utf-8")
    )
