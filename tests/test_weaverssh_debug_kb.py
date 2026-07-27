from __future__ import annotations

import sqlite3
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = REPO_ROOT / "docs" / "debug" / "weaverssh_debug_kb.sql"
DB_PATH = REPO_ROOT / "docs" / "debug" / "weaverssh_debug_kb.sqlite3"


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def test_debug_kb_database_exists_and_has_expected_seed_counts() -> None:
    assert SQL_PATH.exists()
    assert DB_PATH.exists()
    with connect(DB_PATH) as conn:
        assert conn.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] == "weaverssh.debug_kb.v1"
        assert conn.execute("SELECT count(*) FROM error_codes").fetchone()[0] >= 20
        assert conn.execute("SELECT count(*) FROM kb_articles").fetchone()[0] >= 10
        assert conn.execute("SELECT count(*) FROM error_kb_links").fetchone()[0] >= 20


def test_debug_kb_sql_seed_rebuilds_cleanly(tmp_path: Path) -> None:
    rebuilt = tmp_path / "rebuilt.sqlite3"
    with connect(rebuilt) as conn:
        conn.executescript(SQL_PATH.read_text(encoding="utf-8"))
        row = conn.execute(
            "SELECT code, title, kb_slugs FROM debug_error_lookup WHERE code='WV-X11-002'"
        ).fetchone()
        assert row is not None
        assert row["title"] == "XAUTHORITY cookie missing or mismatched"
        assert "x11-display-authority" in row["kb_slugs"]


def test_debug_kb_has_adapter_and_packaging_guidance() -> None:
    with connect(DB_PATH) as conn:
        adapter = conn.execute(
            "SELECT operator_action, developer_action FROM debug_error_lookup WHERE code='WV-ADP-001'"
        ).fetchone()
        assert adapter is not None
        assert "adapter" in adapter["operator_action"].lower()
        assert "guard" in adapter["developer_action"].lower()

        snap = conn.execute(
            "SELECT operator_action FROM debug_error_lookup WHERE code='WV-PKG-003'"
        ).fetchone()
        assert snap is not None
        assert "snapcraft" in snap["operator_action"].lower()
