from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_contract_and_registry() -> None:
    adapter = read("storageadapter/adapter.go")
    registry = read("storageadapter/registry.go")
    wrappers = read("storageadapter/wrappers.go")
    migrate = read("storageadapter/migrate.go")

    for symbol in (
        "type Store interface",
        "type Tx interface",
        "CompareAndSwap",
        "ScanOptions",
        "Capabilities",
    ):
        assert symbol in adapter
    assert 'Register("memory"' in registry
    assert 'Register("file"' in registry
    assert "namespaceStore" in wrappers
    assert "boundedStore" in wrappers
    assert "func Migrate" in migrate


def test_optional_database_providers() -> None:
    sqlite = read("storageplugins/sqlite/provider.go")
    rocksdb = read("storageplugins/rocksdb/provider.go")
    sqlite_import = read("cmd/wv/storage_provider_sqlite.go")
    rocks_import = read("cmd/wv/storage_provider_rocksdb.go")

    assert "//go:build sqlite && cgo" in sqlite
    assert '#cgo pkg-config: sqlite3' in sqlite
    assert 'storageadapter.Register("sqlite"' in sqlite
    assert "BEGIN IMMEDIATE" in sqlite
    assert "journal_mode=WAL" in sqlite
    assert "//go:build rocksdb && cgo" in rocksdb
    assert '#cgo pkg-config: rocksdb' in rocksdb
    assert 'storageadapter.Register("rocksdb"' in rocksdb
    assert "rocksdb_create_iterator" in rocksdb
    assert "-tags sqlite" not in read("tools/verification/build_go123.sh")
    assert "storageplugins/sqlite" in sqlite_import
    assert "storageplugins/rocksdb" in rocks_import


def test_file_core_and_commands_use_adapter() -> None:
    bridge = read("filebackend/storage_adapter.go")
    app = read("internal/app/file_backend.go")
    command = read("cmd/wv/storage.go")
    main = read("cmd/wv/main.go")
    catalog = read("cmd/wv/command_catalog_complete.go")

    assert "OpenAdapterStore" in bridge
    assert "WEAVERSSH_FILE_CORE_CONFIG" in app
    assert "storageadapter.LoadConfigFile" in app
    assert 'case "storage", "storage-adapter"' in main
    assert '"storage"' in catalog
    for operation in ("engines", "validate", "status", "get", "put", "delete", "scan", "migrate"):
        assert f'case "{operation}"' in command or operation in command


def test_examples_and_build_targets() -> None:
    for name, engine in (
        ("memory.json", "memory"),
        ("file.json", "file"),
        ("sqlite.json", "sqlite"),
        ("rocksdb.json", "rocksdb"),
    ):
        payload = json.loads(read(f"docs/examples/storage/{name}"))
        assert payload["version"] == "weaverssh.storage.v1"
        assert payload["engine"] == engine

    make = read("mk/storage-adapter.mk")
    gnu = read("GNUmakefile")
    gate = read("tools/verification/build_go123.sh")
    docs = read("docs/architecture/storage-adapter-infrastructure.md")

    assert "include mk/storage-adapter.mk" in gnu
    for target in (
        "storage-adapter-focused-test",
        "storage-adapter-race-test",
        "storage-sqlite-test",
        "storage-rocksdb-test",
    ):
        assert f"{target}:" in make
    assert "./storageadapter" in gate
    for phrase in (
        "additional engines",
        "WEAVERSSH_FILE_CORE_CONFIG",
        "SQLite",
        "RocksDB",
        "migrate",
    ):
        assert phrase.lower() in docs.lower()
