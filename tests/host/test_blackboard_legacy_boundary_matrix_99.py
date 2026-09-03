"""Boundary matrix for legacy blackboard migration and path confinement.

These tests exercise the parts of the legacy adapter that are difficult to hit
through the happy-path store tests: damaged SQLite files, missing/partial
schemas, unavailable migration runners, raw-copy fallbacks, and path helper
failures.  They stay offline and use temporary SQLite databases only.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3

import pytest

from ida_pro_mcp.host.server import blackboard_legacy as bl

LEGACY_COLUMNS = [
    "id", "category", "title", "content", "addr", "addr_end", "tags",
    "confidence", "created_at", "updated_at", "q_value", "source", "resolved",
    "contradicted", "contradiction_reason", "ioc_type", "evidence", "source_type",
    "version", "kind", "status", "priority", "conflicts_with", "stale",
]


def _legacy_db(path, rows=()):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE blackboard ("
            + ",".join(f'"{column}" TEXT' for column in LEGACY_COLUMNS)
            + ")"
        )
        for row in rows:
            columns = [column for column in LEGACY_COLUMNS if column in row]
            conn.execute(
                "INSERT INTO blackboard ("
                + ",".join(f'"{column}"' for column in columns)
                + ") VALUES ("
                + ",".join("?" for _ in columns)
                + ")",
                [row[column] for column in columns],
            )
    return path


def _row(**overrides):
    row = {
        "id": "boundary-1",
        "category": "general",
        "title": "Boundary finding",
        "content": "content",
        "tags": "[]",
        "confidence": "0.7",
        "created_at": "1",
        "updated_at": "2",
        "q_value": "0.4",
        "source": "test",
        "evidence": "[]",
        "source_type": "test",
        "version": "1",
    }
    row.update(overrides)
    return row


@pytest.fixture(autouse=True)
def _clean_workspace_cache(monkeypatch):
    bl.clear_workspace_cache()
    monkeypatch.delenv(bl.BLACKBOARD_ROOT_ENV, raising=False)


def test_small_helpers_handle_malformed_values_and_binary_read_errors(tmp_path):
    assert bl._json_list(None) == []
    assert bl._json_list([]) == []
    assert bl._json_list("   ") == []
    assert bl._json_list('{"not": "a list"}') == []
    assert bl._json_list("alpha, beta\ngamma") == ["alpha", "beta", "gamma"]
    assert bl._truthy(0) is False
    assert bl._truthy(" YES ") is True
    assert bl._float("not-a-number", 4.5) == 4.5
    assert bl._int("not-an-int", 7) == 7
    assert bl._encode_value(["a"]) == '["a"]'
    assert bl._encode_value({"b": 1}) == '{"b": 1}'
    assert bl._encode_value(True) == 1
    assert bl._meaningful_ioc("unknown") is False
    assert bl._meaningful_ioc("x" * 65) is False
    assert bl.binary_sha256(str(tmp_path)) == ""
    assert bl._binary_cache_key(str(tmp_path / "missing.bin"))[1:] == (0, 0, "")


def test_resolve_falls_back_when_digest_or_workspace_creation_is_unavailable(
    tmp_path, monkeypatch
):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"binary")
    cache = tmp_path / "cache"
    idb = str(tmp_path / "sample.i64")

    monkeypatch.setattr(bl, "binary_sha256", lambda _path: "")
    assert bl.resolve_workspace_path(str(binary), str(cache), idb_path=idb) == idb + ".blackboard.db"

    bl.clear_workspace_cache()
    monkeypatch.setattr(bl, "binary_sha256", lambda _path: hashlib.sha256(b"binary").hexdigest())
    monkeypatch.setattr(bl.os, "makedirs", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read-only")))
    assert bl.resolve_workspace_path(str(binary), str(cache), session_id="session") == str(
        cache / "session.blackboard.db"
    )


def test_legacy_candidate_scan_handles_missing_dirs_sidecars_and_duplicates(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    assert bl._legacy_candidates("digest", str(missing), str(missing)) == []
    assert bl._legacy_candidates("digest", idb_path=str(tmp_path / "missing.i64")) == []

    sidecar = tmp_path / "sample.i64.blackboard.db"
    sidecar.write_bytes(b"not-a-db")
    candidates = bl._legacy_candidates("digest", idb_path=str(tmp_path / "sample.i64"))
    assert candidates == [str(sidecar)]

    directory = tmp_path / "blackboards"
    directory.mkdir()
    name = "sha256-digest-session.db"
    (directory / name).write_bytes(b"x")
    (directory / "unrelated.txt").write_bytes(b"x")
    monkeypatch.setattr(bl, "_blackboards_dirs", lambda *_args: [str(directory), str(directory)])
    found = bl._legacy_candidates("digest", cache_dir="cache", root="root")
    assert found == [str(directory / name)]

    monkeypatch.setattr(bl.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("gone")))
    assert bl._legacy_candidates("digest", cache_dir="cache") == []


def test_workspace_row_probe_distinguishes_missing_empty_and_corrupt_files(tmp_path):
    missing = tmp_path / "missing.db"
    assert bl._workspace_has_rows(str(missing)) is False

    empty = tmp_path / "empty.db"
    with sqlite3.connect(empty) as conn:
        conn.execute("CREATE TABLE blackboard (id TEXT)")
    assert bl._workspace_has_rows(str(empty)) is False

    filled = tmp_path / "filled.db"
    with sqlite3.connect(filled) as conn:
        conn.execute("CREATE TABLE findings (id TEXT)")
        conn.execute("INSERT INTO findings VALUES ('one')")
    assert bl._workspace_has_rows(str(filled)) is True

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_text("not sqlite")
    assert bl._workspace_has_rows(str(corrupt)) is False


def test_table_introspection_and_migration_runner_failure_modes(tmp_path, monkeypatch):
    class _Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

    class _Connection:
        def __init__(self):
            self.calls = 0

        def execute(self, _sql):
            self.calls += 1
            if self.calls == 1:
                return _Cursor([("items",)])
            raise sqlite3.OperationalError("closed")

    fake = _Connection()
    assert bl._list_tables(fake) == {"items"}
    assert bl._table_columns(fake) == {}

    from ida_pro_mcp.host.stores import blackboard_store

    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.host.stores.blackboard_store", None)
    assert bl._init_new_schema(str(tmp_path / "unavailable.db")) is False
    monkeypatch.setitem(
        __import__("sys").modules,
        "ida_pro_mcp.host.stores.blackboard_store",
        blackboard_store,
    )

    monkeypatch.setattr(
        blackboard_store,
        "_migrate",
        lambda _conn: (_ for _ in ()).throw(sqlite3.OperationalError("migration failed")),
    )
    assert bl._init_new_schema(str(tmp_path / "migration-failed.db")) is False

    monkeypatch.setattr(bl.sqlite3, "connect", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        sqlite3.OperationalError("cannot open")
    ))
    assert bl._init_new_schema(str(tmp_path / "broken.db")) is False
    bl._backup_source(str(tmp_path / "missing.db"), str(tmp_path / "target.db"))


def test_merge_same_schema_skips_incompatible_tables_and_bad_databases(tmp_path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE shared (id TEXT, value TEXT)")
        conn.execute("INSERT INTO shared VALUES ('one', 'source')")
        conn.execute("CREATE TABLE source_only (id TEXT)")
    with sqlite3.connect(target) as conn:
        conn.execute("CREATE TABLE shared (id TEXT, other TEXT)")
        conn.execute("CREATE TABLE excluded (id TEXT)")
    bl._merge_same_schema_rows(source, target, exclude=frozenset({"excluded", "shared"}))
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM shared").fetchone()[0] == 0
    bl._merge_same_schema_rows(source, target)
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT id FROM shared").fetchone() == ("one",)

    bl._merge_same_schema_rows(str(tmp_path / "missing-source.db"), str(target))
    bl._merge_same_schema_rows(str(source), str(tmp_path / "missing-target.db"))

    class _Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

    class _Connection:
        def __init__(self, source_conn):
            self.source_conn = source_conn

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql):
            if "sqlite_master" in sql:
                return _Cursor([("shared",)])
            if sql.startswith("PRAGMA"):
                return _Cursor([(0, "id", "TEXT", 0, None, 0)])
            if self.source_conn:
                raise sqlite3.OperationalError("source row became unreadable")
            return _Cursor([])

        def executemany(self, *_args):
            return None

        def commit(self):
            return None

    original_connect = bl.sqlite3.connect

    def _fake_connect(database, *_args, **_kwargs):
        return _Connection(database == str(source))

    try:
        bl.sqlite3.connect = _fake_connect
        bl._merge_same_schema_rows(str(source), str(target))
    finally:
        bl.sqlite3.connect = original_connect

    bl._merge_same_schema_rows(str(source), str(tmp_path))


def test_backup_source_swallows_backup_and_open_failures(tmp_path, monkeypatch):
    source = _legacy_db(tmp_path / "source.db")
    target = tmp_path / "target.db"

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def backup(self, _target):
            raise sqlite3.OperationalError("backup failed")

    monkeypatch.setattr(bl.sqlite3, "connect", lambda *_args, **_kwargs: _Connection())
    bl._backup_source(source, str(target))


def test_merge_legacy_source_uses_raw_copy_when_schema_runner_unavailable(tmp_path, monkeypatch):
    source = _legacy_db(tmp_path / "source.db", [_row(id="raw-copy")])
    target = tmp_path / "target.db"
    calls = []
    monkeypatch.setattr(bl, "_init_new_schema", lambda _path: False)
    monkeypatch.setattr(bl, "_backup_source", lambda source_path, target_path: calls.append((source_path, target_path)))
    bl._merge_legacy_source(source, str(target))
    assert calls == [(source, str(target))]

    current_source = tmp_path / "current.db"
    with sqlite3.connect(current_source) as conn:
        conn.execute("CREATE TABLE findings (id TEXT)")
    second_target = tmp_path / "second-target.db"
    bl._merge_legacy_source(str(current_source), str(second_target))
    assert calls[-1] == (str(current_source), str(second_target))
    bl._merge_legacy_source(str(tmp_path / "none.db"), str(second_target))
    bl._merge_legacy_source(source, str(tmp_path))

    populated_target = tmp_path / "populated-target.db"
    with sqlite3.connect(populated_target) as conn:
        conn.execute("CREATE TABLE findings (id TEXT)")
    bl._merge_legacy_source(str(current_source), str(populated_target))


def test_merge_legacy_source_initializes_an_empty_current_target(tmp_path):
    source = tmp_path / "current-source.db"
    from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

    assert bl._init_new_schema(str(source)) is True
    BlackboardStore(str(source)).write(title="Current row", content="source")
    target = tmp_path / "fresh-target.db"
    bl._merge_legacy_source(str(source), str(target))
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_adoption_reports_no_candidates_and_stat_failures(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace.db"
    assert bl.adopt_legacy_layouts(str(workspace), "digest", str(tmp_path / "cache"))["skipped_reason"] == "no_candidates"

    source = _legacy_db(tmp_path / "cache" / "blackboards" / "sha256-digest-session.db", [_row()])
    monkeypatch.setattr(bl.os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("stat")))
    report = bl.adopt_legacy_layouts(str(workspace), "digest", str(tmp_path / "cache"))
    assert report["skipped_reason"] == "stat_failed"
    assert source


def test_transform_handles_empty_corrupt_and_readonly_fallback_databases(tmp_path, monkeypatch):
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    assert bl.transform_legacy_db(str(empty))["total"] == 0

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_text("not sqlite")
    assert bl.transform_legacy_db(str(corrupt))["total"] == 0

    source = _legacy_db(tmp_path / "source.db", [_row(id="fallback")])
    original_connect = sqlite3.connect
    calls = []

    def _connect(database, *args, **kwargs):
        calls.append(kwargs.get("uri", False))
        if kwargs.get("uri"):
            raise sqlite3.OperationalError("readonly URI unsupported")
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(bl.sqlite3, "connect", _connect)
    transformed = bl.transform_legacy_db(source)
    assert transformed["total"] == 1
    assert calls[:2] == [True, False]


def test_normalize_legacy_row_covers_invalid_defaults_duplicate_ioc_and_rejection_reason():
    row = bl.normalize_legacy_row(
        {
            "id": None,
            "status": "not-valid",
            "kind": "not-valid",
            "category": "general",
            "tags": '["ioc:ip"]',
            "ioc_type": "ip",
            "confidence": "bad",
            "created_at": "bad",
            "updated_at": None,
            "q_value": "bad",
            "priority": "bad",
            "evidence": "not-json",
            "conflicts_with": "not-json",
            "stale": "yes",
            "version": "bad",
        }
    )
    assert row["id"] == ""
    assert row["kind"] == "finding"
    assert row["status"] == "open"
    assert row["tags"] == ["ioc:ip"]
    assert row["confidence"] == 0.5
    assert row["version"] == 1
    assert row["stale"] == 1
    assert "rejected_reason" not in row

    rejected = bl.normalize_legacy_row({"status": "REJECTED", "rejected_reason": "direct"})
    assert rejected["rejected_reason"] == "direct"


def test_insert_helpers_handle_missing_columns_links_and_legacy_aliases(tmp_path):
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE unrelated (value TEXT)")
        assert bl._insert_entries(conn, "unrelated", [{"id": "x"}], {"unrelated": ["value"]}) == 0
        assert bl._insert_conflict_links(conn, [{"id": "x", "conflicts_with": ["y"]}]) == 0

        conn.execute(
            "CREATE TABLE links (entry_a TEXT, entry_b TEXT, type TEXT, reason TEXT, note TEXT, "
            "created_at REAL, updated_at REAL)"
        )
        assert bl._insert_conflict_links(
            conn,
            [
                {"id": "", "conflicts_with": ["other"]},
                {"id": "x", "conflicts_with": "other"},
                {"id": "x", "conflicts_with": ["x", ""]},
            ],
        ) == 0

    target = tmp_path / "legacy-target.db"
    _legacy_db(target)
    source = _legacy_db(tmp_path / "source.db", [_row(id="legacy-target", conflicts_with='["other"]')])
    result = bl.apply_transform(source, str(target))
    assert result["findings"] == 1
    assert result["machinery"] == 0

    machinery_source = _legacy_db(
        tmp_path / "machinery-source.db", [_row(id="legacy-machinery", category="quest_log")]
    )
    machinery_result = bl.apply_transform(machinery_source, str(target))
    assert machinery_result["machinery"] == 1


def test_apply_transform_handles_empty_targets_legacy_machinery_and_sqlite_errors(tmp_path):
    source = _legacy_db(
        tmp_path / "source.db",
        [_row(id="finding"), _row(id="machinery", category="quest_log")],
    )
    empty_target = tmp_path / "empty-target.db"
    sqlite3.connect(empty_target).close()
    result = bl.apply_transform(source, str(empty_target))
    assert result["written"] == 0

    bad_target = tmp_path / "bad-target.db"
    bad_target.mkdir()
    error = bl.apply_transform(source, str(bad_target))
    assert error["error"] is True

    current_target = tmp_path / "current-target.db"
    assert bl._init_new_schema(str(current_target)) is True
    machinery_only = _legacy_db(
        tmp_path / "machinery-only.db", [_row(id="machinery-only", category="quest_log")]
    )
    machinery_result = bl.apply_transform(machinery_only, str(current_target))
    assert machinery_result["findings"] == 0
    assert machinery_result["machinery"] == 1


def test_path_helpers_cover_invalid_roots_cross_device_and_canonical_escape(tmp_path, monkeypatch):
    root = str(tmp_path / "root")
    os.makedirs(root)
    assert bl.path_has_symlink("", root) is True
    assert bl.path_has_symlink(root, "") is True
    assert bl.path_has_symlink(str(tmp_path / "outside"), root) is True

    original_relpath = bl.os.path.relpath
    monkeypatch.setattr(bl.os.path, "relpath", lambda *_args: (_ for _ in ()).throw(ValueError("different drives")))
    assert bl._path_escapes("a", "b") is True
    assert bl.path_has_symlink("a", "b") is True
    monkeypatch.setattr(bl.os.path, "relpath", original_relpath)
    monkeypatch.setattr(bl.os.path, "relpath", lambda *_args: "child//file")
    assert bl.path_has_symlink(os.path.join(root, "child", "file"), root) is False
    monkeypatch.setattr(bl.os.path, "relpath", original_relpath)

    monkeypatch.setattr(bl.os.path, "realpath", lambda *_args: (_ for _ in ()).throw(OSError("bad path")))
    assert bl.workspace_root(env="~/root") is None
    assert bl.workspace_root(idb_path="/tmp/a.i64") is None
    assert bl.confine_path("file", root)[1] == "blackboard file action: invalid path"

    monkeypatch.setattr(bl.os.path, "realpath", lambda _path: "/outside")
    _, error = bl.confine_path("file", root)
    assert error == "blackboard file action: path escapes allowed root"
