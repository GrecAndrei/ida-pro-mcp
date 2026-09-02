"""Composed coverage for legacy blackboard migration and path safety."""

from __future__ import annotations

import hashlib
import sqlite3

from ida_pro_mcp.host.server import blackboard_legacy as legacy


def test_legacy_value_helpers_identity_and_path_confinement(tmp_path, monkeypatch):
    assert legacy._truthy(None) is False
    assert legacy._truthy(" yes ") is True
    assert legacy._truthy("no") is False
    assert legacy._float("bad", 1.5) == 1.5
    assert legacy._int(None, 7) == 7
    assert legacy._json_list(None) == []
    assert legacy._json_list('["a", "b"]') == ["a", "b"]
    assert legacy._json_list("a, b\nc") == ["a", "b", "c"]
    assert legacy._json_list("{}") == []
    assert legacy._encode_value(["b", "a"]) == '["b", "a"]'
    assert legacy._encode_value(True) == 1

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"binary")
    assert legacy.binary_sha256(str(binary)) == hashlib.sha256(b"binary").hexdigest()
    assert legacy.binary_sha256(str(tmp_path / "missing")) == ""
    assert legacy._workspace_base(str(tmp_path)) == str(tmp_path.resolve())
    assert legacy._binary_cache_key(str(binary), str(tmp_path))[0] == str(binary.resolve())

    root = tmp_path / "root"
    root.mkdir()
    assert legacy.confine_path("notes.db", str(root))[0] == str((root / "notes.db").resolve())
    assert legacy.confine_path("", str(root))[1] == "path required"
    assert legacy.confine_path("../escape", str(root))[1]
    assert legacy.confine_path("notes.db", None)[1]
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    assert legacy.path_has_symlink(str(root / "link" / "db"), str(root)) is True
    assert legacy.confine_path("link/db", str(root))[1]

    monkeypatch.setenv(legacy.BLACKBOARD_ROOT_ENV, str(root))
    assert legacy.workspace_root(str(tmp_path), "/some/idb.i64") == str(root.resolve())
    monkeypatch.delenv(legacy.BLACKBOARD_ROOT_ENV)
    assert legacy.workspace_root(str(tmp_path), str(tmp_path / "idb.i64")) == str(tmp_path.resolve())
    assert legacy.workspace_root() is None


def test_normalize_and_transform_legacy_rows_preserve_status_ioc_and_machinery(tmp_path):
    normalized = legacy.normalize_legacy_row(
        {
            "id": "finding-1", "kind": "not-a-kind", "status": "rejected",
            "category": "general", "title": " title ", "content": "body",
            "tags": "[\"manual\"]", "ioc_type": "domain",
            "contradiction_reason": "wrong", "resolved": 0, "contradicted": 1,
            "stale": "yes", "confidence": "bad", "version": "3",
            "vector": "drop-me",
        }
    )
    assert normalized["kind"] == "finding"
    assert normalized["status"] == "rejected"
    assert normalized["category"] == "ioc"
    assert "ioc:domain" in normalized["tags"]
    assert normalized["rejected_reason"] == "wrong"
    assert normalized["confidence"] == 0.5
    assert normalized["stale"] == 1
    assert "vector" not in normalized

    source = tmp_path / "legacy.db"
    with sqlite3.connect(source) as conn:
        conn.execute(
            "CREATE TABLE blackboard (id TEXT PRIMARY KEY, kind TEXT, status TEXT, category TEXT, "
            "title TEXT, content TEXT, addr TEXT, addr_end TEXT, tags TEXT, confidence REAL, "
            "created_at REAL, updated_at REAL, ioc_type TEXT, contradiction_reason TEXT, "
            "resolved INTEGER, contradicted INTEGER, conflicts_with TEXT, evidence TEXT)"
        )
        conn.executemany(
            "INSERT INTO blackboard VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("finding-1", "finding", "", "general", "IOC", "body", "0x1000", "", "[]", 0.9, 1, 2, "ip", "", 0, 0, '["finding-2"]', '["e1"]'),
                ("mach-1", "task", "", "quest_log", "Task", "do it", "", "", "", 0.5, 1, 2, "", "", 0, 0, "", ""),
            ],
        )
        conn.commit()
    transformed = legacy.transform_legacy_db(str(source))
    assert transformed["total"] == 2
    assert transformed["findings"][0]["category"] == "ioc"
    assert transformed["machinery"][0]["category"] == "quest_log"
    assert legacy.transform_legacy_db(str(tmp_path / "missing"))["total"] == 0


def test_apply_transform_current_schema_is_idempotent_and_recreates_links(tmp_path):
    source = tmp_path / "legacy.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE blackboard (id TEXT PRIMARY KEY, category TEXT, title TEXT, content TEXT, conflicts_with TEXT)")
        conn.execute("INSERT INTO blackboard VALUES ('a', 'general', 'A', 'body', '[\"b\"]')")
        conn.commit()
    target = tmp_path / "current.db"
    with sqlite3.connect(target) as conn:
        conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY, category TEXT, title TEXT, content TEXT)")
        conn.execute("CREATE TABLE links (entry_a TEXT, entry_b TEXT, type TEXT, reason TEXT, note TEXT, created_at REAL, updated_at REAL, UNIQUE(entry_a, entry_b, type))")
        conn.execute("CREATE TABLE bb_machinery (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
        conn.commit()
    first = legacy.apply_transform(str(source), str(target))
    second = legacy.apply_transform(str(source), str(target))
    assert first["written"] == 1
    assert second["written"] == 0
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM links").fetchone()[0] == 1
    assert legacy.apply_transform(str(tmp_path / "missing"), str(target))["written"] == 0


def test_legacy_workspace_resolution_and_adoption_paths(tmp_path, monkeypatch):
    legacy.clear_workspace_cache()
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    cache = tmp_path / "cache"
    cache.mkdir()
    path = legacy.resolve_workspace_path(str(binary), str(cache), session_id="s1")
    assert path.endswith(".db") and str(cache / "blackboards") in path
    assert legacy.resolve_workspace_path("", str(cache), idb_path="/tmp/idb.i64").endswith("idb.i64.blackboard.db")
    assert legacy.resolve_workspace_path("", str(cache), session_id="s1").endswith("s1.blackboard.db")
    assert legacy.resolve_workspace_path() == ""

    workspace = tmp_path / "empty.db"
    source = tmp_path / "blackboards"
    source.mkdir()
    (source / "sha256-dead-session.db").touch()
    monkeypatch.setattr(legacy.os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("mtime")))
    assert legacy.adopt_legacy_layouts(str(workspace), "dead", str(tmp_path))["skipped_reason"] == "stat_failed"
    monkeypatch.setattr(legacy, "_legacy_candidates", lambda *_args: [])
    assert legacy.adopt_legacy_layouts(str(workspace), "dead", str(tmp_path))["skipped_reason"] == "no_candidates"
