"""Exercise durable session and bookmark behavior across persistence modes."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import BookmarkManager, Session, SessionManager


def _session(manager: SessionManager, sid: str = "ABCD1234", *, binary: str = "") -> Session:
    value = Session(
        sid,
        str(manager.session_dir / f"SID_{sid}" / f"SID_{sid}_sample.i64"),
        binary,
        tags=["analysis"],
        notes="initial note",
        auto_name="Sample",
    )
    manager.sessions[sid] = value
    manager._save_metadata(value)
    return value


def test_session_value_shapes_and_idb_detection(tmp_path):
    binary = tmp_path / "firmware"
    binary.write_bytes(b"bin")
    session = Session("ABCD1234", "", str(binary))
    assert session.auto_name == "firmware"
    assert session.idb_on_disk() is False

    (tmp_path / "firmware.i64").write_text("idb", encoding="utf-8")
    assert session.idb_on_disk() is True
    data = session.to_dict()
    assert data["binary_exists"] is True
    assert data["idb_exists"] is True
    assert Session.from_dict({"session_id": "ABCD1234", "idb_path": None}).idb_path == ""
    assert Session("ABCD1234", str(tmp_path / "SID_ABCD1234_x.i64"), "").auto_name == "x"
    assert Session("ABCD1234", str(tmp_path / "SID_ABCD1234_x.i64"), "").idb_path_basename() == "SID_ABCD1234_x.i64"
    with pytest.raises(ValueError):
        Session.from_dict({"session_id": "bad/id", "idb_path": ""})
    with pytest.raises(ValueError):
        Session.from_dict({"session_id": "ABCD1234", "idb_path": 3})

    component = Session("ABCD1234", str(tmp_path / "SID_ABCD1234_x.i64"), "")
    (tmp_path / "SID_ABCD1234_x.id0").write_text("legacy", encoding="utf-8")
    assert component.idb_on_disk() is True


def test_session_manager_crud_discovery_and_filters(tmp_path):
    manager = SessionManager(str(tmp_path))
    assert manager.get_stats()["total"] == 0
    assert manager._sanitize_tags([None, "", " x ", "x", "a" * 200]) == ["x", "a" * 64]
    assert manager._sanitize_note(None) == ""
    assert manager._sanitize_name(None) == ""
    assert manager.get_session_artifact_dir("ABCD1234", create=False).endswith("SID_ABCD1234")
    assert manager.get_session_log_dir("ABCD1234").endswith(os.path.join("SID_ABCD1234", "logs"))

    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"demo")
    idb_dir = tmp_path / "idbs"
    idb_dir.mkdir()
    first = manager.create_session(
        str(binary),
        idb_path=str(idb_dir),
        tags=["one", "one", " two "],
        notes="hello",
        packed_idb=True,
        policy_mode="strict",
    )
    assert first.idb_path.startswith(str(idb_dir))
    assert first.idb_path.endswith(".i64")
    second = manager.create_session(str(binary), idb_path=str(tmp_path / "explicit"))
    assert second.idb_path.endswith(".i64")
    assert manager.count() == 2
    assert manager.get_session(first.session_id).session_id == first.session_id
    assert manager.find_session_by_path(str(binary)).session_id == first.session_id
    assert len(manager.find_sessions_by_path(str(binary))) == 2
    assert manager.find_session_by_path(str(tmp_path / "nope")) is None

    updated = manager.update_session(
        first.session_id,
        tags="new-tag",
        notes="updated",
        auto_name="  Display  ",
        analysis_gate=" COMPLETE ",
        unknown="ignored",
        session_id="cannot-change",
    )
    assert updated.tags == ["new-tag"]
    assert updated.notes == "updated"
    assert updated.auto_name == "Display"
    assert updated.analysis_gate == "complete"
    assert manager.rename_session(first.session_id, "Renamed").auto_name == "Renamed"
    assert manager.update_session("MISSING1", name="x") is None
    assert manager.duplicate_session("MISSING1") is None
    duplicate = manager.duplicate_session(first.session_id)
    assert duplicate.session_id != first.session_id
    assert duplicate.analysis_applied is False
    assert duplicate.idb_path != first.idb_path

    assert manager.discover_sessions(binary_name="DEMO")
    assert manager.discover_sessions(query="new-tag")[0].session_id == first.session_id
    listing = manager.list_sessions(binary_name="demo", query="renamed", offset=0, limit=1)
    assert listing["count"] == 1
    assert listing["total"] == 2
    assert manager.list_sessions(offset=99)["sessions"] == []
    assert manager.set_binary_path(first.session_id, str(tmp_path / "new.bin")).binary_path.endswith("new.bin")
    assert manager.set_idb_path(first.session_id, str(tmp_path / "new.i64")).idb_path.endswith("new.i64")

    assert manager.tag_session(first.session_id, "keep").tags[-1] == "keep"
    assert manager.untag_session(first.session_id, "keep").tags == ["new-tag"]
    assert manager.tag_session("MISSING1", "x") is None
    manager.add_note(first.session_id, "second")
    assert "second" in manager.search_notes("SECOND")[0].notes
    manager.clear_notes(first.session_id)
    assert manager.search_notes("second") == []
    assert manager.get_session_age(first.session_id) >= timedelta(0)
    assert manager.get_session_idle_time(first.session_id) >= timedelta(0)
    assert manager.get_session_age("MISSING1") is None


def test_metadata_migration_orphan_recovery_and_deletion(tmp_path):
    cache = tmp_path / "cache"
    sessions = cache / "sessions"
    sessions.mkdir(parents=True)
    sid = "ABCD5678"
    legacy_idb = sessions / f"SID_{sid}_demo.i64"
    legacy_idb.write_text("idb", encoding="utf-8")
    (sessions / f"SID_{sid}_metadata.json").write_text(
        json.dumps(
            {
                "session_id": sid,
                "idb_path": str(legacy_idb),
                "binary_path": "/samples/demo.bin",
                "tags": ["legacy"],
            }
        ),
        encoding="utf-8",
    )
    (sessions / f"SID_{sid}_bookmarks.json").write_text("[]", encoding="utf-8")
    (cache / f"ida_mcp_{sid}.log").write_text("log", encoding="utf-8")
    (cache / f"ida_rpc_{sid}_123.port").write_text("123", encoding="utf-8")

    orphan_sid = "EFGH5678"
    (sessions / f"SID_{orphan_sid}_orphan.idb").write_text("orphan", encoding="utf-8")
    manager = SessionManager(str(cache))
    assert manager.get_session(sid).idb_path.endswith("SID_ABCD5678_demo.i64")
    assert (sessions / f"SID_{sid}" / "metadata.json").exists()
    assert (sessions / f"SID_{sid}" / "logs" / "ida_mcp.log").exists()
    assert manager.get_session(orphan_sid).binary_path == "orphan"
    assert manager._extract_sid("SID_ABCD5678_any.i64") == sid
    assert manager._extract_sid("other.i64") is None
    assert manager._guess_binary_name(sid, f"SID_{sid}_demo.i64") == "demo"
    assert manager._guess_binary_name(sid, "unrelated.i64") == ""

    (cache / f"{sid}.blackboard.db").write_text("db", encoding="utf-8")
    (cache / "runtime_leases").mkdir()
    (cache / "runtime_leases" / f"SID_{sid}.lease.json").write_text("lease", encoding="utf-8")
    (cache / "runtime_leases" / f"SID_{sid}.owner.json").write_text("owner", encoding="utf-8")
    assert manager.delete_session(sid) is True
    assert manager.get_session(sid) is None
    assert not (cache / "runtime_leases" / f"SID_{sid}.owner.json").exists()
    assert manager.delete_session("bad/id") is False
    assert manager.delete_session("MISSING1") is False


def test_session_export_import_pruning_validation_and_snapshots(tmp_path):
    manager = SessionManager(str(tmp_path))
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"app")
    session = manager.create_session(str(binary), notes="before", tags=["active"])
    session_id = session.session_id
    manager._save_skills(
        session_id,
        {
            "skills": {"s1": {"q_value": 0.9}},
            "activity_log": [{"action": "one"}],
            "hypotheses": [{"id": "h", "confidence": "0.9"}, {"id": "bad", "confidence": "x"}],
        },
    )
    manager._save_notebook(session_id, "# Notes\nold")
    exported = manager.export_session(session_id)
    assert exported["_skills"]["s1"]["q_value"] == 0.9
    assert manager.export_session(session_id, include_skills=False).get("_skills") is None
    assert manager.export_session("MISSING1") is None
    # Invalid thresholds fall back to the documented 0.8 default.
    assert len(manager.get_high_confidence_hypotheses(session_id, "bad")) == 1
    assert len(manager.get_high_confidence_hypotheses(session_id, 0.8)) == 1
    assert manager.get_high_confidence_hypotheses("MISSING1") == []

    imported = manager.import_session(exported)
    assert imported.session_id != session_id
    assert imported.idb_path != exported["idb_path"]
    assert manager._load_skills(imported.session_id)["skills"]["s1"]["q_value"] == 0.9
    empty_import = manager.import_session({"binary_path": "", "analysis_options": {}})
    assert empty_import.idb_path.endswith(".i64")

    snapshot = manager.snapshot_session(session_id, "checkpoint")
    assert snapshot["ok"] is True
    manager.update_session(session_id, notes="after", tags=["changed"])
    restored = manager.restore_snapshot(session_id, snapshot["snapshot_id"])
    assert restored.notes == "before"
    assert restored.tags == ["active"]
    assert restored.binary_path == str(binary)
    assert manager.restore_snapshot(session_id, "missing") is None
    assert manager.list_snapshots(session_id)["snapshots"][0]["_message"] == "checkpoint"
    assert manager.snapshot_session("MISSING1") is None
    (tmp_path / "sessions" / f"SID_{session_id}" / "snapshots.json").write_text("bad", encoding="utf-8")
    assert manager._load_snapshots(session_id) == []

    hyp = manager.track_hypothesis(session_id, "loader", ["x"], ["y"], 0.7)
    hid = hyp["hypothesis_id"]
    assert manager.confirm_hypothesis(session_id, hid, ["z"])["hypothesis"]["status"] == "confirmed"
    ref = manager.track_hypothesis(session_id, "other")
    assert manager.refute_hypothesis(session_id, ref["hypothesis_id"], "reason")["hypothesis"]["status"] == "refuted"
    assert manager.confirm_hypothesis(session_id, "missing")["code"] == MCPError.NOT_FOUND
    assert manager.track_hypothesis("MISSING1", "x")["code"] == MCPError.SESSION_NOT_FOUND

    invalid = manager.validate_session(session_id)
    assert invalid["valid"] is False
    assert any("IDB not found" in issue for issue in invalid["issues"])
    assert manager.validate_session("MISSING1") is None

    old = manager.create_session("/gone/old.bin")
    old.last_accessed = datetime.now() - timedelta(days=40)
    manager._save_metadata(old)
    live = manager.create_session("/gone/live.bin")
    live.last_accessed = datetime.now() - timedelta(days=40)
    manager._save_metadata(live)
    assert old.session_id in manager.cleanup_stale(30, runtime_alive=lambda sid: sid == live.session_id)
    assert live.session_id in manager.sessions
    assert manager.auto_prune_if_over_budget("bad", 30) == 0
    assert manager.auto_prune_if_over_budget(0, 30) == 0


def test_session_prune_stats_and_merge_modes(tmp_path):
    manager = SessionManager(str(tmp_path))
    first = manager.create_session("/bin/first", tags=["one"], notes="one")
    second = manager.create_session("/bin/second", tags=["two"], notes="two")
    manager._save_skills(first.session_id, {"skills": {}, "activity_log": [], "hypotheses": []})
    manager._save_skills(
        second.session_id,
        {"skills": {}, "activity_log": [{"action": "second"}], "hypotheses": [{"id": "h"}]},
    )
    assert manager.merge_sessions("MISSING1", second.session_id) is None
    merged = manager.merge_sessions(first.session_id, second.session_id)
    assert "two" in merged.tags
    assert "two" in merged.notes
    merged_data = manager._load_skills(first.session_id)
    assert merged_data["hypotheses"] == [{"id": "h"}]
    assert manager.bulk_tag([first.session_id, "MISSING1"], " merged ") == {first.session_id: True, "MISSING1": False}
    assert manager.bulk_tag([first.session_id], "   ") == {first.session_id: False}
    assert manager.bulk_delete(["MISSING1"]) == {"MISSING1": False}

    assert manager.archive_session(first.session_id).tags[-1] == "archived"
    manager.archive_session(first.session_id)
    assert len(manager.list_archived()) == 1
    assert len(manager.list_active()) == 1
    assert manager.unarchive_session(first.session_id).tags == ["one", "two", "merged"]
    assert manager.find_by_tag("merged")[0].session_id == first.session_id
    assert manager.get_recent(1)
    assert manager.get_oldest(1)
    stats = manager.get_stats()
    assert stats["total"] == 2
    assert stats["phases"]["triage"] == 2
    assert manager.bulk_delete([first.session_id, "MISSING1"])[first.session_id] is True


def test_bookmark_manager_persistence_filters_and_errors(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/bin/bookmark")
    bookmarks = BookmarkManager(manager.session_dir)
    sid = session.session_id
    assert bookmarks.add(sid, {})["code"] == MCPError.INVALID_ARGS
    first = bookmarks.add(
        sid,
        {"addr": "0x1000", "name": "Entry", "notes": "root", "category": "code", "tags": "root, important", "priority": "bad"},
    )
    assert first["bookmark"]["priority"] == 3
    assert first["bookmark"]["tags"] == ["root", "important"]
    updated = bookmarks.add(sid, {"addr": "0x1000", "notes": "revised", "tags": 7, "priority": 1})
    assert updated["updated"] is True
    assert updated["bookmark"]["id"] == 1
    second = bookmarks.add(sid, {"addr": "0x2000", "name": "Callsite", "tags": ["xref"], "priority": 5})
    assert second["bookmark"]["id"] == 2
    assert bookmarks.list(sid, {"category": "general", "query": "revised"})["count"] == 1
    assert bookmarks.list(sid, {"tag": "xref"})["count"] == 1
    assert bookmarks.list(sid, {"priority": "not-int"})["count"] == 2
    assert bookmarks.list(sid, {"query": "revised"})["count"] == 1
    assert bookmarks.find(sid, "xref")["count"] == 1
    assert bookmarks.find(sid, "0x2000")["count"] == 1
    assert bookmarks.update(sid, {})["code"] == MCPError.INVALID_ARGS
    assert bookmarks.update(sid, {"id": "bad"})["code"] == MCPError.INVALID_ARGS
    assert bookmarks.update(sid, {"id": 1, "tags": 9, "priority": "bad", "name": "Root"})["ok"] is True
    assert bookmarks.update(sid, {"id": 99})["code"] == MCPError.BOOKMARK_NOT_FOUND
    assert bookmarks.delete(sid, {})["code"] == MCPError.INVALID_ARGS
    assert bookmarks.delete(sid, {"id": "bad"})["code"] == MCPError.INVALID_ARGS
    assert bookmarks.delete(sid, {"addr": "0x2000"})["deleted"] == 1
    assert bookmarks.delete(sid, {"id": 1})["deleted"] == 1
    assert bookmarks.delete(sid, {"id": 1})["code"] == MCPError.BOOKMARK_NOT_FOUND
    assert bookmarks.export(sid)["report"] == "No bookmarks found."
    assert bookmarks.clear(sid)["ok"] is True
    assert bookmarks.load("MISSING1") == []
    legacy = tmp_path / "sessions" / "SID_MISSING1_bookmarks.json"
    legacy.write_text("[{\"id\": 1, \"addr\": \"0x1\"}]", encoding="utf-8")
    assert bookmarks.load("MISSING1")[0]["addr"] == "0x1"
    legacy.write_text("not-json", encoding="utf-8")
    assert bookmarks.load("MISSING1") == []
