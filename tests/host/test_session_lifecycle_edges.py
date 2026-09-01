"""Offline lifecycle coverage for the persistent session workspace."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import BookmarkManager, Session, SessionManager


def test_session_name_derivation_and_idb_artifact_detection(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"binary")
    session = Session("ABC12345", str(tmp_path / "missing.i64"), str(source))
    assert session.auto_name == "sample.bin"
    assert session.idb_path_basename() == "missing.i64"
    assert session.idb_on_disk() is False

    source.with_name("sample.bin.i64").write_bytes(b"idb")
    assert session.idb_on_disk() is True

    legacy = tmp_path / "SID_ABC12345_sample.id0"
    legacy.write_bytes(b"id0")
    missing_idb = Session("ABC12345", str(tmp_path / "other.i64"), "")
    assert missing_idb.idb_on_disk() is True


def test_session_from_dict_rejects_invalid_identity_and_normalizes_gate():
    for value in (None, "bad", "../../etc", "A" * 100):
        try:
            Session.from_dict({"session_id": value})
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid session id accepted: {value!r}")
    assert Session.from_dict({"session_id": "ABC12345", "analysis_gate": " PENDING "}).analysis_gate == "pending"
    assert Session.from_dict({"session_id": "ABC12345", "analysis_gate": "complete"}).analysis_gate == "complete"


def test_session_metadata_round_trip_reports_source_and_idb_presence(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"binary")
    session = Session("ABC12345", str(tmp_path / "sample.i64"), str(source), tags=["triage"])
    encoded = session.to_dict()
    assert encoded["binary_exists"] is True
    assert encoded["idb_exists"] is False
    restored = Session.from_dict(encoded)
    assert restored.session_id == session.session_id
    assert restored.tags == ["triage"]
    assert restored.binary_path == str(source)


def test_session_tags_notes_filters_and_stats(tmp_path):
    manager = SessionManager(str(tmp_path))
    first = manager.create_session("/samples/first.bin", tags=["malware"], notes="initial triage")
    second = manager.create_session("/samples/second.bin")
    assert manager.tag_session(second.session_id, "firmware") is not None
    assert manager.untag_session(second.session_id, "firmware") is not None
    manager.add_note(second.session_id, "  decoder reviewed  ")
    assert "decoder reviewed" in manager.get_session(second.session_id).notes
    assert [s.session_id for s in manager.search_notes("decoder")] == [second.session_id]
    assert manager.find_by_tag("malware")[0].session_id == first.session_id
    manager.clear_notes(second.session_id)
    assert manager.search_notes("decoder") == []

    archived = manager.archive_session(first.session_id)
    assert archived is not None
    assert len(manager.list_active()) == 1
    assert len(manager.list_archived()) == 1
    stats = manager.get_stats()
    assert stats["total"] == 2 and stats["archived"] == 1
    assert manager.get_recent(1)
    assert manager.get_oldest(1)
    assert manager.get_session_age(first.session_id) >= timedelta(0)
    assert manager.get_session_idle_time(first.session_id) >= timedelta(0)


def test_session_snapshot_restore_rehydrates_user_workspace(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin", tags=["keep"])
    sid = session.session_id
    manager.add_note(sid, "before checkpoint")
    manager._save_notebook(sid, "# Before\n")
    state = manager._load_skills(sid)
    state["skills"]["decompile"] = {"quality": 0.9}
    manager._save_skills(sid, state)
    snapshot = manager.snapshot_session(sid, message="before risky edit")
    assert snapshot and snapshot["snapshot_id"]

    manager.update_session(sid, tags=["changed"], notes="after checkpoint")
    manager._save_notebook(sid, "# After\n")
    restored = manager.restore_snapshot(sid, snapshot["snapshot_id"])
    assert restored is not None
    assert restored.tags == ["keep"]
    assert restored.notes.endswith("before checkpoint")
    assert manager._load_notebook(sid) == "# Before\n"
    assert manager._load_skills(sid)["skills"]["decompile"]["quality"] == 0.9
    assert manager.list_snapshots(sid)["snapshots"][0]["_message"] == "before risky edit"
    assert manager.restore_snapshot(sid, "missing") is None


def test_session_export_duplicate_and_import_use_independent_paths(tmp_path):
    manager = SessionManager(str(tmp_path))
    source = manager.create_session("/samples/target.bin", tags=["research"], notes="notes")
    manager.track_hypothesis(source.session_id, "has a decoder", confidence=0.95)
    exported = manager.export_session(source.session_id)
    assert exported and exported["_hypotheses"]
    duplicate = manager.duplicate_session(source.session_id)
    assert duplicate is not None
    assert duplicate.session_id != source.session_id
    assert duplicate.idb_path != source.idb_path
    imported = manager.import_session(exported)
    assert imported.session_id not in {source.session_id, duplicate.session_id}
    assert imported.idb_path != source.idb_path
    assert manager.get_high_confidence_hypotheses(imported.session_id, 0.9)
    assert manager.export_session("missing") is None


def test_session_hypothesis_lifecycle_and_missing_ids(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    sid = session.session_id
    tracked = manager.track_hypothesis(sid, "calls network API", evidence_for=["xrefs"], confidence=0.6)
    hid = tracked["hypothesis_id"]
    confirmed = manager.confirm_hypothesis(sid, hid, evidence=["import"])
    assert confirmed["hypothesis"]["status"] == "confirmed"
    assert confirmed["hypothesis"]["evidence_for"] == ["xrefs", "import"]
    missing = manager.refute_hypothesis(sid, "missing", "not observed")
    assert missing["error"] is True and missing["code"] == MCPError.NOT_FOUND
    no_session = manager.track_hypothesis("missing", "x")
    assert no_session["error"] is True and no_session["code"] == MCPError.SESSION_NOT_FOUND


def test_session_validation_bulk_operations_and_cleanup(tmp_path):
    manager = SessionManager(str(tmp_path))
    old = manager.create_session("/missing/old.bin")
    current = manager.create_session("/missing/current.bin")
    old.last_accessed = datetime.now() - timedelta(days=45)
    manager._save_metadata(old)
    validation = manager.validate_session(old.session_id)
    assert validation["valid"] is False
    assert any("Binary not found" in issue for issue in validation["issues"])
    assert manager.bulk_tag([old.session_id, "missing"], "review")[old.session_id] is True
    removed = manager.cleanup_stale(max_age_days=30)
    assert old.session_id in removed
    assert manager.session_exists(current.session_id)


def test_bookmark_crud_filters_and_error_contract(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    bookmarks = BookmarkManager(manager.session_dir)
    sid = session.session_id
    assert bookmarks.add(sid, {})["code"] == MCPError.INVALID_ARGS
    added = bookmarks.add(
        sid,
        {"addr": "0x401000", "name": "decoder", "notes": "network path", "category": "code", "tags": "network, hot", "priority": "bad"},
    )
    assert added["ok"] is True
    bid = added["bookmark"]["id"]
    updated = bookmarks.add(sid, {"addr": "0x401000", "name": "decoder2", "tags": ["keep"]})
    assert updated["updated"] is True
    assert updated["bookmark"]["notes"] == "network path"
    assert bookmarks.list(sid, {"tag": "keep"})["count"] == 1
    assert bookmarks.list(sid, {"category": "code", "query": "network"})["count"] == 1
    assert bookmarks.find(sid, "decoder2")["count"] == 1
    assert bookmarks.update(sid, {"id": bid, "priority": "2", "tags": "updated"})["ok"] is True
    assert bookmarks.delete(sid, {"id": "bad"})["code"] == MCPError.INVALID_ARGS
    assert bookmarks.delete(sid, {"id": bid})["deleted"] == 1
    assert bookmarks.delete(sid, {"id": bid})["code"] == MCPError.BOOKMARK_NOT_FOUND
    assert bookmarks.clear(sid)["ok"] is True
    assert bookmarks.export(sid)["report"] == "No bookmarks found."
