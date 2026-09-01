"""Regression tests for the f01_session_manager fixer wave.

Covers findings in host/server/session.py and host/server/server_multi_session.py:
- archive_session preserves existing tags instead of replacing the whole list.
- merge_sessions tolerates skills.json files that lack activity_log/hypotheses.
- get_high_confidence_hypotheses guards a non-numeric / out-of-range threshold.
- delete_session / bulk_delete refuse malformed (path-hostile) session ids.
- BookmarkManager.export tolerates rows missing id/name/addr.
- _ms_group_link re-resolves the group under the lock (no lost update on a
  concurrent group_remove + group_create with the same id).
"""

from __future__ import annotations

import json
import os
import threading

from ida_pro_mcp.host.server.server_multi_session import (
    ServerMultiSessionMixin,
    SessionGroup,
)
from ida_pro_mcp.host.server.session import BookmarkManager, Session, SessionManager


def _skills_path(mgr: SessionManager, sid: str) -> str:
    return os.path.join(mgr.session_dir, f"SID_{sid}", "skills.json")


# ---------------------------------------------------------------------------
# session.py: analysis_gate round-trips through metadata (h03)
# ---------------------------------------------------------------------------


def test_analysis_gate_round_trips_through_to_dict_from_dict():
    session = Session(
        "ABC12345",
        "/tmp/SID_ABC12345_x.i64",
        "/tmp/x.bin",
        analysis_gate="pending",
    )
    restored = Session.from_dict(session.to_dict())
    assert restored.analysis_gate == "pending"

    complete = Session.from_dict({"session_id": "ABC12345", "analysis_gate": "complete"})
    assert complete.analysis_gate == "complete"

    # Unknown / malformed gate values normalize to None so downstream code
    # never sees a gate state it does not understand.
    junk = Session.from_dict({"session_id": "ABC12345", "analysis_gate": "warped"})
    assert junk.analysis_gate is None
    missing = Session.from_dict({"session_id": "ABC12345"})
    assert missing.analysis_gate is None


def test_session_from_dict_normalizes_optional_metadata_types():
    restored = Session.from_dict(
        {
            "session_id": "ABC12345",
            "idb_path": None,
            "binary_path": None,
            "analysis_options": ["not a mapping"],
            "ida_args": ["-A", 123, None],
            "tags": ["firmware", 7, None],
            "notes": 42,
            "auto_name": 99,
            "phase": 123,
            "linked_sessions": ["DEF67890", 1],
            "policy_mode": {"mode": "strict"},
            "metadata": ["not a mapping"],
        }
    )
    assert restored.idb_path == ""
    assert restored.binary_path == ""
    assert restored.analysis_options == {}
    assert restored.ida_args == ["-A"]
    assert restored.tags == ["firmware", "7"]
    assert restored.notes == ""
    assert restored.auto_name == "session_ABC12345"
    assert restored.phase == "triage"
    assert restored.linked_sessions == ["DEF67890"]
    assert restored.policy_mode is None
    assert restored.metadata == {}


def test_analysis_gate_survives_manager_save_and_reload(tmp_path):
    mgr1 = SessionManager(str(tmp_path))
    session = mgr1.create_session("/tmp/x.bin")
    sid = session.session_id
    mgr1.update_session(sid, analysis_gate="complete")

    mgr2 = SessionManager(str(tmp_path))
    reloaded = mgr2.get_session(sid)
    assert reloaded is not None
    assert reloaded.analysis_gate == "complete"
    # The gate is a first-class metadata.json field, not a side table.
    with open(mgr1._get_metadata_path(sid), encoding="utf-8") as f:
        assert json.load(f)["analysis_gate"] == "complete"


# ---------------------------------------------------------------------------
# session.py: archive_session preserves existing tags (bug/medium)
# ---------------------------------------------------------------------------


def test_archive_session_preserves_existing_tags(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s = mgr.create_session("/samples/foo.bin", tags=["malware", "firmware"])
    archived = mgr.archive_session(s.session_id)
    assert archived is not None
    assert "malware" in archived.tags
    assert "firmware" in archived.tags
    assert "archived" in archived.tags
    # get_stats still counts the session as archived.
    assert mgr.get_stats()["archived"] == 1
    # Unarchive removes only the archived tag, keeping the rest.
    restored = mgr.unarchive_session(s.session_id)
    assert "malware" in restored.tags
    assert "archived" not in restored.tags


def test_archive_session_is_idempotent_and_missing_session_returns_none(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s = mgr.create_session("/samples/foo.bin", tags=["keep"])
    mgr.archive_session(s.session_id)
    again = mgr.archive_session(s.session_id)
    assert again is not None
    assert again.tags.count("archived") == 1
    assert "keep" in again.tags
    assert mgr.archive_session("ZZZZZZZZ") is None


# ---------------------------------------------------------------------------
# session.py: merge_sessions tolerates skills.json missing keys
# (error_handling/medium)
# ---------------------------------------------------------------------------


def test_merge_sessions_tolerates_skills_json_missing_keys(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s1 = mgr.create_session("/samples/a.bin")
    s2 = mgr.create_session("/samples/b.bin")
    # Simulate a legacy / hand-written skills.json that only persisted
    # skills and q_table (no activity_log / hypotheses arrays).
    for sid in (s1.session_id, s2.session_id):
        path = _skills_path(mgr, sid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"skills": {}, "q_table": {}}, f)
    merged = mgr.merge_sessions(s1.session_id, s2.session_id)
    assert merged is not None
    # The merge must not raise and must leave the stored data consistent.
    data = mgr._load_skills(s1.session_id)
    assert data["activity_log"] == []
    assert data["hypotheses"] == []


def test_merge_sessions_keeps_existing_hypotheses(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s1 = mgr.create_session("/samples/a.bin")
    s2 = mgr.create_session("/samples/b.bin")
    data = mgr._load_skills(s1.session_id)
    data["hypotheses"] = [{"id": "h1", "confidence": 0.9}]
    mgr._save_skills(s1.session_id, data)
    merged = mgr.merge_sessions(s1.session_id, s2.session_id)
    assert merged is not None
    assert [h["id"] for h in mgr._load_skills(s1.session_id)["hypotheses"]] == ["h1"]


# ---------------------------------------------------------------------------
# session.py: get_high_confidence_hypotheses guards the threshold
# (error_handling/low)
# ---------------------------------------------------------------------------


def test_get_high_confidence_hypotheses_tolerates_bad_threshold(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s = mgr.create_session("/samples/foo.bin")
    data = mgr._load_skills(s.session_id)
    data["hypotheses"] = [
        {"id": "h1", "confidence": 0.95},
        {"id": "h2", "confidence": 0.5},
    ]
    mgr._save_skills(s.session_id, data)

    # Non-numeric threshold falls back to the default 0.8 and does not raise.
    result = mgr.get_high_confidence_hypotheses(s.session_id, min_confidence="nope")
    assert [h["id"] for h in result] == ["h1"]

    # Numeric-string thresholds still work.
    both = mgr.get_high_confidence_hypotheses(s.session_id, min_confidence="0.4")
    assert [h["id"] for h in both] == ["h1", "h2"]

    # Out-of-range thresholds are clamped to [0, 1].
    assert len(mgr.get_high_confidence_hypotheses(s.session_id, min_confidence=-1)) == 2
    assert mgr.get_high_confidence_hypotheses(s.session_id, min_confidence=2) == []


# ---------------------------------------------------------------------------
# session.py: delete_session / bulk_delete refuse malformed sids (security/low)
# ---------------------------------------------------------------------------


def test_delete_session_rejects_malformed_sid(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s = mgr.create_session("/samples/foo.bin")
    # A valid delete still works.
    assert mgr.delete_session(s.session_id) is True
    # Path-hostile / malformed ids are refused without touching the filesystem.
    assert mgr.delete_session("../../etc/passwd") is False
    assert mgr.delete_session("../") is False
    assert mgr.delete_session("SID_..") is False
    assert mgr.delete_session("TOOLONG123") is False


def test_bulk_delete_refuses_malformed_sids(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s = mgr.create_session("/samples/foo.bin")
    results = mgr.bulk_delete([s.session_id, "../../evil"])
    assert results[s.session_id] is True
    assert results["../../evil"] is False


# ---------------------------------------------------------------------------
# session.py: BookmarkManager.export tolerates rows missing id/name/addr
# (error_handling/low)
# ---------------------------------------------------------------------------


def test_bookmark_export_tolerates_rows_missing_keys(tmp_path):
    mgr = SessionManager(str(tmp_path))
    bm = BookmarkManager(mgr.session_dir)
    sid = "A1B2C3D4"
    os.makedirs(os.path.join(mgr.session_dir, f"SID_{sid}"), exist_ok=True)
    with open(
        os.path.join(mgr.session_dir, f"SID_{sid}", "bookmarks.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            [
                {"id": 1, "name": "good", "addr": "0x1000"},
                {"name": "orphan"},           # missing id + addr
                {"id": 3, "addr": "0x3000"},  # missing name
            ],
            f,
        )
    result = bm.export(sid)
    assert result["ok"] is True
    report = result["report"]
    assert "good" in report
    assert "orphan" in report
    assert "0x3000" in report


# ---------------------------------------------------------------------------
# server_multi_session.py: _ms_group_link re-resolves under the lock
# (race/low)
# ---------------------------------------------------------------------------


class _FakeMultiServer(ServerMultiSessionMixin):
    def __init__(self):
        self._session_groups = {}
        self._session_groups_lock = threading.RLock()
        self._dispatch = lambda session_id, tool, tool_args: {"ok": True}

    def _dispatch_to_session(self, session_id, tool, tool_args):
        return self._dispatch(session_id, tool, tool_args)


def test_group_link_writes_to_live_group_after_concurrent_recreate(tmp_path):
    server = _FakeMultiServer()
    g1 = SessionGroup("g1", "test")
    g1.session_ids = ["A1B2C3D4", "E5F6A7B8"]
    server._session_groups["g1"] = g1

    call_no = {"n": 0}

    def dispatch(session_id, tool, tool_args):
        call_no["n"] += 1
        if tool == "symbols":
            # Simulate a concurrent group_remove + group_create(same id) that
            # replaces the group object while the link builder is mid-flight
            # (after _require_group captured the old object).
            if call_no["n"] == 1:
                g2 = SessionGroup("g1", "test")
                g2.session_ids = ["A1B2C3D4", "E5F6A7B8"]
                server._session_groups["g1"] = g2
            return {"ok": True, "exports": [{"name": "foo", "ea": "0x1000"}]}
        if tool == "imports_deep":
            return {"ok": True, "imports": [{"name": "foo"}]}
        return {"ok": True}

    server._dispatch = dispatch

    result = server._handle_multi_session("group_link", {"group_id": "g1"})
    assert result["ok"] is True
    assert result["links_built"] >= 1
    # The links must land on the LIVE group object, not the stale one that was
    # captured before the concurrent remove + recreate.
    live = server._session_groups["g1"]
    assert "foo" in live.links
    assert live.links["foo"]["provider_sid"] == "A1B2C3D4"
    assert live.links["foo"]["importer_sids"] == ["E5F6A7B8"]


def test_group_link_returns_error_when_group_removed_mid_flight(tmp_path):
    server = _FakeMultiServer()
    g1 = SessionGroup("g1", "test")
    g1.session_ids = ["A1B2C3D4", "E5F6A7B8"]
    server._session_groups["g1"] = g1

    call_no = {"n": 0}

    def dispatch(session_id, tool, tool_args):
        call_no["n"] += 1
        if tool == "symbols" and call_no["n"] == 1:
            # The group is removed (not recreated) mid-flight.
            server._session_groups.pop("g1", None)
        return {"ok": True, "exports": [], "imports": []}

    server._dispatch = dispatch
    result = server._handle_multi_session("group_link", {"group_id": "g1"})
    assert result["error"] is True


def test_group_link_does_not_hold_group_lock_during_ida_rpc(tmp_path):
    """Status/list operations remain responsive while links are being built."""
    server = _FakeMultiServer()
    group = SessionGroup("g1", "test")
    group.session_ids = ["A1B2C3D4", "E5F6A7B8"]
    server._session_groups["g1"] = group
    imports_started = threading.Event()
    release_imports = threading.Event()

    def dispatch(session_id, tool, tool_args):
        if tool == "symbols":
            return {"ok": True, "exports": [{"name": "foo", "ea": "0x1000"}]}
        imports_started.set()
        release_imports.wait(timeout=10)
        return {"ok": True, "imports": [{"name": "foo"}]}

    server._dispatch = dispatch
    result: dict = {}
    worker = threading.Thread(
        target=lambda: result.update(
            server._handle_multi_session("group_link", {"group_id": "g1"})
        )
    )
    worker.start()
    assert imports_started.wait(timeout=10)

    status_box: dict = {}
    status_done = threading.Event()

    def _status():
        status_box["value"] = server._ms_status({})
        status_done.set()

    status_thread = threading.Thread(target=_status)
    status_thread.start()
    assert status_done.wait(timeout=2)
    release_imports.set()
    status_thread.join(timeout=2)
    worker.join(timeout=10)

    assert status_box["value"]["ok"] is True
    assert not status_thread.is_alive()
    assert not worker.is_alive()
    assert result.get("ok") is True
