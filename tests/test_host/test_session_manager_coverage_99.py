from __future__ import annotations

import errno
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server.session import (
    MAX_SNAPSHOTS_PER_SESSION,
    MAX_TAGS_PER_SESSION,
    BookmarkManager,
    Session,
    SessionManager,
)


def test_session_model_validation_and_methods(tmp_path: Path):
    s = Session("12345678", idb_path="", binary_path="")
    assert s.idb_path_basename() == ""

    with pytest.raises(ValueError, match="session metadata must be an object"):
        Session.from_dict("not a dict")  # type: ignore

    with pytest.raises(ValueError, match="binary_path must be a string"):
        Session.from_dict({"session_id": "12345678", "binary_path": 123})


def test_session_manager_tags_and_skills_boundaries(tmp_path: Path):
    sm = SessionManager(str(tmp_path))

    # _sanitize_tags break on MAX_TAGS_PER_SESSION
    many_tags = [f"tag_{i}" for i in range(MAX_TAGS_PER_SESSION + 5)]
    sanitized = sm._sanitize_tags(many_tags)
    assert len(sanitized) == MAX_TAGS_PER_SESSION

    # _new_session_id retry exhaustion
    fake_uuid = MagicMock()
    fake_uuid.hex = "ABCDEF123456"
    with patch("uuid.uuid4", return_value=fake_uuid):
        sm.sessions["ABCDEF12"] = Session("ABCDEF12", "/bin", "/bin.i64")
        with pytest.raises(RuntimeError, match="failed to allocate unique session id"):
            sm._new_session_id()

    # _find_global_skills with tag filter not matching and db query error
    conn = sqlite3.connect(sm._global_skills_db)
    conn.execute(
        "INSERT INTO global_skills (skill_id, name, description, steps, tags, source_sid, q_value) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("sk1", "name", "desc", "[]", json.dumps(["reverse"]), "sid", 0.5),
    )
    conn.commit()
    conn.close()

    assert sm._find_global_skills(tags=["cryptography"]) == []

    with patch("sqlite3.connect", side_effect=Exception("db lock")):
        assert sm._find_global_skills() == []


def test_session_manager_metadata_save_and_load_errors(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    s = sm.create_session("/bin1", idb_path="/bin1.i64")

    # ENOSPC
    with patch("builtins.open", side_effect=OSError(errno.ENOSPC, "No space left on device")):
        sm._save_metadata(s)

    # Generic OSError
    with patch("builtins.open", side_effect=OSError(errno.EACCES, "Permission denied")):
        sm._save_metadata(s)

    # Generic Exception
    with patch("builtins.open", side_effect=RuntimeError("disk error")):
        sm._save_metadata(s)

    # _load_metadata_file with invalid session id in dict
    valid_meta = str(tmp_path / "valid_meta.json")
    Path(valid_meta).write_text(json.dumps({"session_id": "ABCDEF12", "idb_path": ""}), encoding="utf-8")
    fake_s = Session("ABCDEF12", "", "")
    fake_s.session_id = ""
    with patch.object(Session, "from_dict", return_value=fake_s):
        assert sm._load_metadata_file(valid_meta) is None

    # _load_metadata_file with corrupt json
    corrupt_meta = str(tmp_path / "corrupt_meta.json")
    Path(corrupt_meta).write_text("not json content", encoding="utf-8")
    assert sm._load_metadata_file(corrupt_meta) is None


def test_session_manager_migration_and_orphaned_edges(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    sid = "12345678"
    session_dir = Path(sm.session_dir)
    target_dir = session_dir / f"SID_{sid}"
    target_dir.mkdir(parents=True, exist_ok=True)

    # File already at destination in target_dir (covers line 517)
    legacy_file = session_dir / f"SID_{sid}_dup.txt"
    legacy_file.write_text("data", encoding="utf-8")
    s = Session(sid, str(target_dir / "test.i64"), "")
    with patch("os.path.abspath", return_value="/mock/same/path"):
        sm._migrate_legacy_session_files(s)

    # Orphaned non-IDB files ignored
    non_idb = session_dir / f"SID_{sid}_log.txt"
    non_idb.write_text("ignore me", encoding="utf-8")
    sm._load_orphaned_idbs()
    assert sid not in sm.sessions


def test_session_manager_path_and_note_lookups(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    s = sm.create_session("/bin/unique", idb_path="/idb/unique.i64")

    # update_session_metadata with nonexistent session
    assert sm.update_session_metadata("NONEXIST", key="val") is False

    # find_session_by_path matching IDB path
    found = sm.find_session_by_path("/idb/unique.i64")
    assert found is not None
    assert found.session_id == s.session_id

    # untag_session, add_note, get_session_idle_time nonexistent
    assert sm.untag_session("NONEXIST", "tag") is None
    assert sm.add_note("NONEXIST", "note") is None
    assert sm.get_session_idle_time("NONEXIST") is None


def test_session_manager_delete_error_paths(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    sid = sm.create_session("/bin/del", idb_path="/idb/del.i64").session_id

    # Create dummy flat files and cache logs
    session_dir = Path(sm.session_dir)
    (session_dir / f"SID_{sid}_flat.txt").write_text("data", encoding="utf-8")
    cache = Path(sm.cache_dir)
    (cache / f"ida_mcp_{sid}.log").write_text("log", encoding="utf-8")
    (cache / f"{sid}.blackboard.db").write_text("db", encoding="utf-8")
    leases_dir = cache / "runtime_leases"
    leases_dir.mkdir(parents=True, exist_ok=True)
    (leases_dir / f"SID_{sid}.lease.json").write_text("{}", encoding="utf-8")

    # Successful delete covering lines 696 and 705
    assert sm.delete_session(sid) is True

    # Force os.remove to raise when deleting all file categories (lines 698-699, 706-707, 713-714, 728-729)
    sid2 = sm.create_session("/bin/del2", idb_path="/idb/del2.i64").session_id
    (session_dir / f"SID_{sid2}_flat.txt").write_text("data", encoding="utf-8")
    (cache / f"ida_mcp_{sid2}.log").write_text("log", encoding="utf-8")
    (cache / f"{sid2}.blackboard.db").write_text("db", encoding="utf-8")
    (leases_dir / f"SID_{sid2}.lease.json").write_text("{}", encoding="utf-8")
    with patch("os.remove", side_effect=OSError("locked")):
        assert sm.delete_session(sid2) is True


def test_session_manager_auto_prune_sessions(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    now = datetime.now()

    # Invalid min_idle_days fallback to 7
    assert sm.auto_prune_if_over_budget(10, 30, min_idle_days="invalid") == 0

    # Pruning pass 1 + pass 2 with both stale in pass 1 and recent survivor skipped in pass 2
    # non_live sorted oldest first:
    # 1. s_stale: 25 days old (pruned in pass 1, hits 978-979 in pass 2)
    # 2. s_old: 6 days old (not pruned in pass 1, pruned in pass 2)
    # 3. s_recent1: 1 hour old (not pruned in pass 1, skipped in pass 2 via idle_cutoff hitting 980-981)
    # 4. s_recent2: 30 mins old (hits 980-981 as well)
    s_stale = sm.create_session("/bin_stale", idb_path="/bin_stale.i64")
    s_old = sm.create_session("/bin_old", idb_path="/bin_old.i64")
    s_recent1 = sm.create_session("/bin_recent1", idb_path="/bin_recent1.i64")
    s_recent2 = sm.create_session("/bin_recent2", idb_path="/bin_recent2.i64")

    s_stale.last_accessed = now - timedelta(days=25)
    s_old.last_accessed = now - timedelta(days=6)
    s_recent1.last_accessed = now - timedelta(hours=1)
    s_recent2.last_accessed = now - timedelta(minutes=30)

    # Budget 1, max_age 10 days, min_idle 2 days
    # s_stale pruned in pass 1. In pass 2: s_stale in stale (hits 979). s_old pruned.
    # Count is now 2 > 1. s_recent1 examined: last_accessed >= idle_cutoff (hits 981).
    # s_recent2 examined: last_accessed >= idle_cutoff (hits 981).
    pruned = sm.auto_prune_if_over_budget(1, max_age_days=10, min_idle_days=2)
    assert pruned == 2
    assert len(sm.sessions) == 2


def test_session_manager_validate_session(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    s = sm.create_session("/bin/val", idb_path="/idb/val.i64")

    # Missing metadata file
    meta_file = Path(sm._get_metadata_path(s.session_id))
    if meta_file.exists():
        meta_file.unlink()

    # Future created_at and empty session_id
    s.created_at = datetime.now() + timedelta(days=2)
    s.session_id = ""

    # Add s back with key "TESTSID" to test empty session_id check
    sm.sessions["TESTSID"] = s
    val = sm.validate_session("TESTSID")
    assert not val["valid"]
    assert any("Metadata file missing" in issue for issue in val["issues"])
    assert any("Empty session_id" in issue for issue in val["issues"])
    assert any("created_at is in the future" in issue for issue in val["issues"])


def test_session_manager_snapshots_and_notebook(tmp_path: Path):
    sm = SessionManager(str(tmp_path))
    sid = sm.create_session("/bin/snap", idb_path="/idb/snap.i64").session_id

    # Create snapshots up to MAX_SNAPSHOTS_PER_SESSION + 2
    for i in range(MAX_SNAPSHOTS_PER_SESSION + 2):
        sm.snapshot_session(sid, f"snap_{i}")

    snapshots = sm.list_snapshots(sid)
    assert len(snapshots["snapshots"]) == MAX_SNAPSHOTS_PER_SESSION

    # restore_snapshot when session not in self.sessions
    snap_id = snapshots["snapshots"][0]["_snapshot_id"]
    del sm.sessions[sid]
    assert sm.restore_snapshot(sid, snap_id) is None

    # Error saving snapshots
    sm.sessions[sid] = Session(sid, "", "")
    with patch("builtins.open", side_effect=OSError("write failed")):
        sm._save_snapshots(sid, [])

    # Load notebook error
    nb_path = Path(sm._get_notebook_path(sid))
    nb_path.parent.mkdir(parents=True, exist_ok=True)
    nb_path.write_text("notes", encoding="utf-8")
    with patch("builtins.open", side_effect=OSError("read failed")):
        assert sm._load_notebook(sid) == ""

    # Save notebook error
    with patch("builtins.open", side_effect=OSError("write failed")):
        sm._save_notebook(sid, "content")


def test_bookmark_manager_error_handling(tmp_path: Path):
    bm = BookmarkManager(str(tmp_path))
    sid = "12345678"
    os.makedirs(os.path.dirname(bm._get_path(sid)), exist_ok=True)

    # save raises
    with patch("builtins.open", side_effect=OSError("disk error")):
        res = bm.save(sid, [])
        assert res.get("error") is True

    # initial save succeeds
    bm.save(sid, [{"id": 1, "addr": "0x1000", "name": "initial"}])

    # add existing bookmark when save fails (hits line 1450)
    with patch.object(bm, "save", return_value=make_error(MCPError.IO_ERROR, "save err")):
        res = bm.add(sid, {"addr": "0x1000", "name": "updated"})
        assert res.get("error") is True

    # add new bookmark when save fails (hits line 1455)
    with patch.object(bm, "save", return_value=make_error(MCPError.IO_ERROR, "save err")):
        res = bm.add(sid, {"addr": "0x2000", "name": "new"})
        assert res.get("error") is True


def test_session_manager_and_bookmark_remaining_edges(tmp_path: Path):
    from ida_pro_mcp.host.server.session import _coerce_bookmark_tags

    sm = SessionManager(str(tmp_path))

    # 1. update_session_metadata
    assert not sm.update_session_metadata("NONEXISTENT", k=1)
    s = sm.create_session("/path/to/binary.i64")
    sid = s.session_id
    assert sm.update_session_metadata(sid, k=1)
    # same update returns False
    assert not sm.update_session_metadata(sid, k=1)

    # 2. duplicate_session with .i64 binary_path (hits line 773)
    dup = sm.duplicate_session(sid)
    assert dup is not None

    # 3. import_session with .i64 binary_path (hits line 838)
    imp = sm.import_session({"binary_path": "test.i64", "metadata": {}})
    assert imp is not None

    # 4. auto_prune_if_over_budget pass 2 break on budget (hits line 977)
    # Clear sessions
    sm.sessions.clear()
    old_time = datetime.now() - timedelta(days=5)
    for i in range(4):
        sess = Session(f"PRN0000{i}", f"/tmp/p{i}.i64", f"/tmp/p{i}")
        sess.last_accessed = old_time
        sm.sessions[sess.session_id] = sess
    # budget=2, max_age_days=10 (so none pruned in pass 1), min_idle_days=1 (older than 1 day so eligible in pass 2)
    sm.auto_prune_if_over_budget(budget=2, max_age_days=10, min_idle_days=1)
    assert len(sm.sessions) == 2

    # 5. _coerce_bookmark_tags(None) (hits line 1357)
    assert _coerce_bookmark_tags(None) == []

    # 6. bookmark export with invalid priority and tags (hits lines 1375-1376, 1551-1552, 1559)
    bm = BookmarkManager(str(tmp_path))
    os.makedirs(os.path.dirname(bm._get_path(sid)), exist_ok=True)
    bm.save(sid, [
        {"id": 1, "addr": "0x1000", "name": "bad_prio", "priority": "not_an_int", "tags": ["tag1", "tag2"]}
    ])
    rep = bm.export(sid)
    assert rep["ok"] is True
    assert "tag1, tag2" in rep["report"]

