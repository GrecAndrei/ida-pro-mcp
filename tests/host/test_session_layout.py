"""Session cache layout: per-session directories, legacy migration, filters.

The session store uses one directory per session
(``cache_dir/sessions/SID_<sid>/``) holding metadata.json, the IDB, and all
session artifacts, with logs in a ``logs/`` subdirectory. Legacy flat-layout
sessions (``SID_<sid>_metadata.json`` next to the other files) are migrated
in place on load so no analysis is lost.
"""

from __future__ import annotations

import json
import os

import pytest

from ida_pro_mcp.host.server.session import BookmarkManager, Session, SessionManager


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_create_session_uses_per_session_directory(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/samples/foo.bin")

    sid = session.session_id
    assert session.idb_path == os.path.join(
        str(tmp_path), "sessions", f"SID_{sid}", f"SID_{sid}_foo.bin.i64"
    )
    assert os.path.isfile(
        os.path.join(str(tmp_path), "sessions", f"SID_{sid}", "metadata.json")
    )
    # No flat-layout leftovers.
    assert not os.path.exists(
        os.path.join(str(tmp_path), "sessions", f"SID_{sid}_metadata.json")
    )


def test_session_artifacts_land_in_session_directory(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/samples/foo.bin")
    sid = session.session_id
    session_dir = os.path.join(str(tmp_path), "sessions", f"SID_{sid}")

    mgr.track_hypothesis(sid, "suspicious API chain", confidence=0.7)
    mgr.snapshot_session(sid, message="checkpoint")
    mgr._save_notebook(sid, "# Analysis")
    mgr._save_skills(sid, {"skills": {"x": {"q": 1.0}}, "hypotheses": [], "activity_log": []})

    assert os.path.isfile(os.path.join(session_dir, "skills.json"))
    assert os.path.isfile(os.path.join(session_dir, "snapshots.json"))
    assert os.path.isfile(os.path.join(session_dir, "notebook.md"))
    assert mgr._load_notebook(sid) == "# Analysis"
    assert mgr.list_snapshots(sid)["snapshots"]
    assert "x" in mgr._load_skills(sid)["skills"]


def test_bookmarks_write_into_session_directory(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/samples/foo.bin")
    sid = session.session_id
    bm = BookmarkManager(mgr.session_dir)
    bm.add(sid, {"addr": "0x401000", "name": "entry"})

    path = os.path.join(str(tmp_path), "sessions", f"SID_{sid}", "bookmarks.json")
    assert os.path.isfile(path)
    assert bm.load(sid)[0]["addr"] == "0x401000"


def test_new_layout_session_reloads_across_manager_instances(tmp_path):
    mgr1 = SessionManager(str(tmp_path))
    session = mgr1.create_session("/samples/foo.bin")
    sid = session.session_id
    mgr1.add_note(sid, "relocations verified")
    mgr1.update_session(sid, analysis_gate="pending")
    mgr1._save_notebook(sid, "# Analysis\n- done")

    mgr2 = SessionManager(str(tmp_path))
    loaded = mgr2.get_session(sid)
    assert loaded is not None
    assert loaded.binary_path == "/samples/foo.bin"
    assert loaded.idb_path == session.idb_path
    assert "relocations verified" in loaded.notes
    # The durable analysis gate survives a manager restart so h05 can resume
    # a large binary in the same gate state it died in.
    assert loaded.analysis_gate == "pending"
    assert mgr2._load_notebook(sid) == "# Analysis\n- done"


def test_legacy_flat_session_is_migrated_on_load(tmp_path):
    cache_dir = str(tmp_path)
    session_dir = os.path.join(cache_dir, "sessions")
    os.makedirs(session_dir)
    sid = "AAAA1111"
    legacy_idb = os.path.join(session_dir, f"SID_{sid}_foo.bin.i64")
    legacy_session = Session(sid, legacy_idb, "/samples/foo.bin", notes="old notes")
    legacy_session.analysis_gate = "complete"
    _write(
        os.path.join(session_dir, f"SID_{sid}_metadata.json"),
        json.dumps(legacy_session.to_dict()),
    )
    _write(os.path.join(session_dir, f"SID_{sid}_bookmarks.json"), json.dumps([{"id": 1, "addr": "0x401000"}]))
    _write(os.path.join(session_dir, f"SID_{sid}_notebook.md"), "# Legacy notebook")
    _write(os.path.join(session_dir, f"SID_{sid}_snapshots.json"), "[]")
    _write(os.path.join(session_dir, f"SID_{sid}_skills.json"), json.dumps({"skills": {}, "hypotheses": []}))
    _write(legacy_idb, "IDB")
    _write(os.path.join(cache_dir, "ida_mcp_AAAA1111.log"), "boot log")

    mgr = SessionManager(cache_dir)
    loaded = mgr.get_session(sid)
    assert loaded is not None
    assert loaded.notes == "old notes"
    # The gate field is carried through the legacy flat-layout migration.
    assert loaded.analysis_gate == "complete"

    session_dir_path = os.path.join(session_dir, f"SID_{sid}")
    assert os.path.isfile(os.path.join(session_dir_path, "metadata.json"))
    assert os.path.isfile(os.path.join(session_dir_path, "bookmarks.json"))
    assert os.path.isfile(os.path.join(session_dir_path, "notebook.md"))
    assert os.path.isfile(os.path.join(session_dir_path, "snapshots.json"))
    assert os.path.isfile(os.path.join(session_dir_path, "skills.json"))
    assert os.path.isfile(os.path.join(session_dir_path, f"SID_{sid}_foo.bin.i64"))
    assert os.path.isfile(os.path.join(session_dir_path, "logs", "ida_mcp.log"))
    # The IDB path in the loaded session now points into the new layout.
    assert loaded.idb_path == os.path.join(session_dir_path, f"SID_{sid}_foo.bin.i64")
    # Flat-layout originals are gone.
    assert not os.path.exists(os.path.join(session_dir, f"SID_{sid}_metadata.json"))
    assert not os.path.exists(os.path.join(session_dir, f"SID_{sid}_bookmarks.json"))
    # Artifacts read through the new paths.
    assert mgr._load_notebook(sid) == "# Legacy notebook"
    assert BookmarkManager(mgr.session_dir).load(sid) == [{"id": 1, "addr": "0x401000"}]


def test_list_sessions_binary_name_filter(tmp_path):
    mgr = SessionManager(str(tmp_path))
    mgr.create_session("/samples/libc.so.6")
    mgr.create_session("/samples/evil.exe")

    listed = mgr.list_sessions(binary_name="libc")
    assert listed["total"] == 1
    assert listed["sessions"][0]["binary_path"].endswith("libc.so.6")

    # Case-insensitive substring match.
    assert mgr.list_sessions(binary_name="LIB")["total"] == 1
    assert mgr.list_sessions(binary_name="nope")["total"] == 0
    # No filter: everything.
    assert mgr.list_sessions()["total"] == 2


def test_list_sessions_query_matches_auto_name_and_notes(tmp_path):
    mgr = SessionManager(str(tmp_path))
    mgr.create_session("/samples/evil.exe")
    mgr.create_session("/samples/other.bin", notes="gadget hunt")

    assert mgr.list_sessions(query="gadget")["total"] == 1
    assert mgr.list_sessions(query="evil.exe")["total"] == 1


def test_orphaned_idb_recovered_from_directory_layout(tmp_path):
    session_dir = os.path.join(str(tmp_path), "sessions")
    sid = "BBBB2222"
    os.makedirs(os.path.join(session_dir, f"SID_{sid}"))
    _write(
        os.path.join(session_dir, f"SID_{sid}", f"SID_{sid}_kernel.bin.i64"),
        "IDB",
    )

    mgr = SessionManager(str(tmp_path))
    recovered = mgr.get_session(sid)
    assert recovered is not None
    assert recovered.idb_path.endswith(f"SID_{sid}_kernel.bin.i64")
    assert recovered.auto_name == "kernel.bin"


def test_delete_session_removes_whole_session_directory(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/samples/foo.bin")
    sid = session.session_id
    session_dir = os.path.join(str(tmp_path), "sessions", f"SID_{sid}")
    _write(os.path.join(session_dir, "notebook.md"), "# Analysis")

    assert mgr.delete_session(sid) is True
    assert not os.path.exists(session_dir)
    assert mgr.get_session(sid) is None
    assert not os.path.exists(os.path.join(str(tmp_path), "sessions", f"SID_{sid}_metadata.json"))


def test_delete_session_also_removes_legacy_flat_layout(tmp_path):
    cache_dir = str(tmp_path)
    session_dir = os.path.join(cache_dir, "sessions")
    os.makedirs(session_dir)
    sid = "CCCC3333"
    _write(os.path.join(session_dir, f"SID_{sid}_metadata.json"), json.dumps(Session(sid, "", "").to_dict()))
    _write(os.path.join(session_dir, f"SID_{sid}_bookmarks.json"), "[]")

    mgr = SessionManager(cache_dir)
    assert mgr.delete_session(sid) is True
    assert not os.path.exists(os.path.join(session_dir, f"SID_{sid}_metadata.json"))
    assert not os.path.exists(os.path.join(session_dir, f"SID_{sid}_bookmarks.json"))


@pytest.mark.parametrize(
    "binary_name,expected",
    [
        ("libc", 1),
        ("so.6", 1),
        ("exe", 1),
        ("", 2),
    ],
)
def test_discover_sessions_binary_name_filter(tmp_path, binary_name, expected):
    mgr = SessionManager(str(tmp_path))
    mgr.create_session("/samples/libc.so.6")
    mgr.create_session("/samples/evil.exe")
    found = mgr.discover_sessions(binary_name=binary_name)
    assert len(found) == expected
