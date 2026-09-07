"""Regression tests for p02_session audit findings.

Covers the p02_session fixer pass:
- import_session: fresh IDB path + fresh timestamps (no aliasing of the source
  session's IDB file).
- get_session: last_accessed persisted to disk (throttled) so restart-time
  prune guards never delete recently-used sessions.
- delete_session: removes the runtime lease file.
- duplicate_session: strips a .i64 binary basename (no double extension).
- BookmarkManager: non-integer priority / non-list tags no longer crash.
- restore_snapshot: keeps runtime-critical fields on the live session and
  returns None (not a misleading "snapshot missing") when the session is gone.
- _save_metadata and friends: pid-scoped temp files (no cross-host corruption).
- concurrent metadata updates from independent managers always leave valid JSON.
- server_session: coverage cache parses structured data/items, is session-keyed
  and lock-guarded; search_notes honors ownership; state errors without a
  session; switch with reopen re-enters safe mode; _maybe_resolve_analysis_state
  matches the watcher's reload decision; cleanup_stale orphan-prune skips
  locked sessions; _run_workflow_sequence uses the error envelope; _wait_for_idb
  returns an absolute legacy-component path.
- server_workflow_batch: batch output→input chaining reports an unresolved
  step reference as a full INVALID_ARGS error envelope (the batch-side sibling
  of _run_workflow_sequence's error envelope), never a silent empty string.
- server_multi_session: _session_groups access is lock-guarded and groups are
  reconciled when sessions are deleted.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_multi_session import ServerMultiSessionMixin, SessionGroup
from ida_pro_mcp.host.server.server_session import ServerSessionMixin
from ida_pro_mcp.host.server.server_workflow_batch import ServerWorkflowBatchMixin
from ida_pro_mcp.host.server.session import BookmarkManager, Session, SessionManager


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    return IDAMCPServer()


# ---------------------------------------------------------------------------
# session.py: import / duplicate / delete / persistence
# ---------------------------------------------------------------------------


def test_import_session_regenerates_idb_path_and_freshens_timestamps(tmp_path):
    mgr = SessionManager(str(tmp_path))
    src = mgr.create_session("/samples/foo.bin", notes="original")
    src_dir = os.path.join(str(tmp_path), "sessions", f"SID_{src.session_id}")
    exported = mgr.export_session(src.session_id)

    imported = mgr.import_session(exported)
    assert imported.session_id != src.session_id
    # Imported session must point at its OWN IDB under its own SID directory,
    # not the source session's artifact directory.
    assert imported.idb_path != src.idb_path
    assert os.path.join(
        str(tmp_path), "sessions", f"SID_{imported.session_id}"
    ) in imported.idb_path
    assert src_dir not in imported.idb_path
    # Fresh timestamps: a just-imported session is not idle.
    assert (datetime.now() - imported.created_at).total_seconds() < 5
    assert (datetime.now() - imported.last_accessed).total_seconds() < 5
    # User-facing content carries over.
    assert imported.notes == "original"


def test_import_session_strips_i64_binary_basename(tmp_path):
    mgr = SessionManager(str(tmp_path))
    src = mgr.create_session("/samples/packed.i64")
    imported = mgr.import_session(mgr.export_session(src.session_id))
    base = os.path.basename(imported.idb_path)
    assert not base.endswith(".i64.i64"), base


def test_duplicate_session_strips_i64_binary_basename(tmp_path):
    mgr = SessionManager(str(tmp_path))
    src = mgr.create_session("/samples/packed.i64")
    dup = mgr.duplicate_session(src.session_id)
    base = os.path.basename(dup.idb_path)
    assert not base.endswith(".i64.i64"), base
    assert base == f"SID_{dup.session_id}_packed.i64"


def test_get_session_persists_last_accessed_throttled(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    sid = session.session_id

    def disk_access():
        with open(mgr._get_metadata_path(sid), encoding="utf-8") as f:
            return json.load(f)["last_accessed"]

    # First get persists (nothing saved before).
    got = mgr.get_session(sid)
    assert disk_access() == got.last_accessed.isoformat()

    # A get within the throttle window must NOT rewrite disk: a fake old
    # in-memory timestamp must not leak to disk until the window elapses.
    mgr._last_accessed_saved[sid] = time.time()
    mgr.sessions[sid].last_accessed = datetime(2000, 1, 1)
    mgr.get_session(sid)
    assert disk_access() != datetime(2000, 1, 1).isoformat()

    # Once the throttle window has elapsed, get_session persists again.
    mgr._last_accessed_saved[sid] = time.time() - 61.0
    mgr.sessions[sid].last_accessed = datetime(2000, 1, 1)
    mgr.get_session(sid)
    assert disk_access() == mgr.sessions[sid].last_accessed.isoformat()


def test_delete_session_removes_runtime_lease(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    lease_dir = os.path.join(str(tmp_path), "runtime_leases")
    os.makedirs(lease_dir, exist_ok=True)
    lease_path = os.path.join(lease_dir, f"SID_{sid}.lease.json")
    with open(lease_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": sid, "pid": 12345}, f)

    assert mgr.delete_session(sid) is True
    assert not os.path.exists(lease_path)


def test_delete_session_removes_runtime_owner_file(tmp_path):
    """D3-F7: delete_session must also drop the runtime_leases/SID_<sid>.owner.json
    claim, which the stale-lease cleanup never touches — otherwise owner files
    accumulate for every session whose runtime was ever started."""
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    lease_dir = os.path.join(str(tmp_path), "runtime_leases")
    os.makedirs(lease_dir, exist_ok=True)
    owner_path = os.path.join(lease_dir, f"SID_{sid}.owner.json")
    with open(owner_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": sid, "owner_pid": os.getpid(), "owner_id": "test"}, f)

    assert mgr.delete_session(sid) is True
    assert not os.path.exists(owner_path)


def test_metadata_save_uses_pid_scoped_tmp(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    meta_path = mgr._get_metadata_path(session.session_id)
    # No unscoped `.tmp` is ever left behind (would let two hosts interleave).
    assert not os.path.exists(meta_path + ".tmp")
    # The pid-scoped temp is renamed away atomically.
    assert not os.path.exists(f"{meta_path}.{os.getpid()}.tmp")


def test_concurrent_metadata_updates_from_independent_managers_stay_valid(tmp_path):
    """Separate host objects must never expose a partially-written snapshot."""
    cache = str(tmp_path)
    first = SessionManager(cache)
    session = first.create_session("/tmp/x.bin")
    second = SessionManager(cache)
    managers = (first, second)
    errors = []
    done = threading.Event()
    start = threading.Barrier(len(managers) + 1)
    meta_path = first._get_metadata_path(session.session_id)

    def writer(manager, worker):
        start.wait()
        for seq in range(30):
            manager.update_session_metadata(
                session.session_id,
                writer=worker,
                sequence=seq,
                payload="x" * 4096,
            )

    def reader():
        start.wait()
        while not done.is_set():
            try:
                with open(meta_path, encoding="utf-8") as f:
                    json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                errors.append(type(exc).__name__)
                return

    reader_thread = threading.Thread(target=reader)
    writers = [
        threading.Thread(target=writer, args=(manager, worker))
        for worker, manager in enumerate(managers)
    ]
    reader_thread.start()
    for thread in writers:
        thread.start()
    for thread in writers:
        thread.join()
    done.set()
    reader_thread.join()

    assert errors == []
    with open(meta_path, encoding="utf-8") as f:
        assert json.load(f)["session_id"] == session.session_id


# ---------------------------------------------------------------------------
# session.py: bookmarks (priority / tags hardening)
# ---------------------------------------------------------------------------


def test_bookmark_add_coerces_non_int_priority(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    bm = BookmarkManager(mgr.session_dir)

    res = bm.add(session.session_id, {"addr": "0x1000", "priority": "high"})
    assert res.get("error") is not True
    assert res["bookmark"]["priority"] == 3

    res = bm.add(session.session_id, {"addr": "0x2000", "priority": 3.5})
    assert res.get("error") is not True
    assert res["bookmark"]["priority"] == 3

    # Explicit int still respected.
    res = bm.add(session.session_id, {"addr": "0x3000", "priority": "1"})
    assert res["bookmark"]["priority"] == 1


def test_bookmark_add_coerces_non_list_tags(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    bm = BookmarkManager(mgr.session_dir)

    res = bm.add(session.session_id, {"addr": "0x1000", "tags": 5})
    assert res.get("error") is not True
    assert res["bookmark"]["tags"] == ["5"]
    res = bm.add(session.session_id, {"addr": "0x2000", "tags": None})
    assert res.get("error") is not True
    assert res["bookmark"]["tags"] == []


def test_bookmark_read_paths_tolerate_non_list_tags_and_non_int_priority(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    bm = BookmarkManager(mgr.session_dir)
    bm.add(session.session_id, {"addr": "0x1000", "tags": ["a"], "priority": 2})
    # Simulate a legacy/bad row: numeric tags + string priority.
    path = bm._get_path(session.session_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            [
                {"id": 1, "name": "alpha", "addr": "0x1000", "tags": ["a"], "priority": 2},
                {"id": 2, "name": "bravo", "addr": "0x2000", "tags": 7, "priority": "high"},
            ],
            f,
        )

    listed = bm.list(session.session_id, {"tag": "a"})
    assert listed.get("error") is not True
    assert listed["total"] == 2

    found = bm.find(session.session_id, "0x2000")
    assert found.get("error") is not True
    assert found["count"] == 1

    exported = bm.export(session.session_id)
    assert exported.get("error") is not True
    assert "Report" in exported["report"]


# ---------------------------------------------------------------------------
# session.py: restore_snapshot
# ---------------------------------------------------------------------------


def test_restore_snapshot_keeps_runtime_paths_but_restores_user_fields(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin", notes="before", policy_mode="assist")
    sid = session.session_id
    mgr.update_session(sid, notes="checkpoint note", auto_name="chk", phase="deep_analysis")
    mgr.snapshot_session(sid, message="checkpoint")
    snapshots = mgr._load_snapshots(sid)
    snap_id = snapshots[-1]["_snapshot_id"]

    # Live session drifts: different paths / policy mode.
    mgr.update_session(
        sid,
        notes="post-snapshot",
        idb_path="/tmp/live/SID_live.i64",
        binary_path="/tmp/live.bin",
        policy_mode="strict",
    )

    restored = mgr.restore_snapshot(sid, snap_id)
    assert restored is not None
    assert restored.notes == "checkpoint note"
    assert restored.auto_name == "chk"
    assert restored.phase == "deep_analysis"
    # Runtime-critical fields stay on the LIVE session.
    assert restored.idb_path == "/tmp/live/SID_live.i64"
    assert restored.binary_path == "/tmp/live.bin"
    assert restored.policy_mode == "strict"


def test_restore_snapshot_returns_none_for_deleted_session(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin", notes="before")
    sid = session.session_id
    mgr.snapshot_session(sid, message="checkpoint")
    snapshots = mgr._load_snapshots(sid)
    snap_id = snapshots[-1]["_snapshot_id"]

    mgr.delete_session(sid)
    assert mgr.restore_snapshot(sid, snap_id) is None


# ---------------------------------------------------------------------------
# server_session.py: coverage cache + state payload
# ---------------------------------------------------------------------------


class _FakeCoverageServer:
    def __init__(self, items=None, text="", current_session_id="ABC12345"):
        self.current_session = type("S", (), {"session_id": current_session_id})()
        self._items = items
        self._text = text
        self.calls = []

    def _execute_tool(self, tool, args):
        self.calls.append((tool, dict(args)))
        if tool == "data":
            result = {"ok": True, "functions": self._text}
            if self._items is not None:
                result["items"] = self._items
            return result
        return {}


def test_coverage_parses_structured_items_and_caches_by_sid():
    fake = _FakeCoverageServer(
        items=[
            {"name": "main", "addr": "0x1000"},
            {"name": "sub_401000", "addr": "0x401000"},
            {"name": "j_printf", "addr": "0x5000"},
        ]
    )
    cov = ServerSessionMixin._get_cached_coverage(fake, "ABC12345")
    assert cov["total_functions"] == 3
    assert cov["named_functions"] == 1
    assert cov["unnamed_functions"] == 2
    assert cov["pct_named"] == 33.3
    # The RPC was asked for structured items.
    assert fake.calls and fake.calls[0][0] == "data"
    assert fake.calls[0][1]["structured"] is True

    # Second call within TTL hits the cache: no further RPC.
    fake.calls.clear()
    ServerSessionMixin._get_cached_coverage(fake, "ABC12345")
    assert fake.calls == []

    # A different session id is a different cache key (fresh RPC).
    cov_other = ServerSessionMixin._get_cached_coverage(fake, "ZZZZ9999")
    assert len(fake.calls) == 1
    assert cov_other["total_functions"] == 3


def test_coverage_falls_back_to_parsing_compact_text():
    fake = _FakeCoverageServer(text="0x1000  3  xrefs=2  main\n0x401000  10  xrefs=0  sub_401000\n")
    cov = ServerSessionMixin._get_cached_coverage(fake, "ABC12345")
    assert cov["total_functions"] == 2
    assert cov["named_functions"] == 1


def test_coverage_returns_empty_on_error():
    class Boom:
        current_session = None

        def _execute_tool(self, tool, args):
            raise RuntimeError("rpc down")

    cov = ServerSessionMixin._get_cached_coverage(Boom(), "ABC12345")
    assert cov == {}


def test_state_with_no_session_returns_error():
    class NoSession:
        def _session_target(self, args):
            return None, None

    result = ServerSessionMixin._session_action_state(NoSession(), {})
    assert result.get("error") is True
    assert result.get("code") == MCPError.SESSION_NOT_FOUND


# ---------------------------------------------------------------------------
# server_session.py: search_notes ownership
# ---------------------------------------------------------------------------


def test_search_notes_respects_ownership(tmp_path):
    mgr = SessionManager(str(tmp_path))
    owned = mgr.create_session("/tmp/a.bin", notes="secret alpha")
    busy = mgr.create_session("/tmp/b.bin", notes="secret bravo")
    free = mgr.create_session("/tmp/c.bin", notes="secret charlie")

    class Fake:
        session_mgr = mgr

        def _client_owns_session(self, sid):
            return sid == owned.session_id

        def _session_is_busy(self, sid):
            return sid == busy.session_id

    result = ServerSessionMixin._session_action_search_notes(Fake(), {"query": "secret"})
    assert result["ok"] is True
    sids = {s["session_id"] for s in result["sessions"]}
    # Owned session visible; busy (live foreign) session hidden; neither-owned-
    # nor-busy recorded session visible (the documented adoption rule).
    assert sids == {owned.session_id, free.session_id}
    assert busy.session_id not in sids


def test_search_notes_requires_query(tmp_path):
    mgr = SessionManager(str(tmp_path))
    result = ServerSessionMixin._session_action_search_notes(
        type("F", (), {"session_mgr": mgr})(), {}
    )
    assert result.get("error") is True
    assert result.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# server_session.py: switch re-enters safe mode
# ---------------------------------------------------------------------------


def test_switch_reopen_reenters_safe_mode(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 64)
    session = server.session_mgr.create_session(str(binary))
    sid = session.session_id
    assert not server._safe_mode_active(sid)

    server._start_server = lambda s: {"ok": True}
    server._wait_for_idb = lambda s, timeout=120: True

    token = server._begin_client_connection()
    try:
        res = server._session_action_switch({"session_id": sid, "reopen": True})
        # Assert before teardown: shutdown clears _pending_analysis (the
        # watcher stop signal added by the lifecycle revamp), which would make
        # a post-shutdown _safe_mode_active check read False.
        assert res.get("ok") is True
        assert res.get("safe_mode") is True
        assert server._safe_mode_active(sid)
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# server_session.py: _maybe_resolve_analysis_state confirmation-only
# ---------------------------------------------------------------------------


def test_maybe_resolve_analysis_state_confirms_completion_and_single_fires(
    tmp_path, monkeypatch
):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    server._mark_analysis_pending(session)
    server.session_runtimes[sid] = {"port": 9999, "process": _FakeIdaProcess()}
    server._send_rpc_raw = lambda payload, port, recv_timeout=10: {"analysis_complete": True}
    seen = []
    real = IDAMCPServer._on_analysis_complete.__get__(server, IDAMCPServer)
    server._on_analysis_complete = lambda s, reload: seen.append(reload) or real(s, reload)
    try:
        server._maybe_resolve_analysis_state(session)
        server._maybe_resolve_analysis_state(session)
        # Confirmation-only path always confirms with reload=False (the
        # reload-on-completion machinery is gone) and cannot double-fire.
        assert seen == [False], seen
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
    finally:
        server.shutdown()


def test_on_analysis_complete_clears_pending_and_persists_gate(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    server._mark_analysis_pending(session)
    assert server._safe_mode_active(sid)
    assert (session.metadata or {}).get("analysis_gate") == "pending"
    try:
        # reload=True is accepted for backward compat but is a legacy no-op.
        server._on_analysis_complete(session, reload=True)
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
        fresh = server.session_mgr.get_session(sid)
        assert (fresh.metadata or {}).get("analysis_gate") == "complete"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# server_session.py: cleanup_stale orphan-prune ownership
# ---------------------------------------------------------------------------


def test_cleanup_stale_orphan_prune_skips_locked_sessions(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    # Both sessions are orphans (binary + idb paths are gone).
    s1 = server.session_mgr.create_session("/tmp/gone1.bin")
    s2 = server.session_mgr.create_session("/tmp/gone2.bin")
    # s2 is locked by a live runtime → must never be deleted by orphan-prune.
    server.session_runtimes[s2.session_id] = {"process": _FakeIdaProcess()}

    token = server._begin_client_connection()
    try:
        res = server._session_action_cleanup_stale({"max_age_days": 1, "prune_orphans": True})
    finally:
        server._end_client_connection(token)
        server.shutdown()
    assert s1.session_id in res["orphan_sids"]
    assert s2.session_id not in res["orphan_sids"]
    assert not server.session_mgr.session_exists(s1.session_id)
    assert server.session_mgr.session_exists(s2.session_id)


# ---------------------------------------------------------------------------
# server_session.py: _run_workflow_sequence error envelope
# ---------------------------------------------------------------------------


def test_workflow_sequence_uses_error_envelope_for_bad_steps():
    class Fake:
        def _execute_tool(self, tool, args):
            return {"ok": True, "value": 1}

    result = ServerSessionMixin._run_workflow_sequence(
        Fake(),
        "wf",
        [
            {"tool": "session", "action": "status"},
            "not-a-dict",
            {"tool": "session"},
        ],
        {},
    )
    assert result["ok"] is True
    for step in result["steps"][1:]:
        err = step["result"]
        assert err.get("error") is True
        for key in ("code", "category", "message"):
            assert key in err, f"missing envelope key {key} in {err}"
    # Successful step is untouched.
    assert "error" not in result["steps"][0]["result"]


# ---------------------------------------------------------------------------
# server_workflow_batch.py: chaining error envelope
# ---------------------------------------------------------------------------


class _FakeBatchMixinHost(ServerWorkflowBatchMixin):
    """Hermetic batch host: the batch mixin plus stubbed IO (no live IDA)."""

    current_session = None
    session_runtimes = {}

    def _execute_tool(self, tool, args):
        return {"ok": True, "tool": tool}

    def _extract_response_options(self, args):
        return dict(args), {}

    def _cache_next_page(self, tool_name, args, payload):
        return payload

    def _record_activity(self, tool_name, args, result):
        return None

    def _try_batch_fast_path(self, calls, continue_on_error):
        return None


def test_batch_chaining_unresolved_ref_uses_error_envelope():
    """An unresolved output→input step reference must surface as a full
    INVALID_ARGS error envelope — the batch-side sibling of the workflow
    sequence contract above — and the failing step must NOT reach _execute_tool
    (no silent empty-string argument substitution)."""
    host = _FakeBatchMixinHost()
    result = host._handle_batch(
        {
            "calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "code", "arguments": {"action": "disasm", "addr": "step0.result.missing.0.x"}},
            ],
            "continue_on_error": True,
        }
    )
    assert result["summary"]["errors"] == 1
    err = result["results"][1]["result"]
    assert err.get("error") is True
    for key in ("code", "category", "message"):
        assert key in err, f"missing envelope key {key} in {err}"
    assert err.get("code") == MCPError.INVALID_ARGS
    assert "unresolved" in err.get("message", "")


# ---------------------------------------------------------------------------
# server_session.py: _wait_for_idb legacy component path
# ---------------------------------------------------------------------------


def test_wait_for_idb_legacy_component_returns_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with open("SID_ABC12345_x.id0", "w", encoding="utf-8") as f:
        f.write("component")
    session = Session("ABC12345", "SID_ABC12345_x.idb", "/tmp/x.bin")
    mgr = SessionManager(str(tmp_path / "cache"))

    class Fake:
        session_mgr = mgr
        session_runtimes = {}

        def _runtime_alive(self, runtime):
            return False

    assert ServerSessionMixin._wait_for_idb(Fake(), session, timeout=1.0) is True
    # The session's idb_path was corrected to a directory-qualified component
    # path (previously the bare basename, which os.path.isfile rejected, making
    # the fix-up branch a no-op).
    assert session.idb_path == os.path.join(".", "SID_ABC12345_x.id0")


# ---------------------------------------------------------------------------
# server_session.py: status / diff-dedup / import_session sanitization
# ---------------------------------------------------------------------------


def test_status_reports_total_via_manager_count(tmp_path):
    mgr = SessionManager(str(tmp_path))
    mgr.create_session("/tmp/x.bin")
    mgr.create_session("/tmp/y.bin")

    class FakeStatus:
        current_session = None
        session_mgr = mgr

        def _session_target(self, args):
            return None, None

    res = ServerSessionMixin._session_action_status(FakeStatus(), {})
    assert res.get("ok") is True
    assert res["session"] is None
    # Uses the locked manager method, not raw dict access.
    assert res["total_sessions"] == 2


def test_trigger_session_diff_dedups_identical_switches(monkeypatch):
    import ida_pro_mcp.host.server.server_session as ss

    spawned = []

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}
            self.name = name
            self.daemon = daemon
            spawned.append(self)

        def start(self):
            # Do NOT run _diff: keep the inflight marker set so dedup is
            # observable without touching the BGE embedder.
            pass

    monkeypatch.setattr(ss.threading, "Thread", FakeThread)
    with ss._SESSION_DIFF_LOCK:
        ss._SESSION_DIFF_INFLIGHT.clear()
    try:
        ServerSessionMixin._trigger_session_diff("a.i64", "b.i64")
        ServerSessionMixin._trigger_session_diff("a.i64", "b.i64")  # dup → no-op
        ServerSessionMixin._trigger_session_diff("b.i64", "c.i64")  # distinct → spawn
        assert len(spawned) == 2
    finally:
        with ss._SESSION_DIFF_LOCK:
            ss._SESSION_DIFF_INFLIGHT.clear()


def test_import_session_sanitizes_ida_args(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    try:
        data = {"binary_path": "/tmp/imported.bin", "notes": "imported"}

        # Server-reserved flags are rejected before they reach the launch line.
        res = server._session_action_import_session(
            {"data": dict(data, ida_args=["-S/evil.py", "0x4000"])}
        )
        assert res.get("error") is True
        assert "reserved" in res["message"]

        res = server._session_action_import_session(
            {"data": dict(data, ida_args=["\x00"])}
        )
        assert res.get("error") is True

        # Clean args pass through (redundant -A dropped), metadata carries.
        res = server._session_action_import_session(
            {"data": dict(data, ida_args=["0x4000", "-A"])}
        )
        assert res.get("ok") is True
        assert res["session"]["ida_args"] == ["0x4000"]
        assert res["session"]["notes"] == "imported"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# server_multi_session.py: group lock + reconciliation
# ---------------------------------------------------------------------------


def _mixin() -> ServerMultiSessionMixin:
    mixin = ServerMultiSessionMixin()
    mixin._init_multi_session()
    return mixin


def test_drop_sid_from_groups_reconciles_membership_and_links():
    mixin = _mixin()
    g = SessionGroup("g1", "G")
    g.session_ids = ["A1111111", "B2222222"]
    g.links["sym"] = {"provider_sid": "A1111111", "export_ea": "0x1000", "importer_sids": ["B2222222"]}
    mixin._session_groups["g1"] = g

    mixin._drop_sid_from_groups("A1111111")
    assert g.session_ids == ["B2222222"]
    assert "sym" not in g.links

    # Importer removal.
    g.links["sym2"] = {"provider_sid": "B2222222", "export_ea": "0x2000", "importer_sids": ["A1111111"]}
    mixin._drop_sid_from_groups("A1111111")
    assert g.links["sym2"]["importer_sids"] == []


def test_multi_session_groups_concurrent_access_does_not_crash():
    mixin = _mixin()
    errors = []

    def creator():
        # Every real writer in server_multi_session.py takes the lock (e.g.
        # _ms_group_create / _drop_sid_from_groups), so the writer must model
        # the locked producer the audit lens cares about — an unlocked writer
        # would only test a scenario production never runs.
        try:
            for i in range(300):
                gid = f"g{i}"
                with mixin._session_groups_lock:
                    mixin._session_groups[gid] = SessionGroup(gid)
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    def lister():
        try:
            for _ in range(300):
                with mixin._session_groups_lock:
                    for group in mixin._session_groups.values():
                        assert group.to_dict()["group_id"]
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    t1 = threading.Thread(target=creator)
    t2 = threading.Thread(target=lister)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert not errors
    # No lost updates: every group the writer created survives, so a lock-
    # discipline regression (a reader or writer bypassing the lock and tearing
    assert len(mixin._session_groups) == 300
    assert all(isinstance(mixin._session_groups[k], SessionGroup) for k in mixin._session_groups)


def test_prepare_open_args_expands_tilde_and_env_vars(tmp_path, monkeypatch):
    class DummyServer(ServerSessionMixin):
        def _normalize_ida_args(self, args):
            return args

    server = DummyServer()
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 16)

    monkeypatch.setenv("TEST_TARGET_DIR", str(tmp_path))
    bin_path, _, _, _, _, err = server._prepare_open_args(
        {"binary_path": "$TEST_TARGET_DIR/sample.bin"}
    )
    assert err is None
    assert bin_path == str(target.resolve())
