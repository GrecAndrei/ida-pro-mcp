"""Regression tests for f02_session_handlers audit findings.

Covers the security/isolation and bookkeeping fixes applied to
``server_session.py``:
- session/get and session/list no longer expose a peer's session record.
- Declarative dict actions (rename/duplicate/archive/unarchive/tag/untag/
  add_note/clear_notes) and snapshot/restore_snapshot reject a live foreign
  session.
- session/update is ownership-guarded and whitelists its fields.
- cleanup_stale / idle_purge / bulk_delete honor ownership and forget the
  deleted session's safe-mode bookkeeping (_background_load_errors included).
- The safe-mode bookkeeping collections are mutated under a lock, so a
  concurrent check-then-act init cannot lose a session's pending marker.
- _trigger_session_diff discards its inflight pair even when the lazy import
  fails.
- rebuild re-enters safe mode when the spawn fails; _ensure_runtime_and_idb
  returns an error envelope so a failed spawn is distinguishable from
  'still starting'.
- session/logs honors explicit session_id/idb targeting; _sess_coerce_untag
  trims like _sess_coerce_tag; session/merge guards both ids and distinctness.
"""

from __future__ import annotations

import threading
from datetime import datetime

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive but cannot be killed.

    ``pid`` is above Linux's pid_max, so ``os.killpg`` on it raises
    ProcessLookupError/EINVAL and every kill path is a safe no-op.
    """

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    # test_restart_restores_pending_gate_from_background_open uses the
    # experimental background path; keep it reachable for the whole file.
    monkeypatch.setenv("IDA_MCP_BACKGROUND_OPEN", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    # Blocking create must not attempt a real idat launch in a unit test.
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _open(server: IDAMCPServer, binary_path: str) -> dict:
    """Open a session directly through the create action (records ownership)."""
    return server._session_action_create({"binary_path": binary_path})


def _restore_ensure_runtime_and_idb(server: IDAMCPServer, monkeypatch) -> None:
    """Re-bind the real _ensure_runtime_and_idb over _make_server's stub."""
    real = IDAMCPServer._ensure_runtime_and_idb.__get__(server, IDAMCPServer)
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", real)


def _open_two_isolated_clients(tmp_path, monkeypatch, server=None):
    """Return (server, sid_a, sid_b) with sid_a a live foreign (busy) session
    for the second connection, and sid_b owned by the second connection."""
    if server is None:
        server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    token_a = server._begin_client_connection()
    try:
        opened_a = _open(server, str(binary_a))
        sid_a = opened_a["session_id"]
    finally:
        # Drop A's connection state (keeps the session row and lets us mark it
        # busy) so B does not inherit ownership.
        server._client_request_state_var.reset(token_a)
    # A's session is actively running: it must stay protected from B.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        opened_b = _open(server, str(binary_b))
        sid_b = opened_b["session_id"]
        return server, token_b, sid_a, sid_b
    except Exception:
        server._end_client_connection(token_b)
        server.shutdown()
        raise


# ---------------------------------------------------------------------------
# session/get and session/list must not expose a peer's record
# ---------------------------------------------------------------------------


def test_session_get_rejects_live_foreign_session(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        denied = server._session_action_get({"session_id": sid_a})
        assert denied.get("error") is True
        assert denied.get("code") == MCPError.FILE_LOCKED

        allowed = server._session_action_get({"session_id": sid_b})
        assert allowed.get("ok") is True
        assert allowed["session"]["session_id"] == sid_b
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_session_list_hides_live_foreign_session(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        listing = server._session_action_list({})
        sids = {s["session_id"] for s in listing["sessions"]}
        assert sid_b in sids
        assert sid_a not in sids
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_session_list_shows_unbusy_foreign_session(tmp_path, monkeypatch):
    """The documented adoption rule: a recorded session nobody is running is
    visible (same policy search_notes applies)."""
    server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    token_a = server._begin_client_connection()
    try:
        opened_a = _open(server, str(binary_a))
        sid_a = opened_a["session_id"]
    finally:
        server._client_request_state_var.reset(token_a)
    # No runtime: A's session is unbusy/adoptable, not live-foreign.

    token_b = server._begin_client_connection()
    try:
        opened_b = _open(server, str(binary_b))
        sid_b = opened_b["session_id"]
        listing = server._session_action_list({})
        sids = {s["session_id"] for s in listing["sessions"]}
        assert sid_b in sids
        assert sid_a in sids  # unbusy foreign session is listed
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# Declarative dict actions + snapshot/restore_snapshot ownership
# ---------------------------------------------------------------------------


def test_declarative_mutations_reject_live_foreign_session(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        cases = [
            {"action": "rename", "session_id": sid_a, "name": "n"},
            {"action": "duplicate", "session_id": sid_a},
            {"action": "archive", "session_id": sid_a},
            {"action": "unarchive", "session_id": sid_a},
            {"action": "tag", "session_id": sid_a, "tag": "x"},
            {"action": "untag", "session_id": sid_a, "tag": "x"},
            {"action": "add_note", "session_id": sid_a, "note": "x"},
            {"action": "clear_notes", "session_id": sid_a},
            {"action": "snapshot", "session_id": sid_a},
            {"action": "restore_snapshot", "session_id": sid_a, "snapshot_id": "s"},
        ]
        for args in cases:
            res = server._handle_session(args)
            assert res.get("error") is True, f"{args['action']} should be denied"
            assert res.get("code") == MCPError.FILE_LOCKED, (
                f"{args['action']} expected FILE_LOCKED, got {res.get('code')}"
            )
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_declarative_mutations_work_on_owned_session(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        tagged = server._handle_session({"action": "tag", "session_id": sid_b, "tag": "mine"})
        assert tagged.get("ok") is True
        assert "mine" in tagged["session"]["tags"]

        named = server._handle_session({"action": "rename", "session_id": sid_b, "name": "Renamed"})
        assert named.get("ok") is True
        assert named["session"]["auto_name"] == "Renamed"

        noted = server._handle_session({"action": "add_note", "session_id": sid_b, "note": "hello"})
        assert noted.get("ok") is True
        assert "hello" in noted["session"]["notes"]
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# session/update: ownership + field whitelist
# ---------------------------------------------------------------------------


def test_update_rejects_foreign_and_unknown_fields(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        # Ownership guard fires before the field whitelist.
        denied = server._session_action_update({"session_id": sid_a, "notes": "x"})
        assert denied.get("error") is True
        assert denied.get("code") == MCPError.FILE_LOCKED

        # Launch-critical fields must not be rewriteable through update.
        bad = server._session_action_update({"session_id": sid_b, "idb_path": "/tmp/x"})
        assert bad.get("error") is True
        assert bad.get("code") == MCPError.INVALID_ARGS
        assert "idb_path" in bad.get("message", "")

        ok = server._session_action_update(
            {"session_id": sid_b, "notes": "hello", "phase": "reporting", "name": "MyBin"}
        )
        assert ok.get("ok") is True
        sess = server.session_mgr.get_session(sid_b)
        assert sess.notes == "hello"
        assert sess.phase == "reporting"
        assert sess.auto_name == "MyBin"

        nothing = server._session_action_update({"session_id": sid_b})
        assert nothing.get("error") is True
        assert nothing.get("code") == MCPError.INVALID_ARGS
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# session/merge: ownership on both ids + distinctness
# ---------------------------------------------------------------------------


def test_merge_guards_ownership_and_distinctness(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary_a = tmp_path / "a.bin"
    binary_b = tmp_path / "b.bin"
    binary_c = tmp_path / "c.bin"
    binary_a.write_bytes(b"a")
    binary_b.write_bytes(b"b")
    binary_c.write_bytes(b"c")

    token_a = server._begin_client_connection()
    try:
        opened_a = _open(server, str(binary_a))
        sid_a = opened_a["session_id"]
    finally:
        server._client_request_state_var.reset(token_a)
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        opened_b = _open(server, str(binary_b))
        sid_b = opened_b["session_id"]
        opened_c = _open(server, str(binary_c))
        sid_c = opened_c["session_id"]

        same = server._session_action_merge({"session_id": sid_b, "source_id": sid_b})
        assert same.get("error") is True
        assert same.get("code") == MCPError.INVALID_ARGS

        foreign = server._session_action_merge({"session_id": sid_a, "source_id": sid_b})
        assert foreign.get("error") is True
        assert foreign.get("code") == MCPError.FILE_LOCKED

        merged = server._session_action_merge({"session_id": sid_b, "source_id": sid_c})
        assert merged.get("ok") is True
        assert merged["session"]["session_id"] == sid_b
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# cleanup_stale / idle_purge: ownership + safe-mode bookkeeping cleanup
# ---------------------------------------------------------------------------


def test_cleanup_stale_age_delete_respects_ownership(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        old = datetime(2000, 1, 1, 0, 0, 0)
        server.session_mgr.sessions[sid_a].last_accessed = old
        server.session_mgr.sessions[sid_b].last_accessed = old
        server._spawn_analysis_watcher = lambda sid: None
        server._pending_analysis = {sid_b}
        server._background_load_errors = {sid_b: {"error": True, "message": "x"}}
        # NB: must NOT go through get_session() — it calls update_access() and
        # resets last_accessed, defeating the age override above.
        server.current_session = server.session_mgr.sessions[sid_b]

        res = server._session_action_cleanup_stale(
            {"max_age_days": 1, "prune_orphans": False}
        )
        assert sid_b in res["deleted_sids"]
        assert sid_a not in res["deleted_sids"]
        assert not server.session_mgr.session_exists(sid_b)
        assert server.session_mgr.session_exists(sid_a)
        # current_session cleared + analysis bookkeeping forgotten.
        assert server.current_session is None
        assert not server._safe_mode_active(sid_b)
        assert sid_b not in server._background_load_errors
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_idle_purge_forgets_analysis_state(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "idle.bin"
    binary.write_bytes(b"idle")
    token = server._begin_client_connection()
    try:
        opened = _open(server, str(binary))
        sid = opened["session_id"]
        server.session_runtimes[sid] = {"process": _FakeIdaProcess()}
        server.session_mgr.sessions[sid].last_accessed = datetime(2000, 1, 1)
        server._spawn_analysis_watcher = lambda s: None
        server._pending_analysis = {sid}
        server._background_load_errors = {sid: {"error": True, "message": "x"}}

        res = server._session_action_idle_purge({"idle_seconds": 1})
        assert sid in res["closed_sids"]
        assert not server.session_mgr.session_exists(sid)
        assert not server._safe_mode_active(sid)
        assert sid not in server._background_load_errors
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_forget_analysis_state_clears_background_load_errors(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    server._pending_analysis = {sid}
    server._background_load_errors = {sid: {"error": True, "message": "boom"}}
    server._analysis_complete_in_flight = {sid}
    try:
        server._forget_analysis_state(sid)
        assert not server._safe_mode_active(sid)
        assert sid not in server._background_load_errors
        assert sid not in server._analysis_complete_in_flight
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Safe-mode bookkeeping lock (concurrent check-then-act init)
# ---------------------------------------------------------------------------


def test_safe_mode_bookkeeping_lock_keeps_all_pending_sessions(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    # Force the lazy-init path every thread races on.
    if hasattr(server, "_pending_analysis"):
        del server._pending_analysis
    if hasattr(server, "_analysis_complete_sessions"):
        del server._analysis_complete_sessions
    sessions = [
        server.session_mgr.create_session(f"/tmp/con{i}.bin") for i in range(16)
    ]
    sids = [s.session_id for s in sessions]
    monkeypatch.setattr(server, "_spawn_analysis_watcher", lambda sid: None)
    barrier = threading.Barrier(len(sessions))

    def mark(session):
        barrier.wait(timeout=5)
        server._mark_analysis_pending(session)

    threads = [threading.Thread(target=mark, args=(s,)) for s in sessions]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert not any(t.is_alive() for t in threads)

    pending = server._pending_analysis
    assert isinstance(pending, set)
    assert set(sids) <= pending, "a concurrent init lost a pending marker"
    for sid in sids:
        assert server._safe_mode_active(sid)
    server.shutdown()


# ---------------------------------------------------------------------------
# _trigger_session_diff: inflight pair discarded even when the lazy import fails
# ---------------------------------------------------------------------------


def test_session_diff_inflight_discarded_on_import_error(tmp_path, monkeypatch):
    import ida_pro_mcp.host.server.server_session as ss

    server = _make_server(tmp_path, monkeypatch)
    real_import = __import__

    def _broken_import(name, *a, **k):
        if name.startswith("ida_pro_mcp.host.intelligence"):
            raise ImportError("no intelligence modules in a minimal install")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", _broken_import)
    class _InlineThread:
        def __init__(self, target, args=(), kwargs=None, **_options):
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self):
            self._target(*self._args, **self._kwargs)

    monkeypatch.setattr(ss.threading, "Thread", _InlineThread)
    pair = ("/old/x.i64", "/new/x.i64")
    ss._SESSION_DIFF_INFLIGHT.discard(pair)
    try:
        server._trigger_session_diff(*pair)
        assert pair not in ss._SESSION_DIFF_INFLIGHT
    finally:
        ss._SESSION_DIFF_INFLIGHT.discard(pair)
        server.shutdown()


# ---------------------------------------------------------------------------
# rebuild: spawn failure re-enters safe mode
# ---------------------------------------------------------------------------


def test_rebuild_reenters_safe_mode_when_spawn_fails(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "rebuild.bin"
    binary.write_bytes(b"\x00" * 64)
    token = server._begin_client_connection()
    try:
        opened = _open(server, str(binary))
        sid = opened["session_id"]

        def _fail_start(session):
            return {"error": True, "code": "IDA_CRASHED", "message": "idat refused"}

        monkeypatch.setattr(server, "_start_server", _fail_start)
        monkeypatch.setattr(server, "_spawn_analysis_watcher", lambda sid: None)
        res = server._session_action_rebuild({"session_id": sid})
        assert res.get("error") is True
        assert res.get("code") == MCPError.IDA_CRASHED
        assert res.get("safe_mode") is True
        assert server._safe_mode_active(sid)
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# _ensure_runtime_and_idb: a failed spawn is an error, not silent success
# ---------------------------------------------------------------------------


def test_ensure_runtime_and_idb_returns_error_on_spawn_failure(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _restore_ensure_runtime_and_idb(server, monkeypatch)
    session = server.session_mgr.create_session("/tmp/z.bin")
    sid = session.session_id

    def _fail_start(s):
        return {"error": True, "code": "IDA_CRASHED", "message": "boom"}

    monkeypatch.setattr(server, "_start_server", _fail_start)
    try:
        err = server._ensure_runtime_and_idb(session)
        assert isinstance(err, dict)
        assert err.get("error") is True
        assert err.get("code") == MCPError.IDA_CRASHED
        assert err.get("session_id") == sid
    finally:
        server.shutdown()


def test_create_surfaces_spawn_error(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    _restore_ensure_runtime_and_idb(server, monkeypatch)
    binary = tmp_path / "spawn.bin"
    binary.write_bytes(b"\x00" * 64)

    def _fail_start(session):
        return {"error": True, "code": "IDA_CRASHED", "message": "no idat available"}

    monkeypatch.setattr(server, "_start_server", _fail_start)
    monkeypatch.setattr(server, "_spawn_analysis_watcher", lambda sid: None)
    token = server._begin_client_connection()
    try:
        res = server._session_action_create({"binary_path": str(binary)})
        assert res.get("ok") is True
        assert res.get("spawn_error") is not None
        assert res["spawn_error"].get("error") is True
        assert res.get("safe_mode") is True
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# session/logs targeting + untag coercion
# ---------------------------------------------------------------------------


def test_logs_targets_explicit_session_and_rejects_foreign(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        server.session_runtimes[sid_b] = {
            "process": _FakeIdaProcess(),
            "ida_log": None,
            "stdout_log": None,
            "stderr_log": None,
        }
        # Owned session: logs resolves to it even without naming it.
        res = server._session_action_logs({})
        assert res.get("ok") is True
        assert res["session_id"] == sid_b

        # Live foreign session: rejected by the ownership guard.
        denied = server._session_action_logs({"session_id": sid_a})
        assert denied.get("error") is True
        assert denied.get("code") == MCPError.FILE_LOCKED
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_untag_rejects_whitespace_only_tag(tmp_path, monkeypatch):
    server, token_b, sid_a, sid_b = _open_two_isolated_clients(tmp_path, monkeypatch)
    try:
        res = server._handle_session({"action": "untag", "session_id": sid_b, "tag": "   "})
        assert res.get("error") is True
        assert res.get("code") == MCPError.INVALID_ARGS
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


# ---------------------------------------------------------------------------
# Restart gate-restore: the REAL startup path rehydrates the analysis gate
# ---------------------------------------------------------------------------
# _make_server constructs IDAMCPServer() directly, so its __init__ runs the
# startup gate restoration. A session left 'pending' by a previous host
# instance must come back in safe mode; a 'complete' one comes back ungated.


def test_restart_restores_pending_gate_into_safe_mode(tmp_path, monkeypatch):
    binary = tmp_path / "restart.bin"
    binary.write_bytes(b"\x00" * 64)

    server1 = _make_server(tmp_path, monkeypatch)
    token = server1._begin_client_connection()
    try:
        opened = _open(server1, str(binary))
        sid = opened["session_id"]
        assert server1._safe_mode_active(sid)
    finally:
        server1._end_client_connection(token)
        server1.shutdown()

    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._safe_mode_active(sid) is True, (
            "metadata analysis_gate='pending' must restore safe mode after restart"
        )
        assert server2._analysis_is_complete(sid) is False
    finally:
        server2.shutdown()


def test_restart_restores_pending_gate_from_background_open(tmp_path, monkeypatch):
    """The background-open path also persists a pending gate that survives a
    host restart (the D3-F1 half-analyzed-IDB case)."""
    binary = tmp_path / "restart-bg.bin"
    binary.write_bytes(b"\x00" * 64)

    server1 = _make_server(tmp_path, monkeypatch)
    token = server1._begin_client_connection()
    try:
        opened = server1._session_action_create_background({"binary_path": str(binary)})
        sid = opened["session_id"]
        assert opened.get("safe_mode") is True
    finally:
        server1._end_client_connection(token)
        server1.shutdown()

    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._safe_mode_active(sid) is True
        assert server2._analysis_is_complete(sid) is False
    finally:
        server2.shutdown()


def test_restart_restores_complete_gate_ungated(tmp_path, monkeypatch):
    binary = tmp_path / "restart-done.bin"
    binary.write_bytes(b"\x00" * 64)

    server1 = _make_server(tmp_path, monkeypatch)
    session = server1.session_mgr.create_session(str(binary))
    sid = session.session_id
    server1._mark_analysis_complete(session)
    server1.shutdown()

    server2 = _make_server(tmp_path, monkeypatch)
    try:
        assert server2._analysis_is_complete(sid) is True
        assert server2._safe_mode_active(sid) is False
    finally:
        server2.shutdown()
