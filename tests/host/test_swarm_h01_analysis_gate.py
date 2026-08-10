"""Swarm h01: safe-mode / analysis-gate lifecycle regression tests.

Pins the coherent lifecycle core in server_session.py:

- Per-session gate persisted through ``session.metadata['analysis_gate']``
  ('pending'/'complete'), idempotent, lock-guarded.
- ``_watch_analysis_completion`` is spawn-race-proof (a runtime that never
  registered is NOT an interruption), requires TWO consecutive
  analysis_complete=True polls before lifting, records a background_error when
  a runtime that WAS seen alive dies while the gate is pending (never lifts
  from a dead runtime), has no deadline, and re-arms instead of leaving a
  still-pending session watcher-less (without spinning on a recorded error).
- ``_on_analysis_complete`` is idempotent (single notice / single transition),
  ``reload`` is a legacy no-op, and it refuses closing/deleted sessions.
- ``_maybe_resolve_analysis_state`` is confirmation-only (never spawns/kills).
- ``_ensure_runtime_and_idb`` propagates ``_wait_for_idb`` failures as an error
  envelope instead of returning None with no IDB.
- ``_session_action_close`` marks the session closing before teardown and
  clears the marker after deletion.
- create_background attaches the same optional open envelope (idb_exists,
  is_running, architecture_recommendations, spawn_error) as blocking create.

Standalone tests — NO live IDA. ``_FakeIdaProcess`` stands in for the idat
subprocess (always alive until removed from ``session_runtimes``).
"""

from __future__ import annotations

import os
import time

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer


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
    # Background-open tests here (create_background / _attach_open_envelope) are
    # behind the experimental opt-in flag.
    monkeypatch.setenv("IDA_MCP_BACKGROUND_OPEN", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    # Never actually spawn idat; the caller seeds session_runtimes / scripts
    # _send_rpc_raw to drive the watcher deterministically.
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    # A fast, deterministic watcher cadence (the poll floor honors this).
    server.safe_mode_poll_seconds = 0.05
    return server


def _fake_runtime() -> dict:
    return {"port": 9999, "process": _FakeIdaProcess()}


# ---------------------------------------------------------------------------
# Gate persistence
# ---------------------------------------------------------------------------


def test_gate_persists_pending_then_complete_through_metadata(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/gate.bin")
    sid = session.session_id
    try:
        server._mark_analysis_pending(session)
        assert server._safe_mode_active(sid)
        assert not server._analysis_is_complete(sid)
        assert (session.metadata or {}).get("analysis_gate") == "pending"
        # Read back through the manager: the gate survives a disk round-trip.
        assert (server.session_mgr.get_session(sid).metadata or {}).get(
            "analysis_gate"
        ) == "pending"
        # The spawn guard keeps a single watcher across repeated entries.
        assert server._analysis_watchers == {sid}
        server._mark_analysis_pending(session)
        assert server._analysis_watchers == {sid}

        server._mark_analysis_complete(session)
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
        assert (session.metadata or {}).get("analysis_gate") == "complete"
        assert (server.session_mgr.get_session(sid).metadata or {}).get(
            "analysis_gate"
        ) == "complete"
        # Complete is idempotent.
        server._mark_analysis_complete(session)
        assert server._analysis_is_complete(sid)
    finally:
        server.shutdown()


def test_mark_pending_clears_stale_spawn_error(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/stale.bin")
    sid = session.session_id
    try:
        # A prior spawn failure is invalidated by re-entering pending: the
        # fresh spawn is the authoritative writer (D1-F12).
        server._background_load_errors = {
            sid: {"error": True, "code": "IDA_CRASHED", "message": "stale"}
        }
        server._mark_analysis_pending(session)
        assert sid not in server._background_load_errors
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Watcher: N=2 consecutive complete polls
# ---------------------------------------------------------------------------


def test_watcher_requires_two_consecutive_complete_polls(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/watcher2.bin")
    sid = session.session_id
    server.session_runtimes[sid] = _fake_runtime()
    # Poll 1: a single True must NOT lift the gate (AU_NONE pre-queue window).
    # Poll 2: resets the consecutive counter. Polls 3-4 lift it.
    sequence = [
        {"analysis_complete": True},
        {"analysis_complete": False},
        {"analysis_complete": True},
        {"analysis_complete": True},
    ]
    state = {"i": 0}

    def rpc(payload, port, recv_timeout=10):
        i = state["i"]
        state["i"] += 1
        return sequence[min(i, len(sequence) - 1)]

    server._send_rpc_raw = rpc
    try:
        server._mark_analysis_pending(session)
        deadline = time.time() + 8
        while time.time() < deadline and server._safe_mode_active(sid):
            time.sleep(0.02)
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
        # If a single True had lifted the gate, the watcher would have exited
        # after the first poll; reaching poll 4 proves the consecutive-count.
        assert state["i"] >= 4, f"expected >=4 polls, got {state['i']}"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Watcher: interruption vs never-registered runtime
# ---------------------------------------------------------------------------


def test_watcher_reports_interruption_when_seen_runtime_dies(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/dead.bin")
    sid = session.session_id
    spawned = []
    real_spawn = IDAMCPServer._spawn_analysis_watcher.__get__(
        server, IDAMCPServer
    )
    server._spawn_analysis_watcher = lambda s: spawned.append(s) or real_spawn(s)
    server.session_runtimes[sid] = _fake_runtime()
    try:
        server._mark_analysis_pending(session)
        assert spawned == [sid]  # one watcher armed by the pending entry
        # Let the watcher observe the runtime alive (saw_runtime -> True).
        time.sleep(0.3)
        # Simulate the runtime dying while auto-analysis is still pending.
        server.session_runtimes.pop(sid, None)
        deadline = time.time() + 8
        while time.time() < deadline and sid not in getattr(
            server, "_background_load_errors", {}
        ):
            time.sleep(0.02)
        err = getattr(server, "_background_load_errors", {}).get(sid)
        assert err is not None
        assert err.get("error") is True
        assert err.get("code") == MCPError.IDA_CRASHED
        # Safe mode stays ON: a dead runtime never lifts the gate.
        assert server._safe_mode_active(sid)
        assert not server._analysis_is_complete(sid)
        # The watcher exits after recording the error and does NOT re-arm
        # (re-arming with the error recorded would spin forever).
        deadline = time.time() + 8
        while time.time() < deadline and sid in (server._analysis_watchers or set()):
            time.sleep(0.02)
        assert sid not in (server._analysis_watchers or set())
        assert spawned == [sid], spawned
    finally:
        server.shutdown()


def test_watcher_never_registered_runtime_is_not_an_interruption(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/noruntime.bin")
    sid = session.session_id
    try:
        server._mark_analysis_pending(session)
        # No runtime ever registers (spawn still in flight): keep polling,
        # do NOT record an interruption error, do NOT lift.
        time.sleep(0.3)
        assert sid not in getattr(server, "_background_load_errors", {})
        assert server._safe_mode_active(sid)
        # Lifting the gate lets the watcher exit cleanly on its next poll.
        server._mark_analysis_complete(session)
        deadline = time.time() + 8
        while time.time() < deadline and sid in (server._analysis_watchers or set()):
            time.sleep(0.02)
        assert sid not in (server._analysis_watchers or set())
    finally:
        server.shutdown()


def test_watcher_rearms_when_session_still_pending_on_exit(tmp_path, monkeypatch):
    """D1-F3: a watcher exiting while the session is still pending must not
    leave it watcher-less (the pending re-entry raced the exit)."""
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/rearm.bin")
    sid = session.session_id
    server._pending_analysis = {sid}
    spawned = []
    server._spawn_analysis_watcher = spawned.append

    calls = {"n": 0}

    def flaky_safe_mode(s):
        # Sample 1 (loop top) sees the gate lifted and returns; sample 2
        # (finally, after the pending re-entry) sees it active again.
        calls["n"] += 1
        return calls["n"] >= 2

    server._safe_mode_active = flaky_safe_mode
    try:
        server._watch_analysis_completion(sid)
        assert calls["n"] >= 2
        assert spawned == [sid], spawned
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# _on_analysis_complete: idempotency and closed/deleted refusal
# ---------------------------------------------------------------------------


def test_on_analysis_complete_is_idempotent_single_notice(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/idem.bin")
    sid = session.session_id
    server._mark_analysis_pending(session)
    transitions = []
    real_mark = IDAMCPServer._mark_analysis_complete.__get__(
        server, IDAMCPServer
    )
    server._mark_analysis_complete = (
        lambda s: transitions.append(1) or real_mark(s)
    )
    try:
        server._on_analysis_complete(session, reload=False)
        server._on_analysis_complete(session, reload=False)  # must no-op
        assert transitions == [1], transitions
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
        notice = (server._pending_session_notices or {}).get(sid)
        assert notice is not None
        assert notice["code"] == "analysis_complete"
        assert notice["message"] == "IDA auto-analysis completed."
    finally:
        server.shutdown()


def test_on_analysis_complete_skips_closing_session(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/closing.bin")
    sid = session.session_id
    server._mark_analysis_pending(session)
    server._begin_session_teardown(sid)
    try:
        server._on_analysis_complete(session, reload=False)
        # Refused: the session is mid-close, bookkeeping must not flip.
        assert server._safe_mode_active(sid)
        assert not server._analysis_is_complete(sid)
    finally:
        server.shutdown()


def test_on_analysis_complete_skips_deleted_session(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/deleted.bin")
    sid = session.session_id
    server._mark_analysis_pending(session)
    server.session_mgr.delete_session(sid)
    try:
        server._on_analysis_complete(session, reload=False)
        # No crash, no re-add of bookkeeping for the gone session.
        assert server._safe_mode_active(sid)
        assert not server._analysis_is_complete(sid)
        assert sid not in getattr(server, "_pending_session_notices", {})
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# _maybe_resolve_analysis_state: confirmation-only
# ---------------------------------------------------------------------------


def test_maybe_resolve_analysis_state_never_spawns_or_kills(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/confirm.bin")
    sid = session.session_id
    # Seed the gate directly so the (spawn-counting) wrappers below are only
    # exercised by _maybe_resolve_analysis_state itself, not by _mark_analysis_pending.
    server._pending_analysis = {sid}
    server.session_runtimes[sid] = _fake_runtime()
    server._send_rpc_raw = lambda payload, port, recv_timeout=10: {
        "analysis_complete": True
    }
    spawned, started, killed = [], [], []
    server._spawn_analysis_watcher = spawned.append
    server._start_server = lambda *a, **k: started.append(1) or None
    server._kill_process_tree = lambda *a, **k: killed.append(1) or None
    try:
        server._maybe_resolve_analysis_state(session)
        server._maybe_resolve_analysis_state(session)
        assert not server._safe_mode_active(sid)
        assert server._analysis_is_complete(sid)
        # Confirmation-only: never spawns, never kills.
        assert spawned == [], spawned
        assert started == [], started
        assert killed == [], killed
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Blocking-open wait: the default open blocks until analysis completes
# ---------------------------------------------------------------------------


def test_wait_for_analysis_complete_waits_then_confirms(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/blockwait.bin")
    sid = session.session_id
    # Seed the gate directly (not via _mark_analysis_pending) so no watcher
    # thread races the blocking wait for the shared rpc sequence.
    server._pending_analysis = {sid}
    server.session_runtimes[sid] = _fake_runtime()
    sequence = [
        {"analysis_complete": False},
        {"analysis_complete": False},
        {"analysis_complete": True, "functions": 42},
    ]
    state = {"i": 0}

    def rpc(payload, port, recv_timeout=10):
        i = state["i"]
        state["i"] = min(i + 1, len(sequence) - 1)
        return sequence[i]

    server._send_rpc_raw = rpc
    try:
        res = server._wait_for_analysis_complete(session, timeout=5.0)
        assert res.get("analysis_complete") is True
        assert res.get("analysis_functions") == 42
        # The blocking wait confirms and lifts safe mode itself.
        assert server._analysis_is_complete(sid)
        assert not server._safe_mode_active(sid)
        assert state["i"] >= 2, "should have polled until the True landed"
    finally:
        server.shutdown()


def test_wait_for_analysis_complete_no_runtime_returns_empty(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/nort.bin")
    # No live runtime: nothing to confirm, return immediately so the blocking
    # open does not stall and the async watcher keeps tracking the gate.
    res = server._wait_for_analysis_complete(session, timeout=5.0)
    assert res == {}
    assert not server._analysis_is_complete(session.session_id)


def test_wait_for_analysis_complete_timeout_returns_empty(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/timeout.bin")
    sid = session.session_id
    server._pending_analysis = {sid}
    server.session_runtimes[sid] = _fake_runtime()
    server._send_rpc_raw = lambda payload, port, recv_timeout=10: {
        "analysis_complete": False
    }
    try:
        res = server._wait_for_analysis_complete(session, timeout=0.2)
        assert res == {}
        # Never marked complete on a timeout; the gate stays pending.
        assert not server._analysis_is_complete(sid)
        assert server._safe_mode_active(sid)
    finally:
        server.shutdown()


def test_blocking_open_wait_confirms_and_clears_safe_mode(tmp_path, monkeypatch):
    """The blocking open calls _wait_for_analysis_complete and reflects it."""
    server = _make_server(tmp_path, monkeypatch)

    def _fake_wait(session, timeout=0.0):
        server._mark_analysis_complete(session)
        return {"analysis_complete": True, "analysis_functions": 7}

    monkeypatch.setattr(server, "_wait_for_analysis_complete", _fake_wait)
    binary = tmp_path / "block.bin"
    binary.write_bytes(b"\x00" * 256)
    try:
        out = server._session_action_create({"binary_path": str(binary)})
        assert out.get("ok") is True
        assert out.get("analysis_complete") is True
        assert out.get("analysis_functions") == 7
        assert out.get("safe_mode") is False
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# _ensure_runtime_and_idb: propagate failures as error envelopes
# ---------------------------------------------------------------------------


def test_ensure_runtime_and_idb_propagates_wait_for_idb_failure(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/waitidb.bin")
    sid = session.session_id
    server.session_runtimes[sid] = _fake_runtime()
    server._wait_for_idb = lambda s, timeout=120: False
    real = IDAMCPServer._ensure_runtime_and_idb.__get__(server, IDAMCPServer)
    try:
        err = real(session)
        assert err is not None
        assert err.get("error") is True
        assert err.get("code") == MCPError.IDA_CRASHED
        assert "IDB" in err.get("message", "")
        assert err.get("details", {}).get("session_id") == sid
    finally:
        server.shutdown()


def test_ensure_runtime_and_idb_propagates_start_server_failure(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/startfail.bin")
    sid = session.session_id
    server._start_server = lambda s: {
        "error": True,
        "code": "RUNTIME_ERROR",
        "message": "idat failed to launch",
    }
    real = IDAMCPServer._ensure_runtime_and_idb.__get__(server, IDAMCPServer)
    try:
        err = real(session)
        assert err is not None
        assert err.get("error") is True
        assert err.get("session_id") == sid
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# _spawn_runtime_background: spawn thread is the authoritative error writer
# ---------------------------------------------------------------------------


def test_spawn_runtime_background_records_error_and_skips_deleted(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    server._ensure_runtime_and_idb = lambda s: {
        "error": True,
        "code": MCPError.IDA_CRASHED,
        "message": "boom",
    }
    try:
        s1 = server.session_mgr.create_session("/tmp/bg1.bin")
        server._spawn_runtime_background(s1)
        deadline = time.time() + 5
        while time.time() < deadline and s1.session_id not in (
            server._background_load_errors or {}
        ):
            time.sleep(0.02)
        assert s1.session_id in (server._background_load_errors or {})

        # A session deleted while the spawn was in flight must not accumulate
        # an orphan error entry (D1-F12).
        s2 = server.session_mgr.create_session("/tmp/bg2.bin")
        sid2 = s2.session_id
        server.session_mgr.delete_session(sid2)
        server._spawn_runtime_background(s2)
        time.sleep(0.5)
        assert sid2 not in (server._background_load_errors or {})
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# create_background open envelope
# ---------------------------------------------------------------------------


def test_background_create_attaches_open_envelope(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "bg.bin"
    binary.write_bytes(b"\x00" * 256)
    try:
        out = server._session_action_create_background({"binary_path": str(binary)})
        assert out.get("ok") is True
        assert out.get("background") is True
        assert out.get("idb_exists") is False
        assert out.get("is_running") is False
        assert out.get("safe_mode") is True
        assert out.get("analysis_complete") is False
        assert "auto_backgrounded" not in out  # explicit call, not the auto route
        assert "spawn_error" not in out  # no prior spawn failure to surface
        assert "warning" not in out  # pinned fields, no top-level warning
    finally:
        server.shutdown()


def test_auto_backgrounded_create_keeps_pinned_fields(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "big.bin"
    binary.write_bytes(b"\x00" * 256)
    # _auto_backgrounded is the marker the large-binary routing sets before
    # delegating to create_background; it must surface with background+safe_mode.
    try:
        out = server._session_action_create_background(
            {"binary_path": str(binary), "_auto_backgrounded": True}
        )
        assert out.get("auto_backgrounded") is True
        assert out.get("background") is True
        assert out.get("safe_mode") is True
        assert "warning" not in out
    finally:
        server.shutdown()


def test_background_create_surfaces_preexisting_spawn_error(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    session = server.session_mgr.create_session("/tmp/env.bin")
    server._background_load_errors = {
        session.session_id: {"error": True, "code": MCPError.IDA_CRASHED, "message": "x"}
    }
    out = {"ok": True}
    try:
        server._attach_open_envelope(session, out, None)
        assert out["idb_exists"] is False
        assert out["is_running"] is False
        assert out["spawn_error"]["error"] is True
        assert out["safe_mode"] is False  # never entered pending in this test
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# _session_action_close: atomic closing marker
# ---------------------------------------------------------------------------


def test_close_sets_closing_marker_forgets_state_and_clears_marker(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    binary = tmp_path / "close.bin"
    binary.write_bytes(b"\x00" * 256)
    token = server._begin_client_connection()
    try:
        out = server._session_action_create({"binary_path": str(binary)})
        sid = out["session_id"]
        assert server._safe_mode_active(sid)
        # Seed extra bookkeeping the close must sweep.
        server._background_load_errors = {
            sid: {"error": True, "code": MCPError.IDA_CRASHED, "message": "x"}
        }
        res = server._session_action_close({"session_id": sid})
        assert res.get("ok") is True
        assert not server.session_mgr.session_exists(sid)
        assert not server._safe_mode_active(sid)
        assert sid not in (server._background_load_errors or {})
        # The close-in-progress flag was cleared after deletion so a later
        # re-open of the same path is not blocked by a stale marker.
        assert not server._session_is_closing(sid)
        assert sid not in (getattr(server, "_session_teardown", None) or set())
    finally:
        server._end_client_connection(token)
        server.shutdown()
