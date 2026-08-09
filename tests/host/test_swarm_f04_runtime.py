"""Regression tests for f04_runtime fixes in server_runtime.py.

Covers:
- apply-raises-during-start cleanup (no orphaned runtime / lease gap / fd leak)
- _cleanup_runtime pop-before-shutdown ordering (queue_timeout=0 kept alive)
- session close vs concurrent call_tool auto-restart (close tombstone)
- _launch_and_wait packed_idb guard on IDA_MCP_FORCE_PRE_ANALYSIS_OPTS
- reanalyze-only analysis_options honored without other actions
- oversized RPC payload -> RpcPayloadTooLarge / SIZE_LIMIT_EXCEEDED envelope
- _resolve_session_from_idb_ref basename ambiguity refused
"""

from __future__ import annotations

import io
import os
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_runtime import (
    RpcPayloadTooLarge,
    RpcQueueTimeout,
    ServerRuntimeMixin,
)

SID = "AB12CDEF"

# Above pid_max on typical hosts: killpg/kill are harmless no-ops.
FAKE_PID = 2147483647


class _FakeProc:
    pid = FAKE_PID

    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 1

    def wait(self, timeout=None):
        return 1


class _Host(ServerRuntimeMixin):
    """Minimal mixin instance that exercises runtime orchestration paths."""

    def __init__(self, tmp_path):
        self._runtime_lease_dir = str(tmp_path / "leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self._runtime_owner_id = "owner-x"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_startup_locks = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._session_teardown = set()
        self._activity_log = []
        self._activity_log_max = 4000
        self.cache_dir = str(tmp_path / "cache")
        self.ida_dir = None
        self.idat_exe = "/fake/ida/idat64"
        self.session_mgr = SimpleNamespace(
            _save_metadata=lambda s: None,
            get_session_artifact_dir=lambda sid, create=True: str(tmp_path / f"artifacts-{sid}"),
            get_session_log_dir=lambda sid, create=True: str(tmp_path / f"logs-{sid}"),
        )

    def _stop_analysis_watchdog(self, sid, join_timeout=0.5):
        pass

    @staticmethod
    def _runtime_alive(runtime):
        if not isinstance(runtime, dict):
            return False
        proc = runtime.get("process")
        if not proc:
            return False
        try:
            return proc.poll() is None
        except Exception:
            return False

    def _make_session(self, tmp_path, packed_idb=False, analysis_options=None):
        binary = tmp_path / f"{SID}_sample.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
        return SimpleNamespace(
            session_id=SID,
            binary_path=str(binary),
            idb_path=str(tmp_path / f"SID_{SID}_sample.bin.i64"),
            analysis_options=analysis_options or {},
            analysis_applied=False,
            packed_idb=packed_idb,
        )


def _make_log_handles(tmp_path):
    fh1 = open(str(tmp_path / "out.log"), "a", encoding="utf-8")
    fh2 = open(str(tmp_path / "err.log"), "a", encoding="utf-8")
    return fh1, fh2


def test_apply_exception_cleans_up_runtime_lease_and_fds(tmp_path, monkeypatch):
    """F04 finding 1: an exception out of _apply_session_options must tear down
    the registered runtime — close its log fds and release the lease — instead
    of leaving the runtime registered while _start_server drops ownership."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    monkeypatch.setattr(host, "_extract_library_init_failure", lambda diag: None)
    monkeypatch.setattr(host, "_is_orphan_locked_db_open_failure", lambda diag: False)
    monkeypatch.setattr(host, "_backup_idb", lambda idb_path: None)
    monkeypatch.setattr(host, "_nuclear_reset", lambda idb_path, aggressive=False: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda target: [])
    monkeypatch.setattr(server_runtime_mod.time, "sleep", lambda *a: None)
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *a, **k: {"ok": True})

    fh1, fh2 = _make_log_handles(tmp_path)
    registered = {}

    def _fake_launch(session, server_port, sanitize_env=False):
        registered["runtime"] = {
            "process": _FakeProc(alive=True),
            "port": 9999,
            "idb_path": session.idb_path,
            "log_handles": [fh1, fh2],
        }
        host.session_runtimes[session.session_id] = registered["runtime"]
        return {"ok": True, "idb_path": session.idb_path, "port": 9999}

    monkeypatch.setattr(host, "_launch_and_wait", _fake_launch)

    def _explode(session, runtime):
        raise ConnectionResetError("runtime died mid-apply")

    monkeypatch.setattr(host, "_apply_session_options", _explode)

    with pytest.raises(ConnectionResetError):
        host._attempt_session_recovery(session, "diag", 0)

    # The runtime was torn down: registry entry gone, fds closed, lease released.
    assert session.session_id not in host.session_runtimes
    assert fh1.closed and fh2.closed
    assert not os.path.exists(host._runtime_owner_path(SID))


def test_cleanup_sends_shutdown_before_popping_runtime(tmp_path, monkeypatch):
    """F04 finding 2: _cleanup_runtime must send the graceful shutdown RPC while
    the runtime is still in session_runtimes so _send_rpc_raw can resolve the
    per-runtime rpc_lock and honor queue_timeout=0 (fail fast on a busy lane)."""
    host = _Host(tmp_path)
    runtime = {
        "process": _FakeProc(alive=True),
        "port": 19999,
        "idb_path": str(tmp_path / "a.i64"),
        "rpc_lock": threading.Lock(),
        "log_handles": [],
        "auth_token": "tok",
    }
    host.session_runtimes[SID] = runtime
    # _start_server lazily creates the per-session startup lock; seed it the
    # same way so the retention assertion below is meaningful.
    host._session_startup_locks[SID] = threading.Lock()
    # Hold the lane busy so the shutdown RPC would queue forever if queue_timeout
    # were dead — it must fail fast instead.
    runtime["rpc_lock"].acquire()

    observed = {}

    def _recording_send(request, port, **kwargs):
        observed["still_registered"] = SID in host.session_runtimes
        observed["queue_timeout"] = kwargs.get("queue_timeout")
        raise RpcQueueTimeout("lane busy")

    monkeypatch.setattr(host, "_send_rpc_raw", _recording_send)

    try:
        host._cleanup_runtime(SID)
    finally:
        runtime["rpc_lock"].release()

    # Shutdown was attempted while the runtime was still registered, with the
    # documented fail-fast queue bound — and then the runtime was removed. The
    # per-session startup lock is deliberately retained (h02: _start_server
    # holds it by reference; popping it would let two threads race on different
    # locks for the same sid and spawn duplicate IDA processes).
    assert observed.get("still_registered") is True
    assert observed.get("queue_timeout") == 0
    assert SID not in host.session_runtimes
    assert SID in host._session_startup_locks


def test_start_server_refuses_other_thread_auto_restart(tmp_path, monkeypatch):
    """F04 finding 3: _start_server must not auto-restart a session whose close
    is in flight (the close-in-progress flag), or it would orphan a fresh IDA
    process once close's delete_session runs."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    host._begin_session_teardown(SID)  # a close/delete is running
    launched = []
    monkeypatch.setattr(
        host, "_start_server_inner", lambda s: launched.append(1) or {"ok": True}
    )

    res = host._start_server(session)

    assert launched == []
    assert res.get("error") is True
    assert res["code"] == MCPError.IDA_BUSY
    assert res.get("recoverable") is True


def test_start_server_allows_same_thread_relaunch(tmp_path, monkeypatch):
    """F04 finding 3: a deliberate restart (safe-mode reload, retry after a
    failed apply, re-open of a just-closed path) is allowed once the close has
    COMPLETED — the close-in-progress flag is cleared unconditionally when the
    teardown+delete finishes, so it never blocks a later relaunch."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    # Simulate a close that ran to completion: flag set, then cleared.
    host._begin_session_teardown(SID)
    assert host._session_teardown_active(SID)
    host._end_session_teardown(SID)
    launched = []
    monkeypatch.setattr(
        host, "_start_server_inner", lambda s: launched.append(1) or {"ok": True}
    )
    # The real _start_server claims ownership before launching.
    host._claim_runtime_ownership(SID)

    res = host._start_server(session)

    assert launched == [1]
    assert "error" not in res


def test_registration_recheck_aborts_launch_that_races_close(tmp_path, monkeypatch):
    """F04 finding 3: even if _start_server passed its pre-launch close check,
    a close that starts while IDA is booting must abort at registration instead
    of orphaning the runtime."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    host._begin_session_teardown(SID)  # close began while IDA was booting
    server_process = _FakeProc(alive=True)
    monkeypatch.setattr(host, "_is_executable_file", lambda p: True)
    monkeypatch.setattr(host, "_build_ida_command", lambda *a, **k: ["fake"])
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *a, **k: {"pong": True, "port": 7777})
    monkeypatch.setattr(host, "_nuclear_reset", lambda idb_path, aggressive=False: None)
    monkeypatch.setattr(host, "_cleanup_stale_idb_family", lambda idb_path: None)
    monkeypatch.setattr(server_runtime_mod.subprocess, "Popen", lambda *a, **k: server_process)
    real_isfile = os.path.isfile

    def _fake_isfile(p):
        return True if str(p).endswith(".port") else real_isfile(p)

    monkeypatch.setattr(server_runtime_mod.os.path, "isfile", _fake_isfile)
    real_open = open

    def _fake_open(path, *a, **k):
        if str(path).endswith(".port"):
            return io.StringIO("7777")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    session_dir = str(tmp_path / "artifacts")
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(str(tmp_path / "logs"), exist_ok=True)
    monkeypatch.setattr(
        host.session_mgr, "get_session_artifact_dir", lambda sid, create=True: session_dir
    )
    monkeypatch.setattr(
        host.session_mgr, "get_session_log_dir", lambda sid, create=True: str(tmp_path / "logs")
    )

    result = host._start_server_inner(session)

    assert result.get("error") is True
    assert result["code"] == MCPError.IDA_BUSY
    assert session.session_id not in host.session_runtimes


def test_launch_and_wait_force_preload_respects_packed_idb(tmp_path, monkeypatch):
    """F04 finding 4: the recovery launch path must apply the same packed_idb
    guard on IDA_MCP_FORCE_PRE_ANALYSIS_OPTS as the primary launch path."""
    host = _Host(tmp_path)
    captured = {}
    monkeypatch.setattr(host, "_build_ida_command", lambda *a, **k: ["fake"])
    monkeypatch.setattr(host, "_get_ida_diagnostics", lambda *a, **k: "")
    monkeypatch.setattr(
        server_runtime_mod.subprocess,
        # A dead process makes _launch_and_wait return IDA_CRASHED right after
        # Popen — but Popen already captured the env, which is all we assert on.
        "Popen",
        lambda cmd, **kwargs: captured.update(cmd=cmd, env=kwargs.get("env")) or _FakeProc(alive=False),
    )
    os.makedirs(str(tmp_path / "logs"), exist_ok=True)
    monkeypatch.setattr(
        host.session_mgr, "get_session_log_dir", lambda sid, create=True: str(tmp_path / "logs")
    )

    # Packed session with a preload request: FORCE must stay 0 (error 4 guard).
    host._launch_and_wait(
        host._make_session(tmp_path, packed_idb=True, analysis_options={"processor": "arm"}), 0
    )
    assert captured["env"]["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] == "0"

    # Non-packed session with a preload request still forces pre-analysis opts.
    captured.clear()
    host._launch_and_wait(
        host._make_session(tmp_path, packed_idb=False, analysis_options={"processor": "arm"}), 0
    )
    assert captured["env"]["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] == "1"


def test_reanalyze_only_opts_trigger_reanalyze(tmp_path, monkeypatch):
    """F04 finding 5: analysis_options={"reanalyze": True} alone must run the
    reanalyze step even though no other actions are produced."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path, analysis_options={"reanalyze": True})
    runtime = {"port": 12345}
    calls = []
    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda request, port, *a, **k: calls.append(request) or {"ok": True},
    )

    result = host._apply_session_options(session, runtime)

    assert "error" not in result
    assert any(
        r.get("args", {}).get("action") == "reanalyze" for r in calls
    ), f"reanalyze action missing from calls: {calls}"


def test_reanalyze_disabled_still_skips(tmp_path, monkeypatch):
    """F04 finding 5: reanalyze=False must skip reanalyze even with actions."""
    host = _Host(tmp_path)
    session = host._make_session(
        tmp_path, analysis_options={"reanalyze": False, "options": {"baseaddr": 0x1000}}
    )
    runtime = {"port": 12345}
    calls = []
    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda request, port, *a, **k: calls.append(request) or {"ok": True},
    )

    host._apply_session_options(session, runtime)

    assert not any(
        r.get("args", {}).get("action") == "reanalyze" for r in calls
    )


def test_oversized_payload_raises_typed_error(tmp_path, monkeypatch):
    """F04 finding 6: an oversized RPC request must raise RpcPayloadTooLarge
    (not a bare ValueError) and surface as SIZE_LIMIT_EXCEEDED, not a connection
    error."""
    host = _Host(tmp_path)
    monkeypatch.setattr(server_runtime_mod, "MAX_RPC_REQUEST_SIZE", 64)
    big = {"tool": "x", "args": {"blob": "z" * 1000}}

    with pytest.raises(RpcPayloadTooLarge):
        host._send_rpc_raw(big, 12345)

    res = host._send_rpc_with_retry(big, 12345)
    assert res.get("error") is True
    assert res["code"] == MCPError.SIZE_LIMIT_EXCEEDED


def test_resolve_basename_ambiguity_returns_none(tmp_path):
    """F04 finding 7: a bare basename that matches more than one session must not
    silently route to an arbitrary session — return None so the caller forces
    disambiguation."""
    host = _Host(tmp_path)

    def _session(sid, base):
        return SimpleNamespace(
            session_id=sid,
            idb_path=str(tmp_path / f"SID_{sid}" / base),
        )

    host.session_mgr = SimpleNamespace(
        get_session=lambda sid: None,
        find_session_by_path=lambda path: None,
        discover_sessions=lambda: [
            _session("AAAA1111", "foo.bin.i64"),
            _session("BBBB2222", "foo.bin.i64"),
        ],
    )

    assert host._resolve_session_from_idb_ref("foo.bin.i64") is None


def test_resolve_basename_unique_match_resolves(tmp_path):
    """F04 finding 7: a basename that matches exactly one session still resolves."""
    host = _Host(tmp_path)
    target = SimpleNamespace(
        session_id="AAAA1111",
        idb_path=str(tmp_path / "SID_AAAA1111" / "foo.bin.i64"),
    )
    host.session_mgr = SimpleNamespace(
        get_session=lambda sid: None,
        find_session_by_path=lambda path: None,
        discover_sessions=lambda: [
            target,
            SimpleNamespace(
                session_id="BBBB2222",
                idb_path=str(tmp_path / "SID_BBBB2222" / "bar.bin.i64"),
            ),
        ],
    )

    assert host._resolve_session_from_idb_ref("foo.bin.i64") is target


class _CountingIntel:
    """Fake usage intelligence that counts observe calls."""

    def __init__(self):
        self.calls = []

    def observe(self, tool, action, **kwargs):
        self.calls.append((tool, action, kwargs))


class TestRecordActivityNoDoubleObserve:
    """H2: _record_activity must not re-observe a call the dispatch already did."""

    def test_record_activity_skips_observe_when_usage_intel_present(self, tmp_path):
        host = _Host(tmp_path)
        intel = _CountingIntel()
        host._usage_intel = intel
        host.current_session = SimpleNamespace(session_id=SID)
        host._record_activity(
            "code", {"action": "decompile", "addr": "0x400000"},
            {"ok": True, "items": []},
            session_id=SID,
        )
        # The dispatch path owns the rich observe; _record_activity only keeps
        # last-activity tracking (and the auto_nudge fallback when no intel).
        assert intel.calls == []
        assert host._session_last_activity.get(SID) is not None

    def test_record_activity_keeps_last_activity_when_no_intel(self, tmp_path):
        host = _Host(tmp_path)
        host._usage_intel = None
        host.current_session = SimpleNamespace(session_id=SID)
        host._record_activity(
            "code", {"action": "decompile", "addr": "0x400000"},
            {"ok": True, "items": []},
            session_id=SID,
        )
        # Still tracks last activity and does not crash through the no-intel
        # auto_nudge fallback (record_tool_call is a documented no-op).
        assert host._session_last_activity.get(SID) is not None
