"""Exercise runtime lifecycle state machines across their shared boundaries."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _Process:
    pid = 4242
    returncode = None

    def poll(self):
        return None


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._activity_log = []
        self._activity_log_max = 20
        self._analysis_watchdog_lock = threading.RLock()
        self._analysis_watchdog_stop_events = {}
        self._analysis_watchdog_threads = {}
        self._analysis_checkpoint_stop_events = {}
        self._analysis_checkpoint_threads = {}
        self._session_startup_locks = {}
        self._runtime_lease_dir = str(tmp_path / "leases")
        Path(self._runtime_lease_dir).mkdir()
        self._runtime_owner_id = "lifecycle-owner"
        self.session_mgr = SimpleNamespace(sessions={})
        self.cache_dir = str(tmp_path)
        self.current_session = None


def test_watchdog_and_checkpoint_threads_cover_transitions(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    host._analysis_watchdog_interval = 0.001
    host._analysis_watchdog_stall_seconds = 0.001
    host.session_runtimes["AB12CDEF"] = {"process": _Process(), "port": 7777}
    metadata = []
    host._update_session_indexing_metadata = lambda sid, **updates: metadata.append((sid, updates))
    states = iter([
        None,
        {"analysis": {"is_ok": False, "active": False}, "inventory": {"functions_qty": "bad"}},
        {"analysis": {"is_ok": True, "active": False}, "inventory": {"functions_qty": "3"}},
    ])
    def query_state(*_args, **_kwargs):
        return next(states)

    def runtime_alive(runtime):
        return bool(runtime)

    host._query_ida_state = query_state
    host._runtime_alive = runtime_alive

    class ScriptedEvent:
        def __init__(self):
            self.results = iter([False, False, False, True])
            self.was_set = False

        def wait(self, _timeout):
            return next(self.results, True)

        def set(self):
            self.was_set = True

    class ImmediateThread:
        def __init__(self, target, **_kwargs):
            self._target = target

        def start(self):
            self._target()

        def join(self, **_kwargs):
            return None

        def is_alive(self):
            return False

    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.threading.Event", ScriptedEvent)
    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.threading.Thread", ImmediateThread)
    host._start_analysis_watchdog("AB12CDEF", 7777)
    watchdog = host._analysis_watchdog_threads["AB12CDEF"]
    watchdog.join(timeout=1)
    assert not watchdog.is_alive()
    assert metadata[0][1]["analysis_state"] == "starting"
    assert metadata[-1][1]["analysis_state"] == "ready"
    assert metadata[-1][1]["analysis_functions_qty"] == 3
    host._stop_analysis_watchdog("AB12CDEF")

    checkpointed = []

    def run_checkpoint(session_id):
        checkpointed.append(session_id)

    host._run_analysis_checkpoint = run_checkpoint
    host._checkpoint_save_seconds = 0.001
    host.checkpoint_save_seconds = 0.001
    class CheckpointEvent(ScriptedEvent):
        def __init__(self):
            self.results = iter([False, True])
            self.was_set = False

    monkeypatch.setattr("ida_pro_mcp.host.server.server_runtime.threading.Event", CheckpointEvent)
    host._start_analysis_checkpoint_timer("AB12CDEF", 7777)
    checkpoint = host._analysis_checkpoint_threads["AB12CDEF"]
    checkpoint.join(timeout=1)
    assert checkpointed == ["AB12CDEF"]
    host._stop_analysis_checkpoint_timer("AB12CDEF")


def test_checkpoint_and_metadata_persistence_modes(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    sid = "AB12CDEF"
    host.session_runtimes[sid] = {"process": _Process(), "port": 8888, "auth_token": "token"}
    host._analysis_is_complete = lambda _sid: True
    sent = []
    def send_rpc(*args, **kwargs):
        sent.append((args, kwargs))
        return {"ok": True}

    host._send_rpc_raw = send_rpc
    recorded = []

    def record_checkpoint(value):
        recorded.append(value)

    host._record_analysis_checkpoint = record_checkpoint
    host._run_analysis_checkpoint(sid)
    assert recorded == [sid]
    assert sent[0][0][1] == 8888
    host._send_rpc_raw = lambda *_args, **_kwargs: {"error": True}
    host._run_analysis_checkpoint(sid)
    host.session_runtimes[sid]["process"] = None
    host._run_analysis_checkpoint(sid)
    host.session_runtimes[sid]["process"] = _Process()

    updates = []
    host._query_ida_state = lambda *_args, **_kwargs: {"inventory": {"functions_qty": "bad"}}
    host._update_session_indexing_metadata = lambda value, **kwargs: updates.append((value, kwargs))
    ServerRuntimeMixin._record_analysis_checkpoint(host, sid)
    host._query_ida_state = lambda *_args, **_kwargs: {"inventory": {"functions_qty": "11"}}
    ServerRuntimeMixin._record_analysis_checkpoint(host, sid)
    assert updates[-1][1]["analysis_progress"] == 11
    assert updates[-2][1]["analysis_progress"] is None

    calls = []
    host.session_mgr = SimpleNamespace(
        update_session_metadata=lambda value, **kwargs: calls.append((value, kwargs)),
        sessions={},
    )
    ServerRuntimeMixin._update_session_indexing_metadata(host, sid, analysis_state="ready")
    assert calls[-1][1]["analysis_state"] == "ready"
    session = SimpleNamespace(session_id=sid, metadata={})
    saved = []
    def save_metadata(value):
        saved.append(value)

    host.session_mgr = SimpleNamespace(sessions={sid: session}, _save_metadata=save_metadata)
    ServerRuntimeMixin._update_session_indexing_metadata(host, sid, analysis_state="ready")
    ServerRuntimeMixin._update_session_indexing_metadata(host, sid, analysis_state="ready")
    assert session.metadata == {"analysis_state": "ready"}
    assert len(saved) == 1
    ServerRuntimeMixin._update_session_indexing_metadata(host, "MISSING1", analysis_state="ready")

    host._persist_session_fields(session, runtime_pid=3)
    assert session.runtime_pid == 3 and saved
    host.session_mgr = SimpleNamespace(update_session=lambda value, **kwargs: calls.append((value, kwargs)))
    host._persist_session_fields(session, runtime_pid=4)
    assert calls[-1][1]["runtime_pid"] == 4


def test_teardown_cleanup_and_idb_reference_modes(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    sid = "AB12CDEF"
    host._begin_session_teardown(sid)
    assert host._session_teardown_active(sid)
    host._end_session_teardown(sid)
    assert not host._session_teardown_active(sid)
    try:
        with host._teardown_session(sid):
            assert host._session_teardown_active(sid)
            raise RuntimeError("teardown test")
    except RuntimeError:
        pass
    assert not host._session_teardown_active(sid)

    class Handle:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    first = Handle()
    host.session_runtimes[sid] = {
        "process": _Process(),
        "port": 9000,
        "idb_path": str(tmp_path / "small.i64"),
        "log_handles": [first],
    }
    Path(host.session_runtimes[sid]["idb_path"]).write_bytes(b"idb")
    host._remove_runtime_lease = lambda _sid: None
    host._send_rpc_raw = lambda *_args, **_kwargs: {"saved": False}
    host._release_runtime_ownership = lambda _sid: None
    host._stop_analysis_watchdog = lambda *_args, **_kwargs: None
    host._stop_analysis_checkpoint_timer = lambda *_args, **_kwargs: None
    killed = []
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server_runtime._kill_process_tree",
        lambda proc, grace_seconds: killed.append((proc, grace_seconds)),
    )
    host._cleanup_runtime(sid)
    assert sid not in host.session_runtimes and first.closed and killed

    host._cleanup_runtime("NO_RUNTIME")
    host.session_runtimes = {"ONE12345": {}, "TWO12345": {}}

    def cleanup_runtime(value):
        killed.append(value)

    def adopt_or_cleanup_stale_runtime_leases():
        killed.append("leases")

    host._cleanup_runtime = cleanup_runtime
    host._adopt_or_cleanup_stale_runtime_leases = adopt_or_cleanup_stale_runtime_leases
    host._cleanup_all_runtimes()
    assert killed[-3:] == ["ONE12345", "TWO12345", "leases"]

    sessions = {}
    def get_session(value):
        return sessions.get(value)

    def find_session_by_path(value):
        return sessions.get(value)

    def discover_sessions():
        return list(sessions.values())

    manager = SimpleNamespace(
        get_session=get_session,
        find_session_by_path=find_session_by_path,
        discover_sessions=discover_sessions,
    )
    host.session_mgr = manager
    exact = SimpleNamespace(session_id=sid, idb_path=str(tmp_path / "SID_AB12CDEF_demo.i64"), binary_path="")
    sessions[sid] = exact
    assert host._resolve_session_from_idb_ref(sid) is exact
    assert host._resolve_session_from_idb_ref("SID_AB12CDEF_demo.i64") is exact
    assert host._resolve_session_from_idb_ref(str(tmp_path / "SID_AB12CDEF_demo.i64")) is exact
    assert host._resolve_session_from_idb_ref("missing.i64") is None
    assert host._resolve_session_from_idb_ref(3) is None


def test_process_and_file_recovery_modes(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    idb = tmp_path / "sample.i64"
    idb.write_bytes(b"small")
    (tmp_path / "sample.mcp.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "sample.id0").write_text("sidecar", encoding="utf-8")
    host._nuclear_reset(str(idb), aggressive=False)
    assert not (tmp_path / "sample.mcp.lock").exists()
    host._nuclear_reset(str(idb), aggressive=True)
    assert not idb.exists() and not (tmp_path / "sample.id0").exists()
    host._nuclear_reset("")

    monkeypatch.setattr(host, "_live_runtime_pids", lambda: {22})
    monkeypatch.setattr(host, "_ida_binary_names", lambda: ["idat64"])
    fake_proc = SimpleNamespace(info={"pid": 22, "name": "idat64", "cmdline": ["/tmp/db.i64"]})
    monkeypatch.setitem(__import__("sys").modules, "psutil", SimpleNamespace(process_iter=lambda _fields: [fake_proc]))
    assert host._terminate_ida_processes_for_path(str(tmp_path / "db.i64")) == []
    assert host._terminate_ida_processes_for_path("") == []
