"""Deep offline coverage for background indexing and task ownership edges."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.batch_manager import BatchManager
from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_batch
from ida_pro_mcp.host.server.server_batch import BackgroundMixin


class _Sessions:
    def __init__(self, sessions):
        self.sessions = list(sessions)

    def discover_sessions(self):
        return list(self.sessions)

    def get_session(self, session_id):
        return next(
            (session for session in self.sessions if str(session.session_id) == str(session_id)),
            None,
        )


class _BatchHarness(BackgroundMixin):
    def __init__(self, sessions=(), responses=()):
        self.session_mgr = _Sessions(sessions)
        self._batch_mgr = BatchManager(max_workers=1)
        self.responses = list(responses)
        self.calls = []
        self.metadata = []
        self._client_request_state().owned_session_ids.update(
            str(session.session_id) for session in sessions
        )

    def _resolve_session_from_idb_ref(self, ref):
        return next(
            (
                session
                for session in self.session_mgr.sessions
                if ref in {session.session_id, session.idb_path, session.binary_path}
            ),
            None,
        )

    def _ensure_client_owns_session(self, _session):
        return None

    def _resolve_policy_mode(self):
        return "assist"

    def call_tool(self, tool, idb_path, **args):
        self.calls.append((tool, idb_path, args))
        return self.responses.pop(0)

    def _update_session_indexing_metadata(self, session_id, **updates):
        self.metadata.append((session_id, updates))


def _session(tmp_path: Path, sid: str, *, idb_exists=True):
    binary = tmp_path / f"{sid}.bin"
    binary.write_bytes(b"matching binary")
    idb = tmp_path / f"{sid}.i64"
    if idb_exists:
        idb.write_bytes(b"idb")
    return SimpleNamespace(
        session_id=sid,
        binary_path=str(binary),
        idb_path=str(idb),
        analysis_options={},
    )


def _embedding_db(path: str, *, rows=(), with_quality=True):
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE embedding_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        quality = ", index_quality TEXT" if with_quality else ""
        conn.execute(f"CREATE TABLE func_embeddings(ea TEXT PRIMARY KEY, vec_blob BLOB NOT NULL{quality})")
        for ea, row_quality in rows:
            if with_quality:
                conn.execute(
                    "INSERT INTO func_embeddings(ea, vec_blob, index_quality) VALUES(?, X'00', ?)",
                    (ea, row_quality),
                )
            else:
                conn.execute(
                    "INSERT INTO func_embeddings(ea, vec_blob) VALUES(?, X'00')", (ea,)
                )
        conn.commit()


def test_background_binding_falls_back_without_connection_state():
    session = SimpleNamespace(session_id="S1")

    class _NoState(BackgroundMixin):
        _client_request_state = None

        def __init__(self):
            self._session = None

        @property
        def current_session(self):
            return self._session

        @current_session.setter
        def current_session(self, value):
            self._session = value

    host = _NoState()
    bound = host._bind_background_run(lambda task: task["value"], session=session)
    assert bound({"value": 7}) == 7
    assert host.current_session is session

    no_session = host._bind_background_run(lambda task: task, session=None)
    assert no_session("ready") == "ready"

    stateful = _BatchHarness()
    stateful._client_request_state().active_agent = "worker-agent"
    agent_session = SimpleNamespace(session_id="AGENT-SESSION")
    bound = stateful._bind_background_run(lambda task: task, session=agent_session)
    assert bound("agent-task") == "agent-task"
    assert "AGENT-SESSION" in stateful._client_request_state().owned_sessions_by_agent["worker-agent"]
    stateful._client_request_state().current_session = None
    assert stateful._bind_background_run(lambda task: task, session=None)("no-session") == "no-session"
    empty_id = stateful._bind_background_run(lambda task: task, session=SimpleNamespace(session_id=""))
    assert empty_id("empty-id") == "empty-id"
    stateful._batch_manager.shutdown()


def test_matching_index_reuse_reports_existing_missing_and_unusable_inputs(tmp_path):
    target = _session(tmp_path, "TARGET")
    source = _session(tmp_path, "SOURCE")
    target_db = f"{target.idb_path}.embeddings.db"
    _embedding_db(target_db, rows=[("0x1", "full")])
    host = _BatchHarness([source, target])
    assert host._seed_index_from_matching_binary(target)["reason"] == "target_index_present"
    host._batch_manager.shutdown()

    missing_binary = _session(tmp_path, "MISSING")
    Path(missing_binary.binary_path).unlink()
    host = _BatchHarness([missing_binary])
    assert host._seed_index_from_matching_binary(missing_binary) == {
        "reused": False,
        "reason": "binary_unavailable",
    }
    host._batch_manager.shutdown()


def test_matching_index_reuse_skips_empty_size_and_digest_mismatches(tmp_path):
    target = _session(tmp_path, "TARGET")
    empty = _session(tmp_path, "EMPTY")
    _embedding_db(f"{empty.idb_path}.embeddings.db")
    host = _BatchHarness([empty, target])
    assert host._seed_index_from_matching_binary(target)["reason"] == "no_compatible_index"
    host._batch_manager.shutdown()

    size_target = _session(tmp_path, "SIZE_TARGET")
    size_source = _session(tmp_path, "SIZE_SOURCE")
    Path(size_source.binary_path).write_bytes(b"different length")
    _embedding_db(f"{size_source.idb_path}.embeddings.db", rows=[("0x1", "fast")])
    host = _BatchHarness([size_source, size_target])
    assert host._seed_index_from_matching_binary(size_target)["reason"] == "no_compatible_index"
    host._batch_manager.shutdown()

    digest_target = _session(tmp_path, "DIGEST_TARGET")
    digest_source = _session(tmp_path, "DIGEST_SOURCE")
    Path(digest_source.binary_path).write_bytes(b"matching binarx")
    _embedding_db(f"{digest_source.idb_path}.embeddings.db", rows=[("0x1", "fast")])
    host = _BatchHarness([digest_source, digest_target])
    assert host._seed_index_from_matching_binary(digest_target)["reason"] == "no_compatible_index"
    host._batch_manager.shutdown()


def test_matching_index_reuse_records_path_fingerprint_and_rejects_profile(tmp_path, monkeypatch):
    source = _session(tmp_path, "SOURCE")
    target = _session(tmp_path, "TARGET", idb_exists=False)
    Path(target.binary_path).write_bytes(Path(source.binary_path).read_bytes())
    _embedding_db(
        f"{source.idb_path}.embeddings.db",
        rows=[("0x1", "full")],
    )
    host = _BatchHarness([source, target])
    reused = host._seed_index_from_matching_binary(target)
    assert reused["reused"] is True
    with sqlite3.connect(f"{target.idb_path}.embeddings.db") as conn:
        metadata = dict(conn.execute("SELECT key, value FROM embedding_meta"))
    assert metadata["source_fingerprint"]
    host._batch_manager.shutdown()

    class _EmptyIndex:
        size = 0

        def __init__(self, _db_path, _embedder):
            pass

    import ida_pro_mcp.host.intelligence.embeddings as embeddings

    monkeypatch.setattr(embeddings, "FunctionEmbeddingIndex", _EmptyIndex)
    source2 = _session(tmp_path, "SOURCE2")
    target2 = _session(tmp_path, "TARGET2")
    Path(target2.binary_path).write_bytes(Path(source2.binary_path).read_bytes())
    _embedding_db(f"{source2.idb_path}.embeddings.db", rows=[("0x2", "full")])
    host = _BatchHarness([source2, target2])
    host.assembler = SimpleNamespace(_embedder=object())
    rejected = host._seed_index_from_matching_binary(target2)
    host._batch_manager.shutdown()
    assert rejected["reason"] == "incompatible_embedding_profile"


def test_matching_index_reuse_covers_cached_digest_malformed_db_and_stat_race(tmp_path, monkeypatch):
    target = _session(tmp_path, "TARGET")
    source = _session(tmp_path, "SOURCE")
    source2 = _session(tmp_path, "SOURCE2")
    Path(source2.binary_path).unlink()
    Path(source2.binary_path).symlink_to(source.binary_path)
    _embedding_db(f"{source.idb_path}.embeddings.db", rows=[("0x1", "full")], with_quality=False)
    _embedding_db(f"{source2.idb_path}.embeddings.db", rows=[("0x2", "fast")])
    malformed = _session(tmp_path, "MALFORMED")
    Path(f"{malformed.idb_path}.embeddings.db").write_text("not sqlite")
    host = _BatchHarness([source, source2, malformed, target])
    reused = host._seed_index_from_matching_binary(target)
    assert reused["reused"] is True
    assert reused["full_quality_functions"] == 0
    host._batch_manager.shutdown()

    race_target = _session(tmp_path, "RACE_TARGET")
    race_source = _session(tmp_path, "RACE_SOURCE")
    _embedding_db(f"{race_source.idb_path}.embeddings.db", rows=[("0x3", "full")])
    real_stat = server_batch.os.stat
    real_isfile = server_batch.os.path.isfile

    def stat_with_race(path):
        if str(path) == race_source.binary_path:
            raise OSError("source disappeared")
        return real_stat(path)

    def isfile_during_race(path):
        if str(path) == race_source.binary_path:
            return True
        return real_isfile(path)

    monkeypatch.setattr(server_batch.os, "stat", stat_with_race)
    monkeypatch.setattr(server_batch.os.path, "isfile", isfile_during_race)
    host = _BatchHarness([race_source, race_target])
    assert host._seed_index_from_matching_binary(race_target)["reason"] == "no_compatible_index"
    host._batch_manager.shutdown()


def test_matching_index_reuse_reaches_existing_locks_and_successful_validation(tmp_path, monkeypatch):
    source = _session(tmp_path, "SOURCE")
    target = _session(tmp_path, "TARGET")
    Path(target.binary_path).write_bytes(Path(source.binary_path).read_bytes())
    _embedding_db(f"{source.idb_path}.embeddings.db", rows=[("0x1", "full")])
    host = _BatchHarness([source, target])

    class _ValidIndex:
        size = 1

        def __init__(self, _db_path, _embedder):
            pass

    import ida_pro_mcp.host.intelligence.embeddings as embeddings

    monkeypatch.setattr(embeddings, "FunctionEmbeddingIndex", _ValidIndex)
    host.assembler = SimpleNamespace(_embedder=object())
    assert host._seed_index_from_matching_binary(target)["reused"] is True
    assert host._seed_index_from_matching_binary(target)["reason"] == "target_index_present"
    host._batch_manager.shutdown()

    equal = _BatchHarness([target])
    left = SimpleNamespace(analysis_options={"bits": 64})
    right = SimpleNamespace(analysis_options={"bits": 64})
    assert equal._semantic_load_profiles_compatible(left, right) is True
    equal._batch_manager.shutdown()


def test_lazy_index_initializers_converge_when_another_thread_wins_the_race(monkeypatch):
    host = _BatchHarness()

    class _InstallLock:
        def __enter__(self):
            host._semantic_index_reuse_lock = threading.RLock()
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(server_batch, "_LAZY_STATE_LOCK", _InstallLock())
    # Invoke the actual lazy lock path directly; the unlocked operation is
    # replaced because this test is only about double-checked initialization.
    original = host._seed_index_from_matching_binary_unlocked
    host._seed_index_from_matching_binary_unlocked = lambda _session: {}
    assert host._seed_index_from_matching_binary(SimpleNamespace()) == {}
    host._seed_index_from_matching_binary_unlocked = original

    class _InstallJobState:
        enters = 0

        def __enter__(self):
            self.enters += 1
            host._semantic_index_jobs_lock = threading.RLock()
            if self.enters == 2:
                host._semantic_index_tasks = {"already": "present"}
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(server_batch, "_LAZY_STATE_LOCK", _InstallJobState())
    host._semantic_index_jobs_lock = None
    host._semantic_index_tasks = None
    lock, active = host._semantic_index_job_state()
    assert isinstance(lock, type(threading.RLock()))
    assert active == {"already": "present"}
    host._batch_manager.shutdown()


def test_semantic_job_state_and_submission_admission_errors():
    missing = _BatchHarness()
    missing._resolve_session_from_idb_ref = lambda _ref: None
    assert missing._submit_semantic_index({}, "missing")["code"] == MCPError.FILE_NOT_FOUND
    missing._batch_manager.shutdown()

    session = SimpleNamespace(session_id="S1", idb_path="S1.i64", binary_path="S1.bin")
    denied = _BatchHarness([session])
    denied._ensure_client_owns_session = lambda _session: make_error(MCPError.POLICY_DENIED, "denied")
    assert denied._submit_semantic_index({}, "S1")["code"] == MCPError.POLICY_DENIED
    denied._batch_manager.shutdown()

    invalid = _BatchHarness([session])
    assert invalid._submit_semantic_index({"limit": 0}, "S1")["code"] == MCPError.INVALID_ARGS
    lock, active = invalid._semantic_index_job_state()
    assert lock is invalid._semantic_index_jobs_lock
    assert active is invalid._semantic_index_tasks
    invalid._semantic_index_tasks["S1"] = "active"

    class _ActiveManager:
        def status(self, task_id):
            assert task_id == "active"
            return [{"state": "running"}]

    invalid._batch_mgr = _ActiveManager()
    reused = invalid._submit_semantic_index({"mode": "fast"}, "S1")
    assert reused["reused"] is True
    invalid._batch_mgr = BatchManager(max_workers=1)
    invalid._batch_manager.shutdown()


def test_semantic_submission_covers_finished_dedup_and_unscoped_seed(tmp_path):
    session = _session(tmp_path, "S1")
    host = _BatchHarness([session], [{"ok": True, "indexed": 1, "attempted": 1, "complete": True}])
    host._semantic_index_tasks = {"S1": "finished"}

    class _FinishedManager:
        def status(self, _task_id):
            return [{"state": "done"}]

        def submit(self, **kwargs):
            self.kwargs = kwargs
            return "new-job"

    manager = _FinishedManager()
    host._batch_mgr = manager
    host._seed_index_from_matching_binary = lambda _session: {"reused": True, "from_session": "other"}
    submitted = host._submit_semantic_index({"mode": "fast"}, "S1")
    assert submitted["task_id"] == "new-job"
    task = SimpleNamespace(task_id="new-job", _cancel_event=threading.Event(), progress=None)
    assert manager.kwargs["run_fn"](task)["complete"] is True


def test_background_dispatch_and_lazy_manager_paths():
    host = BackgroundMixin()
    host._batch_mgr = None
    manager = host._batch_manager
    assert isinstance(manager, BatchManager)
    assert host._handle_background({"action": "list"})["tasks"] == []
    manager.shutdown()

    preflight = _BatchHarness()
    assert preflight._background_policy_preflight(script=None, tool_call=None) is None
    assert preflight._background_policy_preflight(script=None, tool_call={"tool": "x", "args": [1]})["error"] is True
    preflight._batch_manager.shutdown()


def test_lazy_batch_manager_and_ownership_iteration_edges(monkeypatch):
    host = BackgroundMixin()
    sentinel = SimpleNamespace()

    class _InstallManager:
        def __enter__(self):
            host._batch_mgr = sentinel
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(server_batch, "_LAZY_STATE_LOCK", _InstallManager())
    host._batch_mgr = None
    assert host._batch_manager is sentinel

    class _NoStateOwnership(BackgroundMixin):
        _client_request_state = None

        def __init__(self):
            self._session = SimpleNamespace(session_id="S1")

        @property
        def current_session(self):
            return self._session

    owned = _NoStateOwnership()
    owned._client_owns_session = lambda sid: sid == "S1"
    assert owned._owned_batch_session_ids() == {"S1"}

    stateful = BackgroundMixin()
    stateful._client_owns_session = lambda sid: sid == "S1"
    stateful._client_request_state().owned_session_ids.update({"S1", "S2"})
    assert stateful._owned_batch_session_ids() == {"S1"}


def test_semantic_cleanup_ignores_a_newer_job_for_the_same_session():
    session = SimpleNamespace(session_id="S1", idb_path="S1.i64", binary_path="S1.bin")
    host = _BatchHarness([session], [{"ok": True, "indexed": 1, "attempted": 1, "complete": True}])

    class _ManualManager:
        def submit(self, **kwargs):
            self.kwargs = kwargs
            return "job-1"

    manager = _ManualManager()
    host._batch_mgr = manager
    submitted = host._submit_semantic_index({"start": "1", "end": "2"}, "S1")
    assert submitted["task_id"] == "job-1"
    host._semantic_index_tasks["S1"] = "newer-job"
    task = SimpleNamespace(task_id="job-1", _cancel_event=threading.Event(), progress=None)
    assert manager.kwargs["run_fn"](task)["complete"] is True


def test_semantic_job_limit_error_no_progress_and_cancellation_boundaries():
    session = SimpleNamespace(session_id="S1", idb_path="S1.i64", binary_path="S1.bin")
    limited = _BatchHarness(
        [session],
        [{"ok": True, "indexed": 1, "attempted": 1, "failed": 0, "complete": False, "next_cursor": "0x20"}],
    )
    submitted = limited._submit_semantic_index(
        {"_background": True, "_index_total_limit": 1, "_index_slice_size": 1, "start": "0x1", "end": "0x2"},
        "S1",
    )
    result = limited._batch_manager.wait(submitted["task_id"], timeout=3)
    assert result["state"] == "done"
    assert result["result"]["limit_reached"] is True
    limited._batch_manager.shutdown()

    failed = _BatchHarness([session], [make_error(MCPError.IDA_TIMEOUT, "backend timed out")])
    submitted = failed._submit_semantic_index({"start": "1", "end": "2"}, "S1")
    result = failed._batch_manager.wait(submitted["task_id"], timeout=3)
    assert result["state"] == "failed"
    assert "backend timed out" in result["error"]
    failed._batch_manager.shutdown()

    stalled = _BatchHarness(
        [session],
        [{"ok": True, "indexed": 0, "attempted": 0, "failed": 0, "complete": False, "next_cursor": "0x20"}],
    )
    submitted = stalled._submit_semantic_index(
        {"start": "0x1", "end": "0x2", "start_after": "0x20"}, "S1"
    )
    result = stalled._batch_manager.wait(submitted["task_id"], timeout=3)
    assert result["state"] == "failed"
    assert "no progress" in result["error"]
    stalled._batch_manager.shutdown()

    class _CancelHarness(_BatchHarness):
        cancel_on_first_update = True

        def _update_session_indexing_metadata(self, session_id, **updates):
            super()._update_session_indexing_metadata(session_id, **updates)
            if self.cancel_on_first_update and len(self.metadata) == 1:
                next(iter(self._batch_mgr._tasks.values()))._cancel_event.set()

    cancelled = _CancelHarness([session], [])
    submitted = cancelled._submit_semantic_index({"start": "0x1", "end": "0x2"}, "S1")
    result = cancelled._batch_manager.wait(submitted["task_id"], timeout=3)
    assert result["state"] == "cancelled"
    assert result["result"]["cancelled"] is True
    cancelled._batch_manager.shutdown()


def test_background_submission_fallback_and_owned_task_edges():
    session = SimpleNamespace(session_id="S1")
    host = _BatchHarness([session])
    captured = []

    class _Submitter:
        def submit(self, **kwargs):
            captured.append(kwargs)
            return "task-1"

        def shutdown(self):
            pass

    host._batch_mgr = _Submitter()
    result = host._bg_submit(
        {"session_id": "S1", "tool_call": {"tool": "analysis", "args": {"action": "status"}}}
    )
    assert result == {"task_id": "task-1", "state": "pending"}
    task = SimpleNamespace(session_id="S1", args=captured[0]["args"])
    assert captured[0]["run_fn"](task)["status"] == "ok"
    assert host._client_request_state().current_session is None
    assert captured[0]["run_fn"](
        SimpleNamespace(session_id=None, args={})
    ) == {"status": "unknown"}

    class _BrokenSessions:
        def get_session(self, _session_id):
            raise RuntimeError("gone")

    host.session_mgr = _BrokenSessions()
    assert captured[0]["run_fn"](task)["status"] == "ok"
    host.session_mgr = SimpleNamespace(get_session=lambda _session_id: None)
    assert captured[0]["run_fn"](task)["status"] == "ok"
    host._batch_mgr = _Submitter()

    no_session = _BatchHarness()
    no_session._batch_mgr = _Submitter()
    assert no_session._bg_submit(
        {"tool_call": {"tool": "analysis", "args": {"action": "status"}}}
    )["task_id"] == "task-1"
    no_session._batch_manager.shutdown()

    missing_session = _BatchHarness([session])
    assert missing_session._bg_submit(
        {"session_id": "missing", "tool_call": {"tool": "analysis", "args": {}}}
    )["code"] == MCPError.FILE_NOT_FOUND
    missing_session._batch_manager.shutdown()

    denied_session = _BatchHarness([session])
    denied_session._ensure_client_owns_session = lambda _session: make_error(
        MCPError.POLICY_DENIED, "not yours"
    )
    assert denied_session._bg_submit(
        {"session_id": "S1", "tool_call": {"tool": "analysis", "args": {}}}
    )["code"] == MCPError.POLICY_DENIED
    denied_session._batch_manager.shutdown()

    policy_blocked = _BatchHarness()
    assert policy_blocked._bg_submit(
        {"tool_call": {"tool": "modify", "args": {"action": "rename"}}}
    )["error"] is True
    policy_blocked._batch_manager.shutdown()

    unguarded = BackgroundMixin()
    unguarded._batch_mgr = SimpleNamespace(
        status=lambda _task_id: [{"task_id": "task-1", "session_id": "S1"}],
    )
    unguarded._client_owns_session = None
    assert unguarded._owned_batch_session_ids() is None
    assert unguarded._filter_owned_batch_tasks([{"session_id": "S1"}]) == [{"session_id": "S1"}]
    assert unguarded._require_owned_batch_task("task-1") is None
    assert unguarded._bg_status({"task_id": "task-1"})["ok"] is True


def test_owned_task_denials_and_filtered_status_paths():
    session = SimpleNamespace(session_id="S1")
    host = _BatchHarness([session])
    host._client_owns_session = lambda sid: sid == "S1"
    host._batch_mgr._tasks = {}
    task_id = host._batch_mgr.submit(
        action="tool_call", args={}, session_id="S2", run_fn=lambda _task: {"ok": True}
    )
    host._batch_mgr.wait(task_id, timeout=3)
    assert host._bg_result({"task_id": task_id})["code"] == MCPError.NOT_FOUND
    assert host._bg_wait({"task_id": task_id})["code"] == MCPError.NOT_FOUND
    assert host._bg_status({"task_id": task_id})["code"] == MCPError.NOT_FOUND
    assert host._bg_cancel({"task_id": task_id})["code"] == MCPError.NOT_FOUND
    assert host._bg_list({"session_id": "S2"})["tasks"] == []
    assert host._bg_list({"session_id": "S1"})["tasks"] == []
    host._batch_mgr.shutdown()
