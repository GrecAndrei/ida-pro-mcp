"""Boundary coverage for durable blackboard orchestration modes."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import blackboard_orchestration as bo


class _BrokenConnection:
    def execute(self, _sql, *_args):
        raise sqlite3.OperationalError("connection failed")

    def close(self):
        return None


class _Mixin:
    def __init__(self):
        self.current_session = SimpleNamespace(idb_path="/tmp/demo.i64")
        self.notifications = []
        self.statuses = []
        self.execute_result = None
        self.write_result = "proposal-1"
        self.raise_on_status = False

    def _execute_tool(self, *_args, **_kwargs):
        if isinstance(self.execute_result, BaseException):
            raise self.execute_result
        return self.execute_result

    def _create_trace_task(self, *_args, **_kwargs):
        return "trace-1"

    def _set_task_status(self, _store, entry, status, payload):
        if self.raise_on_status:
            raise RuntimeError("cannot claim")
        self.statuses.append((entry, status, payload))

    def _run_trace_task(self, *_args, **_kwargs):
        return {"ok": True}

    def _get_blackboard_store(self):
        return None

    def _write_crawler_proposal(self, _store, **_kwargs):
        return self.write_result

    def _proposal_entries(self, _store, **_kwargs):
        return [{"id": "proposal-1", "addr": "0x1000", "title": "Found", "confidence": 0.8}]

    def _send_notification(self, payload):
        self.notifications.append(payload)


class _Store:
    def __init__(self, db_path=""):
        self.db_path = db_path
        self.entries = []
        self.read_result = {"content": '{"status":"pending"}'}
        self.list_error = None
        self.targets_result = {"targets": []}
        self.next_result = []

    def read(self, _entry_id):
        return self.read_result

    def list(self, **_kwargs):
        if self.list_error:
            raise self.list_error
        return self.entries

    def targets(self, *_args, **_kwargs):
        if isinstance(self.targets_result, BaseException):
            raise self.targets_result
        return self.targets_result

    def next_target(self, **_kwargs):
        if isinstance(self.next_result, BaseException):
            raise self.next_result
        return self.next_result


@pytest.fixture
def orchestrator():
    instance = bo.BlackboardOrchestrator(_Mixin(), max_workers=1)
    yield instance
    instance.shutdown()


def _broken_db(method):
    db = bo.MachineryDB("unused.db", {})
    db._ensure = lambda: True

    def _conn():
        return _BrokenConnection()

    db._conn = _conn
    method(db)
    assert db._usable is False


def test_machinery_db_handles_read_write_delete_and_task_errors(tmp_path):
    path = tmp_path / "machinery.sqlite"
    db = bo.MachineryDB(str(path), {})
    db.set("phase", "key", {"value": 1})
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE bb_machinery SET value='not-json'")
    assert db.get("phase", "key") == {"value": 1}
    assert db._usable is False
    assert db.task("missing") is None

    _broken_db(lambda value: value.set("phase", "key", 1))
    _broken_db(lambda value: value.delete("phase", "key"))
    _broken_db(lambda value: value.save_task("task", "trace", "pending", {}))
    _broken_db(lambda value: value.update_task("task", "done", {}))
    _broken_db(lambda value: value.task("task"))

    disabled = bo.MachineryDB("", {})
    assert disabled.task("missing") is None


def test_task_pool_forgets_unknown_futures_and_honors_expired_deadline(monkeypatch):
    pool = object.__new__(bo.TaskPool)
    pool._lock = __import__("threading").Lock()
    future = object()
    pool._futures = {"known": future}
    pool._forget(object())
    assert pool.pending() == ["known"]
    pool._forget(future)
    assert pool.pending() == []

    class _Future:
        def result(self, timeout):
            raise AssertionError(f"must not wait: {timeout}")

    pool._futures = {"expired": _Future()}
    clock = iter((100.0, 101.0))
    monkeypatch.setattr(bo.time, "monotonic", lambda: next(clock))
    pool.drain(timeout=0.1)


def test_crawler_start_is_idempotent_and_orchestrator_machinery_surfaces(tmp_path):
    crawler = bo._CrawlerRuntime()
    crawler._thread = SimpleNamespace(is_alive=lambda: True)
    crawler.start(lambda: None)
    assert crawler.is_running() is True

    mixin = _Mixin()
    instance = bo.BlackboardOrchestrator(mixin, max_workers=1)
    store = _Store(str(tmp_path / "workspace.sqlite"))
    instance.machinery_set(store, "phase", "step", {"value": 2})
    assert instance.machinery_get(store, "phase", "step") == {"value": 2}
    instance.machinery_delete(store, "phase", "step")
    assert instance.machinery_get(store, "phase", "step", "default") == "default"
    assert instance.machinery_snapshot_keys(store, "phase") == []
    assert instance.machinery_snapshot_keys(_Store(str(tmp_path / "missing" / "db")), "phase") == []
    assert instance.machinery_snapshot_keys(_Store(""), "phase") == []
    instance.shutdown()


def test_open_store_and_enqueue_trace_task_degrade_across_payload_modes(tmp_path, monkeypatch):
    mixin = _Mixin()
    instance = bo.BlackboardOrchestrator(mixin, max_workers=1)
    store = _Store(str(tmp_path / "workspace.sqlite"))

    assert instance._open_store("") is None
    class _Module:
        class BlackboardStore:
            def __init__(self, **_kwargs):
                raise RuntimeError("store unavailable")

    monkeypatch.setattr(type(mixin), "_blackboard_module", _Module, raising=False)
    assert instance._open_store(str(tmp_path / "workspace.sqlite")) is None

    store.read_result = None
    assert instance.enqueue_trace_task(store, "source", "text", 1, 2) == "trace-1"
    store.read_result = {"content": "not-json"}
    assert instance.enqueue_trace_task(store, "source", "text", 1, 2) == "trace-1"

    class _Machinery:
        def save_task(self, *_args):
            raise RuntimeError("durable write failed")

    monkeypatch.setattr(instance, "_machinery_for", lambda _store: _Machinery())
    assert instance.enqueue_trace_task(store, "source", "text", 1, 2) == "trace-1"
    instance.shutdown()


def test_run_pending_trace_tasks_handles_bad_lists_claims_and_non_pending_payloads(tmp_path):
    mixin = _Mixin()
    instance = bo.BlackboardOrchestrator(mixin, max_workers=1)
    store = _Store(str(tmp_path / "workspace.sqlite"))
    store.entries = [
        {"id": "", "content": '{"status":"pending"}'},
        {"id": "bad-json", "content": "not-json"},
        {"id": "reread-list", "content": '{"status":"pending"}'},
    ]
    store.read_result = {"content": "[]"}
    result = instance.run_pending_trace_tasks(store, 5)
    assert result["enqueued"] == 0

    store.list_error = RuntimeError("list failed")
    assert instance.run_pending_trace_tasks(store, 1)["enqueued"] == 0

    store.list_error = None
    store.entries = [{"id": "claim-fails", "content": '{"status":"pending"}'}]
    store.read_result = {"content": '{"status":"pending"}'}
    mixin.raise_on_status = True
    assert instance.run_pending_trace_tasks(store, 1)["enqueued"] == 0

    class _QueueUnavailable:
        def submit(self, *_args):
            return False

        def shutdown(self):
            return None

    mixin.raise_on_status = False
    store.entries = [{"id": "reread-missing", "content": '{"status":"pending"}'}]
    store.read_result = None
    instance._pool = _QueueUnavailable()
    assert instance.run_pending_trace_tasks(store, 1)["enqueued"] == 0
    instance.shutdown()


def test_trace_status_and_probe_cover_malformed_or_unavailable_runtime_results(orchestrator):
    store = _Store()
    store.entries = [
        {"id": "bad", "title": "Bad", "content": "not-json"},
        {"id": "unknown", "title": "Unknown", "content": "{}"},
    ]
    assert orchestrator.trace_status_rows(store, "", 10)[0]["status"] == "unknown"
    assert orchestrator.trace_status_rows(store, "pending", 10) == []

    mixin = orchestrator._mixin
    mixin.execute_result = ["not", "a", "mapping"]
    assert orchestrator.default_probe("0x1000")["findings"] == []
    mixin.execute_result = RuntimeError("offline")
    assert orchestrator.default_probe("0x1000")["title"] == ""


def test_crawl_loop_frontier_rpc_and_crawl_step_fallbacks(orchestrator):
    mixin = orchestrator._mixin
    store = _Store()
    assert orchestrator._frontier_rpc(store) is None
    mixin.call_tool = lambda *args, **kwargs: (args, kwargs)
    rpc = orchestrator._frontier_rpc(store)
    assert rpc is not None
    assert rpc("code", {"addr": "0x1"})[0][0] == "code"

    class _Stop:
        def __init__(self):
            self.values = iter((False, True))

        def wait(self, _timeout):
            return next(self.values)

        def set(self):
            return None

    orchestrator._crawler._stop = _Stop()
    orchestrator._open_store = lambda _path: (_ for _ in ()).throw(RuntimeError("open failed"))
    orchestrator._crawl_loop("workspace")

    orchestrator._crawler._stop = _Stop()
    orchestrator._open_store = lambda _path: None
    orchestrator._crawl_loop("workspace")

    seen = []
    orchestrator._crawler._stop = _Stop()
    orchestrator._open_store = lambda _path: object()

    def _record(value):
        seen.append(value)

    orchestrator.crawl_step = _record
    orchestrator._crawl_loop("workspace")
    assert seen

    store.targets_result = RuntimeError("frontier unavailable")
    store.next_result = RuntimeError("fallback unavailable")
    assert orchestrator.crawl_step(store) is None

    store.targets_result = {"targets": [{"addr": ""}, {}, {"address": "0x1000"}]}
    orchestrator._crawler.mark_visited("0x1000")
    assert orchestrator.crawl_step(store) is None

    orchestrator._crawler._visited.clear()
    orchestrator._crawler._probe = lambda _addr: "not-a-result"
    orchestrator._crawler.mark_visited = lambda _addr: False
    assert orchestrator.crawl_step(store) is None


def test_crawl_step_handles_non_mapping_probe_and_empty_proposal(orchestrator):
    store = _Store()
    store.targets_result = {"targets": [{"entry_id": "0x2000"}]}
    orchestrator._crawler._probe = lambda _addr: ["not-a-dict"]
    assert orchestrator.crawl_step(store) is None

    orchestrator._crawler._visited.clear()
    store.targets_result = {"targets": [{"entry_id": "0x3000"}]}
    orchestrator._crawler._probe = lambda _addr: {"findings": ["finding"], "labels": ["tag"]}
    orchestrator._mixin.write_result = ""
    assert orchestrator.crawl_step(store) == ""
