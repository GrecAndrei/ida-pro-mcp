"""Offline lifecycle coverage for durable blackboard orchestration."""

from __future__ import annotations

import sqlite3
import threading
from types import SimpleNamespace

from ida_pro_mcp.host.server.blackboard_orchestration import (
    BlackboardOrchestrator,
    MachineryDB,
    TaskPool,
    _CrawlerRuntime,
    is_governance_error,
)


def test_machinery_db_round_trip_and_defensive_fallbacks(tmp_path):
    path = tmp_path / "machinery.sqlite"
    cache = {}
    db = MachineryDB(str(path), cache)
    assert db.get("phase", "missing") is None
    db.set("phase", "current", {"step": 2})
    assert db.get("phase", "current") == {"step": 2}
    db.set("phase", "current", {"step": 3})
    db.delete("phase", "missing")
    db.delete("phase", "current")
    assert db.get("phase", "current") is None

    db.save_task("task-1", "trace", "pending", {"status": "pending"})
    db.update_task("task-1", "done", {"status": "done"})
    assert db.task("task-1")["payload"] == {"status": "done"}
    assert db.task("unknown") is None

    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE bb_tasks SET payload='not-json' WHERE task_id='task-1'")
    assert db.task("task-1")["payload"] == {}

    memory = {}
    empty = MachineryDB("", memory)
    empty.set("fallback", "key", {"value": True})
    assert empty.get("fallback", "key") == {"value": True}
    empty.delete("fallback", "key")
    assert empty.get("fallback", "key") is None
    empty.save_task("x", "trace", "pending", {})

    bad = MachineryDB(str(tmp_path / "missing" / "db.sqlite"), {})
    bad.set("x", "y", 1)
    assert bad.get("x", "y") == 1
    bad.update_task("x", "done", {})


def test_task_pool_and_crawler_runtime_lifecycle_modes():
    pool = TaskPool(max_workers=1)
    completed = []
    assert pool.submit("one", lambda: completed.append("one")) is True
    pool.drain(timeout=2)
    assert completed == ["one"]
    assert pool.pending() == []
    pool.shutdown()
    pool.shutdown()
    assert pool.submit("after-shutdown", lambda: None) is False

    crawler = _CrawlerRuntime()
    assert crawler.mark_visited("0x1000") is True
    assert crawler.mark_visited("0x1000") is False
    assert crawler.visited_count() == 1
    started = threading.Event()

    def mark_started():
        started.set()

    crawler.start(mark_started)
    assert started.wait(2)
    crawler.start(lambda: None)
    crawler.stop()


class _Mixin:
    def __init__(self, *, trace_result=None, trace_error=None):
        self.current_session = SimpleNamespace(idb_path="/tmp/demo.i64")
        self.notifications = []
        self.statuses = []
        self.trace_result = trace_result
        self.trace_error = trace_error

    def _send_notification(self, payload):
        self.notifications.append(payload)

    def _create_trace_task(self, _store, *_args, **_kwargs):
        return "trace-1"

    def _set_task_status(self, _store, entry, status, payload):
        self.statuses.append((entry, status, payload))

    def _run_trace_task(self, _store, _entry, _payload):
        if self.trace_error:
            raise RuntimeError(self.trace_error)
        return self.trace_result or {"ok": True, "items": [1]}

    def _get_blackboard_store(self):
        return None

    def _write_crawler_proposal(self, _store, **kwargs):
        self.proposal = kwargs
        return "proposal-1"

    def _proposal_entries(self, _store, **_kwargs):
        return [{"id": "proposal-1", "addr": "0x1000", "title": "Found", "confidence": 0.8}]


def _store(tmp_path, targets=None):
    return SimpleNamespace(
        db_path=str(tmp_path / "workspace.sqlite"),
        targets=lambda *_args, **_kwargs: {"targets": list(targets or [])},
        next_target=lambda **_kwargs: [],
        read=lambda _entry_id: {"content": '{"status":"pending"}'},
        list=lambda **_kwargs: [],
    )


def test_orchestrator_trace_crawler_and_probe_modes(tmp_path):
    mixin = _Mixin()
    orch = BlackboardOrchestrator(mixin, max_workers=1)
    store = _store(tmp_path, [{"addr": "0x1000"}, {"address": "0x2000"}])

    assert orch.default_probe("0x1000")["findings"] == []
    mixin._execute_tool = lambda *_args, **_kwargs: {"name": "fn", "findings": ["interesting"], "labels": ["loader"]}
    probe = orch.default_probe("0x1000")
    assert probe["title"] == "fn" and probe["labels"] == ["loader"]
    orch._crawler._notify_fn = mixin._send_notification
    proposal = orch.crawl_step(store)
    assert proposal == "proposal-1"
    assert mixin.proposal["behavior_tags"] == ["loader"]
    assert orch.crawler_visited_count() == 1
    assert orch.pending_proposal_rows(store)[0]["proposal_id"] == "proposal-1"
    assert mixin.notifications
    assert orch.crawl_step(store) == "proposal-1"
    assert orch.crawl_step(store) is None

    trace_id = orch.enqueue_trace_task(store, "source", "text", 2, 5)
    assert trace_id == "trace-1"
    assert orch.trace_status_rows(store, "pending", 5) == []
    orch._run_one_trace(str(store.db_path), trace_id, {"id": trace_id}, {"status": "pending"}, fallback_store=store)
    assert any(status == "done" for _entry, status, _payload in mixin.statuses)
    orch.shutdown()
    orch.shutdown()


def test_orchestrator_trace_and_crawler_failure_fallbacks(tmp_path):
    mixin = _Mixin(trace_error="trace failed")
    orch = BlackboardOrchestrator(mixin, max_workers=1)
    store = _store(tmp_path, [{"entry_id": "0x1000"}, {"addr": ""}])
    mixin._execute_tool = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
    assert orch.default_probe("0x1000")["findings"] == []
    assert orch.crawl_step(store) is None
    orch._run_one_trace("", "trace-2", {}, {"status": "running"})
    assert orch._machinery_for(store).task("missing") is None
    orch._run_one_trace(str(store.db_path), "trace-3", {}, {"status": "running"}, fallback_store=store)
    assert any(status == "failed" for _entry, status, _payload in mixin.statuses)
    assert is_governance_error({"error": True, "code": "POLICY_DENIED"}) is True
    assert is_governance_error({"error": True, "code": "OTHER"}) is False
    orch.shutdown()
