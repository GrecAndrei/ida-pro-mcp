"""Offline lifecycle and persistence coverage for the background batch manager."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

import ida_pro_mcp.host.batch_manager as batch_module
from ida_pro_mcp.host.batch_manager import BatchManager, BatchTask


def _manager(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    return BatchManager(max_workers=1)


def test_submit_rejects_after_shutdown_and_rolls_back_executor_failure(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    manager.shutdown()
    with pytest.raises(RuntimeError, match="after shutdown"):
        manager.submit("script", {})

    manager = _manager(tmp_path, monkeypatch)

    class _BrokenExecutor:
        def submit(self, *_args):
            raise RuntimeError("executor rejected")

    manager._executor = _BrokenExecutor()
    with pytest.raises(RuntimeError, match="executor rejected"):
        manager.submit("script", {})
    assert manager.status() == []
    manager._executor = None
    manager.shutdown()


def test_worker_default_failure_and_pre_cancelled_paths(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    try:
        task_id = manager.submit("default", {})
        assert manager.wait(task_id, timeout=5)["state"] == "done"
        assert manager.result(task_id)["result"]["status"] == "completed"

        failed_id = manager.submit(
            "failure", {}, run_fn=lambda _task: (_ for _ in ()).throw(ValueError("bad worker"))
        )
        failed = manager.wait(failed_id, timeout=5)
        assert failed["state"] == "failed"
        assert failed["error"] == "bad worker"

        task = BatchTask(action="cancel-before-run")
        task._cancel_event.set()
        manager._run_task(task, None)
        assert task.state == "cancelled"
        assert task.finished_at is not None
    finally:
        manager.shutdown()


def test_cancel_finished_missing_and_futureless_tasks(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    try:
        done_id = manager.submit("done", {})
        manager.wait(done_id, timeout=5)
        already_done = manager.cancel(done_id)
        assert already_done["code"] == "INVALID_ARGS"
        assert manager.cancel("missing")["code"] == "NOT_FOUND"

        task = BatchTask(task_id="futureless", action="manual")
        manager._tasks[task.task_id] = task
        cancelled = manager.cancel(task.task_id)
        assert cancelled["state"] == "pending"
        assert manager.wait(task.task_id)["state"] == "pending"
        assert manager.result(task.task_id)["state"] == "pending"
    finally:
        manager.shutdown()


def test_wait_result_and_list_filters_cover_terminal_shapes(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    try:
        task_id = manager.submit("filtered", {})
        manager.wait(task_id, timeout=5)
        assert manager.list_tasks("done")[0]["task_id"] == task_id
        assert manager.list_tasks("failed") == []
        assert manager.status(task_id)[0]["task_id"] == task_id
        assert manager.result(task_id)["state"] == "done"
    finally:
        manager.shutdown()


def test_shutdown_cancels_queued_work_and_is_idempotent(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    started = threading.Event()

    def cooperative(task):
        started.set()
        task._cancel_event.wait(timeout=5)
        return {"cancelled": True, "cursor": "resume"}

    first = manager.submit("first", {}, run_fn=cooperative)
    assert started.wait(timeout=5)
    second = manager.submit("second", {}, run_fn=lambda _task: {"done": True})
    manager.shutdown(wait=True)
    assert manager.status(first)[0]["state"] == "cancelled"
    assert manager.status(second)[0]["state"] == "cancelled"
    manager.shutdown()


def test_cancel_queued_future_marks_it_cancelled(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    started = threading.Event()

    def blocker(task):
        started.set()
        task._cancel_event.wait(timeout=5)

    running = manager.submit("running", {}, run_fn=blocker)
    assert started.wait(timeout=5)
    queued = manager.submit("queued", {}, run_fn=lambda _task: {"done": True})
    assert manager.cancel(queued)["state"] == "cancelled"
    manager.cancel(running)
    manager.shutdown()


def test_trim_history_only_evicts_old_terminal_tasks(tmp_path, monkeypatch):
    monkeypatch.setattr(batch_module, "_MAX_TASK_HISTORY", 1)
    manager = _manager(tmp_path, monkeypatch)
    try:
        old = BatchTask(task_id="old", action="old")
        old.state = "done"
        old.created_at = 1
        current = BatchTask(task_id="current", action="current")
        current.state = "running"
        current.created_at = 2
        newest = BatchTask(task_id="newest", action="newest")
        newest.state = "done"
        newest.created_at = 3
        manager._tasks = {old.task_id: old, current.task_id: current, newest.task_id: newest}
        manager._trim_history()
        assert set(manager._tasks) == {"current"}
    finally:
        manager._executor = None
        manager.shutdown()


def test_persistence_truncates_large_results_and_handles_result_serialization(
    tmp_path, monkeypatch
):
    manager = _manager(tmp_path, monkeypatch)
    try:
        large = BatchTask(task_id="large", action="large")
        large.state = "done"
        large.result = "x" * (batch_module._MAX_PERSIST_RESULT_BYTES + 10)
        manager._tasks[large.task_id] = large
        manager._persist_now_locked()
        path = next(tmp_path.glob("tasks-*.json"))
        persisted = json.loads(path.read_text(encoding="utf-8"))
        assert persisted[0]["result"]["_truncated"] is True

        broken = BatchTask(task_id="broken", action="broken")
        broken.state = "done"
        broken.result = object()
        manager._tasks[broken.task_id] = broken
        original_dumps = batch_module.json.dumps

        def selective_dumps(value, *args, **kwargs):
            if value is broken.result:
                raise TypeError("cannot encode result")
            return original_dumps(value, *args, **kwargs)

        monkeypatch.setattr(batch_module.json, "dumps", selective_dumps)
        manager._persist_now_locked()
        assert manager._dirty is False

        monkeypatch.setattr(
            batch_module.os,
            "replace",
            lambda *_args: (_ for _ in ()).throw(OSError("disk full")),
        )
        manager._dirty = True
        manager._persist_now_locked()
        assert manager._dirty is True
    finally:
        manager.shutdown()


def test_persistence_empty_flush_and_loader_validation(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    try:
        manager._persist_now_locked()
        assert list(tmp_path.glob("tasks-*.json")) == []
    finally:
        manager.shutdown()

    fixed = "1234567890abcdef1234567890abcdef"
    monkeypatch.setattr(batch_module.uuid, "uuid4", lambda: SimpleNamespace(hex=fixed))
    state_path = tmp_path / "tasks-1234567890ab.json"
    state_path.write_text(
        json.dumps(
            [
                {"task_id": "valid", "state": "done", "args": {"x": 1}},
                {"task_id": "bad-args", "state": "done", "args": []},
                {"task_id": "bad-state", "state": "unknown"},
                {"task_id": "", "state": "done"},
                4,
            ]
        ),
        encoding="utf-8",
    )
    loaded = _manager(tmp_path, monkeypatch)
    try:
        records = {entry["task_id"]: entry for entry in loaded.status()}
        assert set(records) == {"valid", "bad-args"}
    finally:
        loaded.shutdown()

    state_path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    invalid_shape = _manager(tmp_path, monkeypatch)
    invalid_shape.shutdown()

    state_path.write_text("not json", encoding="utf-8")
    corrupt = _manager(tmp_path, monkeypatch)
    corrupt.shutdown()
