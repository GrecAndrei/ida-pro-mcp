from __future__ import annotations

import time

import pytest

from ida_pro_mcp.services import BatchManager, BatchTask


def test_submit_and_status():
    mgr = BatchManager(max_workers=1)
    task_id = mgr.submit("script", {"x": 1})
    tasks = mgr.status()
    found = any(t["task_id"] == task_id for t in tasks)
    assert found, f"task {task_id} not found in {tasks}"
    matching = [t for t in tasks if t["task_id"] == task_id]
    assert matching[0]["state"] in ("pending", "running", "done")


def test_submit_with_run_fn():
    mgr = BatchManager(max_workers=1)
    results = []

    def _collect(task):
        results.append(task.action)
        return {"done": True}

    task_id = mgr.submit("script", {"x": 1}, run_fn=_collect)
    result = mgr.wait(task_id, timeout=5)
    assert result["state"] == "done"
    assert result["result"] == {"done": True}
    assert results == ["script"]


def test_cancel():
    mgr = BatchManager(max_workers=1)
    ready = []

    def _slow(task):
        ready.append(1)
        for _ in range(100):
            if task._cancel_event.is_set():
                return
            time.sleep(0.01)

    task_id = mgr.submit("script", {}, run_fn=_slow)
    while not ready:
        time.sleep(0.01)
    cancel_result = mgr.cancel(task_id)
    assert cancel_result["state"] == "cancelled"


def test_list_tasks():
    mgr = BatchManager(max_workers=1)
    t1 = mgr.submit("script", {})
    t2 = mgr.submit("tool_call", {})

    tasks = mgr.list_tasks()
    assert len(tasks) >= 2
    ids = {t["task_id"] for t in tasks}
    assert t1 in ids
    assert t2 in ids


def test_status_nonexistent():
    mgr = BatchManager()
    tasks = mgr.status("nonexistent")
    assert tasks == []


def test_result_nonexistent():
    mgr = BatchManager()
    result = mgr.result("nonexistent")
    # Now goes through make_error — carries code/category/hint per error
    # envelope convention (see src/ida_pro_mcp/host/errors.py).
    assert result.get("error") is True
    assert result.get("category") == "user"
    assert "task nonexistent not found" in result.get("message", "")
    assert result.get("code") == "NOT_FOUND"


def test_wait_timeout():
    mgr = BatchManager(max_workers=1)
    ready = []

    def _block(task):
        ready.append(1)
        task._cancel_event.wait()

    task_id = mgr.submit("script", {}, run_fn=_block)
    while not ready:
        time.sleep(0.01)
    result = mgr.wait(task_id, timeout=0.1)
    assert result["state"] == "running"
    mgr.cancel(task_id)
