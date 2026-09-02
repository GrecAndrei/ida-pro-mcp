from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid

import pytest

import ida_pro_mcp.host.batch_manager as batch_manager_module
from ida_pro_mcp.services import BatchManager, BatchTask


def test_batch_worker_env_is_safe_for_invalid_values():
    """Invalid worker-count overrides must not prevent the host from starting."""
    code = (
        "from ida_pro_mcp.host.batch_manager import BatchManager; "
        "print(BatchManager()._max_workers)"
    )
    for raw, expected in (("oops", 4), ("-1", 1), ("0", 1)):
        env = dict(os.environ, IDA_MCP_BATCH_MAX_WORKERS=raw)
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0, proc.stderr
        assert int(proc.stdout) == expected


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
    ready = threading.Event()

    def _slow(task):
        ready.set()
        task._cancel_event.wait()

    task_id = mgr.submit("script", {}, run_fn=_slow)
    assert ready.wait(timeout=5), "worker never started"
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
    ready = threading.Event()

    def _block(task):
        ready.set()
        task._cancel_event.wait()

    task_id = mgr.submit("script", {}, run_fn=_block)
    assert ready.wait(timeout=5), "worker never started"
    result = mgr.wait(task_id, timeout=0.1)
    assert result["state"] == "running"
    mgr.cancel(task_id)


def test_persisted_task_keeps_submission_args(tmp_path, monkeypatch):
    """Reloaded task history must retain the request that created the task.

    The public status response does not expose args, but the on-disk task
    record does. Losing them makes persisted background work impossible to
    audit or resume accurately after a restart.
    """
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    mgr = BatchManager(max_workers=1)
    task_id = mgr.submit(
        "tool_call",
        {"tool_call": {"tool": "calc", "args": {"action": "eval", "expr": "2+2"}}},
    )
    mgr.wait(task_id, timeout=5)
    mgr.shutdown()

    state_files = list(tmp_path.glob("tasks-*.json"))
    assert len(state_files) == 1
    state_path = state_files[0]
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted[0]["args"] == {
        "tool_call": {"tool": "calc", "args": {"action": "eval", "expr": "2+2"}}
    }


def test_persisted_loader_skips_bad_records_and_recovers_inflight_tasks(
    tmp_path, monkeypatch
):
    """One malformed record must not hide valid history or fake liveness."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    fixed_uuid = uuid.UUID("1234567890abcdef1234567890abcdef")
    monkeypatch.setattr(batch_manager_module.uuid, "uuid4", lambda: fixed_uuid)
    (tmp_path / "tasks-1234567890ab.json").write_text(
        json.dumps(
            [
                {"task_id": "first", "state": "done", "args": {"n": 1}},
                "damaged-record",
                {
                    "task_id": "interrupted",
                    "state": "running",
                    "args": {"n": 2},
                },
                {"task_id": "last", "state": "cancelled", "args": {"n": 3}},
            ]
        ),
        encoding="utf-8",
    )

    mgr = BatchManager(max_workers=1)
    try:
        tasks = {task["task_id"]: task for task in mgr.status()}
        assert set(tasks) == {"first", "interrupted", "last"}
        assert tasks["first"]["state"] == "done"
        assert tasks["last"]["state"] == "cancelled"
        assert tasks["interrupted"]["state"] == "failed"
        assert "restart" in tasks["interrupted"]["error"]
    finally:
        mgr.shutdown()
