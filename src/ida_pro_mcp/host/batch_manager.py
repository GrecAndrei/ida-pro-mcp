from __future__ import annotations

import contextlib
import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .errors import MCPError, make_error

_MAX_TASK_HISTORY = 1000
_DEFAULT_MAX_WORKERS = int(os.environ.get("IDA_MCP_BATCH_MAX_WORKERS", "4"))
_PERSIST_PATH = os.path.join(
    os.environ.get("IDA_MCP_BATCH_STATE_DIR", os.path.join(os.path.expanduser("~"), ".ida-mcp-batch")),
    "tasks.json",
)
_MAX_PERSIST_RESULT_BYTES = 10_000
_MAX_PERSIST_FIELDS = {"task_id", "session_id", "action", "args", "state", "created_at", "started_at", "finished_at", "result", "error"}


@dataclass
class BatchTask:
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str | None = None
    action: str = "script"
    args: dict[str, Any] = field(default_factory=dict)
    state: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: Any = None
    error: str | None = None
    progress: str | None = None
    _future: Future | None = field(default=None, repr=False)
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "session_id": self.session_id,
            "action": self.action,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.elapsed, 3),
            "progress": self.progress,
            "result": self.result if self.state == "done" else None,
            "error": self.error,
        }


class BatchManager:
    def __init__(self, max_workers: int = _DEFAULT_MAX_WORKERS):
        self._lock = threading.Lock()
        self._tasks: dict[str, BatchTask] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="batch-")
        self._load_persisted()

    def submit(
        self,
        action: str,
        args: dict[str, Any],
        *,
        session_id: str | None = None,
        run_fn: Callable[[BatchTask], Any] | None = None,
    ) -> str:
        task = BatchTask(action=action, args=args, session_id=session_id)
        with self._lock:
            self._tasks[task.task_id] = task
            self._trim_history()
        task.state = "pending"
        future = self._executor.submit(self._run_task, task, run_fn)
        task._future = future
        return task.task_id

    def _run_task(self, task: BatchTask, run_fn: Callable[[BatchTask], Any] | None) -> None:
        try:
            task.started_at = time.time()
            task.state = "running"
            if task._cancel_event.is_set():
                task.state = "cancelled"
                task.finished_at = time.time()
                return
            result = run_fn(task) if run_fn is not None else {"status": "completed", "action": task.action}
            if task._cancel_event.is_set():
                task.state = "cancelled"
                task.finished_at = time.time()
                return
            task.result = result
            task.state = "done"
        except Exception as exc:
            task.error = str(exc)
            task.state = "failed"
        finally:
            task.finished_at = time.time()
            self._save_persisted()

    def status(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if task_id:
                task = self._tasks.get(task_id)
                return [task.to_dict()] if task else []
            return [t.to_dict() for t in list(self._tasks.values())]

    def result(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return make_error(MCPError.NOT_FOUND, f"task {task_id} not found")
        if task._future:
            with contextlib.suppress(Exception):
                task._future.result(timeout=0)
        return task.to_dict()

    def cancel(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return make_error(MCPError.NOT_FOUND, f"task {task_id} not found")
        if task.state in ("done", "failed", "cancelled"):
            return make_error(
                MCPError.INVALID_ARGS,
                f"task {task_id} already {task.state}",
                hint="Cancellation only applies to pending or running tasks.",
            )
        task._cancel_event.set()
        if task._future and not task._future.done():
            task._future.cancel()
        task.state = "cancelled"
        task.finished_at = time.time()
        self._save_persisted()
        return task.to_dict()

    def wait(self, task_id: str, timeout: float | None = None) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return make_error(MCPError.NOT_FOUND, f"task {task_id} not found")
        if task._future is None:
            return task.to_dict()
        with contextlib.suppress(Exception):
            task._future.result(timeout=timeout)
        return task.to_dict()

    def list_tasks(self, state: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            tasks = list(self._tasks.values())
            if state:
                tasks = [t for t in tasks if t.state == state]
            tasks.sort(key=lambda t: t.created_at, reverse=True)
            return [t.to_dict() for t in tasks]

    def _trim_history(self) -> None:
        if len(self._tasks) > _MAX_TASK_HISTORY:
            oldest = sorted(
                self._tasks.values(),
                key=lambda t: t.created_at,
                reverse=False,
            )[: len(self._tasks) - _MAX_TASK_HISTORY]
            for t in oldest:
                del self._tasks[t.task_id]

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    def _persist_path(self) -> str:
        os.makedirs(os.path.dirname(_PERSIST_PATH), exist_ok=True)
        return _PERSIST_PATH

    def _save_persisted(self) -> None:
        try:
            data = []
            with self._lock:
                for t in list(self._tasks.values()):
                    if t.state in ("done", "failed", "cancelled"):
                        d = t.to_dict()
                        r = d.get("result")
                        if r is not None:
                            try:
                                raw = json.dumps(r, default=str)
                                if len(raw) > _MAX_PERSIST_RESULT_BYTES:
                                    d["result"] = {"_truncated": True, "preview": str(r)[:_MAX_PERSIST_RESULT_BYTES]}
                            except Exception:
                                d["result"] = str(r)[:_MAX_PERSIST_RESULT_BYTES]
                        data.append({k: v for k, v in d.items() if k in _MAX_PERSIST_FIELDS})
            if data:
                with open(self._persist_path(), "w") as f:
                    json.dump(data[-_MAX_TASK_HISTORY:], f, default=str)
        except Exception:
            pass

    def _load_persisted(self) -> None:
        if not os.path.exists(_PERSIST_PATH):
            return
        try:
            with open(_PERSIST_PATH) as f:
                data = json.load(f)
            for d in data:
                t = BatchTask(
                    task_id=d.get("task_id", uuid.uuid4().hex[:12]),
                    session_id=d.get("session_id"),
                    action=d.get("action", "script"),
                    args=d.get("args", {}),
                )
                t.state = d.get("state", "done")
                t.created_at = d.get("created_at", time.time())
                t.started_at = d.get("started_at")
                t.finished_at = d.get("finished_at")
                t.result = d.get("result")
                t.error = d.get("error")
                with self._lock:
                    self._tasks[t.task_id] = t
        except Exception:
            pass
