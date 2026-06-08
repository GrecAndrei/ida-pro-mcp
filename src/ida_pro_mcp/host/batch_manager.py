from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


_MAX_TASK_HISTORY = 1000
_DEFAULT_MAX_WORKERS = int(os.environ.get("IDA_MCP_BATCH_MAX_WORKERS", "4"))


@dataclass
class BatchTask:
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    action: str = "script"
    args: Dict[str, Any] = field(default_factory=dict)
    state: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None
    progress: Optional[str] = None
    _future: Optional[Future] = field(default=None, repr=False)
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return end - self.started_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
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
        self._tasks: Dict[str, BatchTask] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="batch-")

    def submit(
        self,
        action: str,
        args: Dict[str, Any],
        *,
        run_fn: Optional[Callable[[BatchTask], Any]] = None,
    ) -> str:
        task = BatchTask(action=action, args=args)
        with self._lock:
            self._tasks[task.task_id] = task
            self._trim_history()
        task.state = "pending"
        future = self._executor.submit(self._run_task, task, run_fn)
        task._future = future
        return task.task_id

    def _run_task(self, task: BatchTask, run_fn: Optional[Callable[[BatchTask], Any]]) -> None:
        try:
            task.started_at = time.time()
            task.state = "running"
            if task._cancel_event.is_set():
                task.state = "cancelled"
                task.finished_at = time.time()
                return
            if run_fn is not None:
                result = run_fn(task)
            else:
                result = {"status": "completed", "action": task.action}
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

    def status(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if task_id:
                task = self._tasks.get(task_id)
                return [task.to_dict()] if task else []
            return [t.to_dict() for t in list(self._tasks.values())]

    def result(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"task {task_id} not found"}
        if task._future:
            try:
                task._future.result(timeout=0)
            except Exception:
                pass
        return task.to_dict()

    def cancel(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"task {task_id} not found"}
        if task.state in ("done", "failed", "cancelled"):
            return {"error": f"task {task_id} already {task.state}"}
        task._cancel_event.set()
        if task._future and not task._future.done():
            task._future.cancel()
        task.state = "cancelled"
        task.finished_at = time.time()
        return task.to_dict()

    def wait(self, task_id: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"task {task_id} not found"}
        if task._future is None:
            return task.to_dict()
        try:
            task._future.result(timeout=timeout)
        except Exception:
            pass
        return task.to_dict()

    def list_tasks(self, state: Optional[str] = None) -> List[Dict[str, Any]]:
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
