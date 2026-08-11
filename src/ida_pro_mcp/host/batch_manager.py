from __future__ import annotations

import atexit
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
# Base directory for per-instance task persistence. Each BatchManager writes
# only its own file (tasks-<instance>.json), so concurrent connections/processes
# never clobber each other's persisted task state.
_PERSIST_STATE_DIR = os.environ.get(
    "IDA_MCP_BATCH_STATE_DIR",
    os.path.join(os.path.expanduser("~"), ".ida-mcp-batch"),
)
# How long cancel() waits for a cooperative worker to honour the cancellation
# before reporting the transient state (a running worker cannot be aborted).
_CANCEL_GRACE_SECONDS = 1.0
_MAX_PERSIST_RESULT_BYTES = 10_000
_MAX_PERSIST_FIELDS = {"task_id", "session_id", "action", "args", "state", "created_at", "started_at", "finished_at", "result", "error"}
# D10: debounce interval for task-state persistence. State changes are recorded
# in memory immediately; the full-file rewrite to disk happens at most once per
# second, and shutdown() flushes a still-dirty state so the final transition is
# not lost on process exit.
_PERSIST_DEBOUNCE_SECONDS = 1.0


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
    progress: Any = None
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
            "result": self.result if self.state in {"done", "failed", "cancelled"} else None,
            "error": self.error,
        }


class BatchManager:
    def __init__(self, max_workers: int = _DEFAULT_MAX_WORKERS):
        self._lock = threading.Lock()
        self._tasks: dict[str, BatchTask] = {}
        self._instance_id = uuid.uuid4().hex[:12]
        self._max_workers = max_workers
        # The executor is created lazily and re-created on demand. It is
        # "parked" (shut down + dropped) as soon as the task queue is idle so
        # its non-daemon batch-* worker threads are reclaimed promptly instead
        # of lingering for the process lifetime. Threads carry the stable
        # "batch-" prefix and the pool stays bounded by max_workers.
        self._executor = self._new_executor()
        # Set by shutdown(); guards against submitting new work after teardown
        # and makes repeated shutdown() calls idempotent.
        self._shutdown = False
        # D10: persistence debounce state. _dirty records that a write is owed;
        # _persist_lock serializes the read-snapshot + write; _last_persist_time
        # gates the ≤1/sec rate; _persist_path_cached avoids re-stating/mkdir on
        # every save (os.makedirs was previously on the hot path).
        self._persist_lock = threading.Lock()
        self._dirty = False
        self._last_persist_time = 0.0
        self._persist_path_cached: str | None = None
        self._load_persisted()
        # The host's server shutdown path does not reach the BatchManager, and
        # an idle pool otherwise leaves non-daemon workers alive for the whole
        # process. Joining them at interpreter exit prevents orphaned workers
        # after a stdio/daemon exit. (Per-instance reclamation is handled by
        # _maybe_park_idle_executor, so this exit net does not pin threads.)
        atexit.register(self.shutdown)

    def _new_executor(self) -> ThreadPoolExecutor:
        return ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="batch-"
        )

    def submit(
        self,
        action: str,
        args: dict[str, Any],
        *,
        session_id: str | None = None,
        run_fn: Callable[[BatchTask], Any] | None = None,
    ) -> str:
        task = BatchTask(action=action, args=args, session_id=session_id)
        # The whole add+queue sequence holds the lock so a concurrently
        # finishing worker cannot park the executor between the task being
        # recorded as pending and its future being queued (parking only skips
        # when no task is pending/running, so the new task must already be
        # visible).
        with self._lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            if self._executor is None:
                self._executor = self._new_executor()
            task.state = "pending"
            self._tasks[task.task_id] = task
            self._trim_history()
            future = self._executor.submit(self._run_task, task, run_fn)
        task._future = future
        return task.task_id

    def _run_task(self, task: BatchTask, run_fn: Callable[[BatchTask], Any] | None) -> None:
        try:
            with self._lock:
                task.started_at = time.time()
                task.state = "running"
            if task._cancel_event.is_set():
                with self._lock:
                    task.state = "cancelled"
                    task.finished_at = time.time()
                return
            result = run_fn(task) if run_fn is not None else {"status": "completed", "action": task.action}
            if task._cancel_event.is_set():
                if result is None or (isinstance(result, dict) and result.get("cancelled")):
                    # The worker honoured the cancellation and aborted early
                    # (semantic-index jobs return {"cancelled": True, ...}).
                    # Preserve its payload (e.g. a resume cursor) instead of
                    # silently discarding the completed work.
                    with self._lock:
                        task.result = result
                        task.state = "cancelled"
                        task.finished_at = time.time()
                    return
                # The worker ran to completion despite the cancel request; the
                # work actually happened (e.g. a rename/patch), so report it as
                # done with its result rather than as a false cancellation.
            with self._lock:
                task.result = result
                task.state = "done"
        except Exception as exc:
            with self._lock:
                task.error = str(exc)
                task.state = "failed"
        finally:
            with self._lock:
                task.finished_at = time.time()
                # Once no task is pending/running the pool has nothing left to
                # do; park it so its batch-* worker threads exit instead of
                # idling for the process lifetime.
                self._maybe_park_idle_executor()
            self._save_persisted()

    def _maybe_park_idle_executor(self) -> None:
        """Shut down and drop the executor when no task is in flight.

        Caller holds _lock. Worker threads for a parked executor consume a
        shutdown sentinel and exit promptly; the next submit() lazily creates a
        fresh bounded pool. This keeps batch-* threads from accumulating across
        tests/instances while the executor stays bounded at max_workers.
        """
        executor = self._executor
        if executor is None:
            return
        if any(t.state in ("pending", "running") for t in self._tasks.values()):
            return
        self._executor = None
        # wait=False: this may run on the very worker that just finished the
        # last task; joining here would deadlock. Sentinels already queued make
        # the workers exit as soon as they drain.
        executor.shutdown(wait=False)

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
            # Check-and-set under the lock so a worker that just completed is
            # never flipped from 'done' to 'cancelled' (TOCTOU).
            if task.state in ("done", "failed", "cancelled"):
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"task {task_id} already {task.state}",
                    hint="Cancellation only applies to pending or running tasks.",
                )
            task._cancel_event.set()
            queued_aborted = bool(task._future is not None and task._future.cancel())
            if queued_aborted:
                # The worker never picked the task up: it is genuinely cancelled.
                task.state = "cancelled"
                task.finished_at = time.time()
        if not queued_aborted and task._future is not None:
            # A running task cannot be interrupted; cooperative workers abort on
            # the next cancel check. Give them a short grace window so the
            # reported state reflects the true outcome instead of claiming
            # 'cancelled' while the worker is still executing.
            with contextlib.suppress(Exception):
                task._future.result(timeout=_CANCEL_GRACE_SECONDS)
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
            # Never evict a task that is still pending or running: dropping it
            # would make status/result/cancel return NOT_FOUND while its future
            # is still executing in the pool.
            evictable = [
                t for t in self._tasks.values()
                if t.state not in ("pending", "running")
            ]
            oldest = sorted(evictable, key=lambda t: t.created_at)[
                : len(self._tasks) - _MAX_TASK_HISTORY
            ]
            for t in oldest:
                del self._tasks[t.task_id]

    def shutdown(self, wait: bool = True) -> None:
        # Idempotent: a parked (None) executor has no threads to join, and a
        # repeated call (atexit + explicit teardown) must not double-flush.
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=wait)
        # D10: flush a still-dirty state so the last transition is never lost
        # when the process exits (shutdown is registered via atexit).
        with self._persist_lock:
            if self._dirty:
                self._persist_now_locked()

    def _persist_path(self) -> str:
        if self._persist_path_cached:
            return self._persist_path_cached
        state_dir = os.environ.get("IDA_MCP_BATCH_STATE_DIR") or _PERSIST_STATE_DIR
        # makedirs once, not on every save — it only needs to guarantee the
        # first write can open the file. _load_persisted() calls this first in
        # __init__, so the directory exists before any task completes.
        with contextlib.suppress(Exception):
            os.makedirs(state_dir, exist_ok=True)
        path = os.path.join(state_dir, f"tasks-{self._instance_id}.json")
        self._persist_path_cached = path
        return path

    def _save_persisted(self) -> None:
        # D10: debounce to at most one disk write per second. Record the dirty
        # flag immediately (cheap, in-memory) and actually write only when the
        # debounce window has elapsed; a later flush captures every terminal
        # task, so skipping an intermediate write loses nothing.
        with self._persist_lock:
            self._dirty = True
            if time.time() - self._last_persist_time < _PERSIST_DEBOUNCE_SECONDS:
                return
            self._persist_now_locked()

    def _persist_now_locked(self) -> None:
        """Write terminal task state to disk. Caller holds _persist_lock."""
        try:
            with self._lock:
                data = []
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
                    path = self._persist_path()
                    payload = json.dumps(data[-_MAX_TASK_HISTORY:], default=str)
                    # Atomic write (temp file + rename) so a concurrent reader
                    # never observes a truncated JSON file; the lock above also
                    # serialises writers on this instance's path.
                    tmp_path = f"{path}.tmp"
                    with open(tmp_path, "w") as f:
                        f.write(payload)
                    os.replace(tmp_path, path)
            # Only a successful write clears the dirty flag and opens the next
            # debounce window; a transient failure stays dirty so the state is
            # retried on the next flush (e.g. shutdown).
            self._dirty = False
            self._last_persist_time = time.time()
        except Exception:
            pass

    def _load_persisted(self) -> None:
        path = self._persist_path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
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
