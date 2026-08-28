"""Blackboard orchestration: bounded task runner, crawler, trace executor,
and the durable machinery store.

The redesign separates analyst memory from machinery:

* analyst memory lives in the store's findings table (written via ``store.write`` /
  ``store.upsert_finding``);
* machinery -- crawler state, trace tasks, evidence-gravity snapshots, and the
  per-session phase/policy core -- lives in dedicated ``bb_machinery`` /
  ``bb_tasks`` tables on the workspace DB.

This module owns that machinery and the background execution that uses it:

* a bounded worker pool that executes queued tasks off the request thread;
* a frontier crawler that writes *real* proposed entries (status ``proposed``)
  and notifies the client with the real entry id;
* an async trace executor: ``trace_run`` enqueues pending tasks and returns a
  task id immediately instead of blocking the request thread.

All table access is defensive: the tables are created idempotently and every
read/write falls back to in-memory state when the table layout is unavailable
or incompatible, so the host keeps working whether or not the store itself
defines the machinery tables yet.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any, Callable

#: Upper bound on evidence items carried in one gravity snapshot.
EVIDENCE_GRAVITY_MAX_ITEMS = 8

#: Machinery namespace for the per-session phase core.
NS_PHASE = "phase"
#: Machinery namespace for the per-session policy core.
NS_POLICY = "policy"
#: Machinery namespace for evidence-gravity snapshots.
NS_GRAVITY = "gravity"
#: Machinery namespace for crawler state.
NS_CRAWLER = "crawler"

#: Task types recorded in ``bb_tasks``.
TASK_TRACE = "trace"
TASK_CRAWLER = "crawler"
_MACHINERY_BUSY_TIMEOUT_MS = 30_000


def _machinery_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bb_machinery (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            namespace  TEXT NOT NULL DEFAULT '',
            key        TEXT NOT NULL,
            value      TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bb_machinery_ns_key "
        "ON bb_machinery(namespace, key)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bb_tasks (
            task_id    TEXT PRIMARY KEY,
            task_type  TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending',
            payload    TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bb_tasks_status ON bb_tasks(status)"
    )


class MachineryDB:
    """Defensive durable key/value + task store over the workspace DB.

    Reads and writes are wrapped so an incompatible table layout degrades to
    in-memory state instead of raising: the caller always gets a value back,
    and ``set`` silently keeps a memory cache when the table is unusable.
    """

    def __init__(self, db_path: str, memory_cache: dict):
        self.db_path = db_path
        self._memory_cache = memory_cache
        self._usable: bool | None = bool(str(db_path or "").strip())

    # -- connection ---------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, timeout=float(_MACHINERY_BUSY_TIMEOUT_MS) / 1000.0
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_MACHINERY_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure(self) -> bool:
        if self._usable is False:
            return False
        try:
            with closing(self._conn()) as conn:
                _machinery_schema(conn)
                conn.commit()
            self._usable = True
            return True
        except (sqlite3.Error, OSError):
            self._usable = False
            return False

    # -- key/value (bb_machinery) ------------------------------------------

    def get(self, namespace: str, key: str):
        cache_key = (str(namespace or ""), str(key or ""))
        if not self._ensure():
            return self._memory_cache.get(cache_key)
        try:
            with closing(self._conn()) as conn:
                row = conn.execute(
                    "SELECT value FROM bb_machinery WHERE namespace=? AND key=?",
                    (cache_key[0], cache_key[1]),
                ).fetchone()
            if row is None:
                return self._memory_cache.get(cache_key)
            value = json.loads(row["value"])
            self._memory_cache[cache_key] = value
            return value
        except (sqlite3.Error, OSError, ValueError):
            self._usable = False
            return self._memory_cache.get(cache_key)

    def set(self, namespace: str, key: str, value: Any) -> None:
        cache_key = (str(namespace or ""), str(key or ""))
        self._memory_cache[cache_key] = value
        if not self._ensure():
            return
        try:
            payload = json.dumps(value, ensure_ascii=True, sort_keys=True)
            now = time.time()
            with closing(self._conn()) as conn:
                conn.execute(
                    "INSERT INTO bb_machinery(namespace, key, value, updated_at) "
                    "VALUES (?,?,?,?) "
                    "ON CONFLICT(namespace, key) DO UPDATE SET "
                    "value=excluded.value, updated_at=excluded.updated_at",
                    (cache_key[0], cache_key[1], payload, now),
                )
                conn.commit()
        except (sqlite3.Error, OSError, ValueError):
            self._usable = False

    def delete(self, namespace: str, key: str) -> None:
        cache_key = (str(namespace or ""), str(key or ""))
        self._memory_cache.pop(cache_key, None)
        if not self._ensure():
            return
        try:
            with closing(self._conn()) as conn:
                conn.execute(
                    "DELETE FROM bb_machinery WHERE namespace=? AND key=?",
                    (cache_key[0], cache_key[1]),
                )
                conn.commit()
        except (sqlite3.Error, OSError):
            self._usable = False

    # -- tasks (bb_tasks) ---------------------------------------------------

    def save_task(
        self, task_id: str, task_type: str, status: str, payload: dict[str, Any]
    ) -> None:
        if not self._ensure():
            return
        try:
            now = time.time()
            data = json.dumps(payload or {}, ensure_ascii=True, sort_keys=True)
            with closing(self._conn()) as conn:
                conn.execute(
                    "INSERT INTO bb_tasks(task_id, task_type, status, payload, "
                    "created_at, updated_at) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(task_id) DO UPDATE SET status=excluded.status, "
                    "payload=excluded.payload, updated_at=excluded.updated_at",
                    (str(task_id), str(task_type), str(status), data, now, now),
                )
                conn.commit()
        except (sqlite3.Error, OSError, ValueError):
            self._usable = False

    def update_task(self, task_id: str, status: str, payload: dict[str, Any]) -> None:
        if not self._ensure():
            return
        try:
            now = time.time()
            data = json.dumps(payload or {}, ensure_ascii=True, sort_keys=True)
            with closing(self._conn()) as conn:
                conn.execute(
                    "UPDATE bb_tasks SET status=?, payload=?, updated_at=? "
                    "WHERE task_id=?",
                    (str(status), data, now, str(task_id)),
                )
                conn.commit()
        except (sqlite3.Error, OSError, ValueError):
            self._usable = False

    def task(self, task_id: str) -> dict[str, Any] | None:
        if not self._ensure():
            return None
        try:
            with closing(self._conn()) as conn:
                row = conn.execute(
                    "SELECT * FROM bb_tasks WHERE task_id=?", (str(task_id),)
                ).fetchone()
            if row is None:
                return None
            out = dict(row)
            try:
                out["payload"] = json.loads(out.get("payload") or "{}")
            except ValueError:
                out["payload"] = {}
            return out
        except (sqlite3.Error, OSError):
            self._usable = False
            return None


class TaskPool:
    """A bounded worker pool whose tasks never block the request thread.

    ``submit`` returns immediately with a task id; ``drain`` lets tests (and
    callers that must observe results) wait for outstanding work. Idle worker
    threads are cleaned up by the interpreter's ``ThreadPoolExecutor`` exit
    hook, so a long-lived host never accumulates them and a test process never
    hangs on them.
    """

    def __init__(self, max_workers: int = 2):
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers or 1)),
            thread_name_prefix="bb-task",
        )
        self._futures: dict[str, Any] = {}
        self._lock = threading.Lock()

    def submit(self, task_id: str, fn: Callable[[], None]) -> bool:
        """Run ``fn`` on the pool; returns True when queued."""
        try:
            future = self._executor.submit(fn)
        except RuntimeError:
            return False
        with self._lock:
            self._futures[str(task_id)] = future
        future.add_done_callback(self._forget)
        return True

    def _forget(self, future) -> None:
        with self._lock:
            for task_id, fut in list(self._futures.items()):
                if fut is future:
                    self._futures.pop(task_id, None)
                    return

    def pending(self) -> list[str]:
        with self._lock:
            return sorted(self._futures.keys())

    def drain(self, timeout: float = 15.0) -> None:
        with self._lock:
            futures = list(self._futures.values())
        deadline = time.monotonic() + max(0.0, float(timeout))
        for future in futures:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with contextlib.suppress(Exception):
                future.result(timeout=remaining)

    def shutdown(self) -> None:
        with contextlib.suppress(RuntimeError):
            self._executor.shutdown(wait=False, cancel_futures=True)


class _CrawlerRuntime:
    """State for the background frontier crawler (one per host)."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._visited: set[str] = set()
        self._visited_count = 0
        self._probe: Callable[[str], dict[str, Any]] | None = None
        self._notify_fn: Callable[[dict], None] | None = None
        self._lock = threading.Lock()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, loop_fn: Callable[[], None]) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=loop_fn, daemon=True, name="bb-crawler"
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def mark_visited(self, addr: str) -> bool:
        with self._lock:
            if addr in self._visited:
                return False
            self._visited.add(addr)
            self._visited_count += 1
            return True

    def visited_count(self) -> int:
        return int(self._visited_count)


class BlackboardOrchestrator:
    """Host-side orchestration for the blackboard: machinery, tasks, crawler.

    Bound to the server mixin so it can reach the runtime hooks
    (``_execute_tool``, ``_send_notification``, the store class) without
    importing the server module. Every method here is safe to call with no
    live IDA session: the crawler's probe and the trace executor simply
    collect no evidence, exactly as a no-runtime session already behaves.
    """

    def __init__(self, mixin, max_workers: int = 2):
        self._mixin = mixin
        self._pool = TaskPool(max_workers=max_workers)
        self._crawler = _CrawlerRuntime()
        self._machinery_cache: dict = {}
        self._machinery: dict[str, MachineryDB] = {}
        self._shutdown = False
        self._trace_submit_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._crawler.stop()
        self._pool.shutdown()

    def drain(self, timeout: float = 15.0) -> None:
        """Wait for enqueued trace tasks to finish.

        ``run_pending_trace_tasks`` returns immediately (non-blocking); call
        this when a caller must observe completed results before reading
        ``trace_status`` — tests, the CLI, and any synchronous consumer.
        """
        self._pool.drain(timeout=timeout)

    # -- machinery access ---------------------------------------------------

    def _machinery_for(self, store) -> MachineryDB:
        db_path = str(getattr(store, "db_path", "") or "").strip()
        if not db_path:
            return MachineryDB("", self._machinery_cache)
        inst = self._machinery.get(db_path)
        if inst is None:
            inst = MachineryDB(db_path, self._machinery_cache)
            self._machinery[db_path] = inst
        return inst

    def machinery_get(self, store, namespace: str, key: str, default=None):
        value = self._machinery_for(store).get(namespace, key)
        return default if value is None else value

    def machinery_set(self, store, namespace: str, key: str, value: Any) -> None:
        self._machinery_for(store).set(namespace, key, value)

    def machinery_delete(self, store, namespace: str, key: str) -> None:
        self._machinery_for(store).delete(namespace, key)

    def machinery_snapshot_keys(self, store, namespace: str) -> list[str]:
        db_path = str(getattr(store, "db_path", "") or "").strip()
        if not db_path:
            return []
        try:
            with closing(sqlite3.connect(db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT key FROM bb_machinery WHERE namespace=? "
                    "ORDER BY id DESC",
                    (str(namespace),),
                ).fetchall()
            return [str(r["key"]) for r in rows]
        except (sqlite3.Error, OSError):
            return []

    # -- trace executor -----------------------------------------------------

    def _open_store(self, db_path: str):
        mod = getattr(type(self._mixin), "_blackboard_module", None)
        if mod is None or not db_path:
            return None
        try:
            return mod.BlackboardStore(db_path=db_path)
        except Exception:
            return None

    def enqueue_trace_task(
        self, store, source_entry_id: str, source_text: str, depth: int, limit: int
    ) -> str:
        """Persist a pending trace task and return its task id."""
        entry_id = self._mixin._create_trace_task(
            store, source_entry_id, source_text, depth=depth, limit=limit
        )
        try:
            entry = store.read(entry_id)
            payload = {}
            if entry:
                try:
                    payload = json.loads(str(entry.get("content") or "{}"))
                except Exception:
                    payload = {}
            self._machinery_for(store).save_task(
                entry_id, TASK_TRACE, str(payload.get("status") or "pending"), payload
            )
        except Exception:
            pass
        return entry_id

    def run_pending_trace_tasks(self, store, limit: int) -> dict[str, Any]:
        """Enqueue pending trace tasks onto the worker pool.

        Returns immediately; ``drain()`` waits for the background execution so
        a caller that must observe results (tests, the CLI) can synchronize.
        """
        pending = []
        try:
            rows = store.list(
                category="trace_task",
                include_resolved=True,
                include_contradicted=True,
                limit=max(50, int(limit or 3) * 4),
            )
            for entry in rows:
                payload = {}
                try:
                    payload = json.loads(str(entry.get("content") or "{}"))
                except Exception:
                    payload = {}
                if str(payload.get("status") or "").strip().lower() == "pending":
                    pending.append((str(entry.get("id") or ""), entry, payload))
        except Exception:
            pending = []
        pending = pending[: max(1, int(limit or 3))]
        task_ids: list[str] = []
        db_path = str(getattr(store, "db_path", "") or "").strip()
        machinery = self._machinery_for(store)
        for entry_id, entry, payload in pending:
            if not entry_id:
                continue
            # Claim against the visible payload before queueing.  The worker
            # runs asynchronously, so merely updating bb_tasks here leaves a
            # window where a second MCP request can observe the original
            # pending finding and enqueue the same trace again.
            with self._trace_submit_lock:
                current = entry
                current_payload = payload
                with contextlib.suppress(Exception):
                    reread = store.read(entry_id)
                    if reread:
                        current = reread
                        current_payload = json.loads(str(reread.get("content") or "{}"))
                if not isinstance(current_payload, dict):
                    current_payload = {}
                if str(current_payload.get("status") or "").strip().lower() != "pending":
                    continue
                running_payload = dict(current_payload)
                running_payload["status"] = "running"
                try:
                    self._mixin._set_task_status(
                        store, current, "running", running_payload
                    )
                except Exception:
                    # Do not queue work that cannot be durably claimed.
                    continue
                machinery.update_task(entry_id, "running", running_payload)
                queued = self._pool.submit(
                    entry_id,
                    lambda eid=entry_id, e=current, p=running_payload: self._run_one_trace(
                        db_path, eid, e, p, fallback_store=store
                    ),
                )
            if queued:
                task_ids.append(entry_id)
                continue
            failed_payload = dict(running_payload or {})
            failed_payload.update({
                "status": "failed",
                "error": "trace worker pool is unavailable",
            })
            with contextlib.suppress(Exception):
                self._mixin._set_task_status(
                    store, entry, "failed", failed_payload
                )
            machinery.update_task(entry_id, "failed", failed_payload)
        return {
            "ok": True,
            "enqueued": len(task_ids),
            "task_ids": task_ids,
            "status": "running",
        }

    def _run_one_trace(
        self,
        db_path: str,
        entry_id: str,
        entry: dict,
        payload: dict,
        fallback_store=None,
    ) -> None:
        store = self._open_store(db_path) or fallback_store or self._mixin._get_blackboard_store()
        if store is None:
            failed_payload = dict(payload or {})
            failed_payload.update({
                "status": "failed",
                "error": "blackboard store is unavailable",
                "result": {"ok": False, "error": "blackboard store is unavailable"},
            })
            # There is no visible findings store to update, but a valid DB
            # path still lets us close the durable machinery task instead of
            # leaving it permanently in running state.
            if db_path:
                with contextlib.suppress(Exception):
                    MachineryDB(db_path, self._machinery_cache).update_task(
                        entry_id, "failed", failed_payload
                    )
            return
        try:
            self._mixin._set_task_status(store, entry, "running", payload)
            result = self._mixin._run_trace_task(store, entry, payload)
            status = "done" if result.get("ok") else "failed"
            payload = dict(payload or {})
            payload["status"] = status
            payload["result"] = result
            self._mixin._set_task_status(store, entry, status, payload)
            self._machinery_for(store).update_task(entry_id, status, payload)
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            failed_payload = dict(payload or {})
            failed_payload.update({
                "status": "failed",
                "error": error,
                "result": {"ok": False, "error": error},
            })
            with contextlib.suppress(Exception):
                self._mixin._set_task_status(
                    store, entry, "failed", failed_payload
                )
            with contextlib.suppress(Exception):
                self._machinery_for(store).update_task(
                    entry_id, "failed", failed_payload
                )

    def trace_status_rows(self, store, status: str, limit: int) -> list[dict[str, Any]]:
        """Read trace task summaries from the store's trace_task entries."""
        rows = store.list(
            category="trace_task",
            include_resolved=True,
            include_contradicted=True,
            limit=limit,
        )
        summaries = []
        for t in rows:
            payload = {}
            try:
                payload = json.loads(str(t.get("content") or "{}"))
            except Exception:
                payload = {}
            task_status = str(payload.get("status") or "").strip().lower()
            if status and task_status != status:
                continue
            summaries.append(
                {
                    "trace_task_id": t.get("id"),
                    "title": t.get("title"),
                    "status": task_status or "unknown",
                    "addrs": (payload.get("entities") or {}).get("addrs", [])[:10],
                    "symbols": (payload.get("entities") or {}).get("symbols", [])[:10],
                    "result": payload.get("result") or {},
                }
            )
        return summaries

    # -- crawler ------------------------------------------------------------

    def default_probe(self, addr: str) -> dict[str, Any]:
        """Inspect an address through the runtime hook when one is live."""
        execute = getattr(self._mixin, "_execute_tool", None)
        if execute is None:
            return {"findings": [], "labels": [], "callees": [], "title": ""}
        try:
            res = execute("code", {"action": "smart_decompile", "addr": addr})
        except Exception:
            return {"findings": [], "labels": [], "callees": [], "title": ""}
        if not isinstance(res, dict):
            return {"findings": [], "labels": [], "callees": [], "title": ""}
        return {
            "findings": res.get("findings") or [],
            "labels": res.get("labels") or res.get("behavior_tags") or [],
            "callees": res.get("callees") or [],
            "title": str(res.get("name") or ""),
        }

    def start_crawler(self, store, probe=None, notify_fn=None) -> bool:
        self._crawler._probe = probe
        self._crawler._notify_fn = notify_fn or getattr(
            self._mixin, "_send_notification", None
        )
        db_path = str(getattr(store, "db_path", "") or "").strip()
        self._crawler.start(lambda: self._crawl_loop(db_path))
        return self._crawler.is_running()

    def stop_crawler(self) -> bool:
        self._crawler.stop()
        return False

    def crawler_is_running(self) -> bool:
        return self._crawler.is_running()

    def crawler_visited_count(self) -> int:
        return self._crawler.visited_count()

    def _crawl_loop(self, db_path: str) -> None:

        while not self._crawler._stop.wait(0.5):
            try:
                store = self._open_store(db_path)
                if store is not None:
                    self.crawl_step(store)
            except Exception:
                continue

    def _frontier_rpc(self, store):
        """Best-effort rpc_fn for the frontier strategy, or None."""
        mixin = self._mixin
        session = getattr(mixin, "current_session", None)
        idb_ref = str(getattr(session, "idb_path", "") or "") if session else ""
        if not idb_ref or not hasattr(mixin, "call_tool"):
            return None

        def rpc(tool: str, payload: dict[str, Any]):
            return mixin.call_tool(tool, idb_ref, **payload)

        return rpc

    def crawl_step(self, store) -> str | None:
        """One crawler iteration: frontier -> probe -> real proposed entry.

        Returns the new proposal entry id, or None when there was nothing to
        visit or the probe produced no finding. Runs synchronously so tests
        can drive it deterministically; the background loop calls it in turn.
        """
        rpc = self._frontier_rpc(store)
        try:
            frontier = store.targets("frontier", limit=25, rpc_fn=rpc)
            targets = frontier.get("targets") or []
        except Exception:
            targets = []
        if not targets:
            try:
                targets = store.next_target(limit=25)
            except Exception:
                targets = []
        addr = ""
        for target in targets:
            cand = str(
                target.get("addr")
                or target.get("address")
                or target.get("entry_id")
                or ""
            ).strip()
            if not cand:
                continue
            if cand in self._crawler._visited:
                continue
            addr = cand
            break
        if not addr:
            return None
        if not self._crawler.mark_visited(addr):
            return None
        probe = self._crawler._probe or self.default_probe
        probe_result = probe(addr) if probe else self.default_probe(addr)
        if not isinstance(probe_result, dict):
            probe_result = {}
        findings = probe_result.get("findings") or []
        if not findings:
            return None
        title = (
            str(probe_result.get("title") or "").strip()
            or f"Crawler quick analysis @ {addr}"
        )
        summary = str(findings[0])[:220]
        behavior_tags = [
            str(t) for t in (probe_result.get("labels") or []) if str(t).strip()
        ]
        entry_id = self._mixin._write_crawler_proposal(
            store,
            addr=addr,
            title=title,
            content=summary,
            behavior_tags=behavior_tags,
        )
        if entry_id:
            self._machinery_for(store).save_task(
                entry_id,
                TASK_CRAWLER,
                "proposed",
                {"addr": addr, "title": title, "behavior_tags": behavior_tags},
            )
            self._notify_proposal(entry_id, addr, title, behavior_tags)
        return entry_id

    def _notify_proposal(
        self, entry_id: str, addr: str, title: str, behavior_tags: list[str]
    ) -> None:
        notify = self._crawler._notify_fn
        if notify is None:
            return
        with contextlib.suppress(Exception):
            notify(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "logger": "blackboard.crawler",
                        "data": {
                            "message": (
                                "Crawler generated a proposal. Call blackboard "
                                "proposal_accept(entry_id=<id>) or "
                                "proposal_reject(entry_id=<id>) to accept or reject it."
                            ),
                            "proposals": [
                                {
                                    "proposal_id": entry_id,
                                    "addr": addr,
                                    "title": title,
                                    "behavior_tags": behavior_tags,
                                }
                            ],
                        },
                    },
                }
            )

    def pending_proposal_rows(self, store, limit: int = 50) -> list[dict[str, Any]]:
        """Real proposed entries, rendered as crawler-style proposal rows."""
        rows = self._mixin._proposal_entries(store, status="proposed", limit=limit)
        out = []
        for e in rows:
            out.append(
                {
                    "proposal_id": e.get("id") or e.get("entry_id"),
                    "addr": e.get("addr"),
                    "title": e.get("title"),
                    "confidence": e.get("confidence"),
                    "behavior_tags": [],
                }
            )
        return out


def is_governance_error(result: dict) -> bool:
    """True when a dispatch result is a POLICY_DENIED governance envelope."""
    return bool(result.get("error")) and str(result.get("code") or "") == "POLICY_DENIED"


__all__ = [
    "BlackboardOrchestrator",
    "EVIDENCE_GRAVITY_MAX_ITEMS",
    "MachineryDB",
    "NS_CRAWLER",
    "NS_GRAVITY",
    "NS_PHASE",
    "NS_POLICY",
    "TASK_CRAWLER",
    "TASK_TRACE",
    "TaskPool",
    "is_governance_error",
]
