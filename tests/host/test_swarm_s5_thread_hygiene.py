"""Regression tests for the s09-thread-hygiene settle wave.

Covers BatchManager thread hygiene:
- No batch-* ThreadPoolExecutor worker threads may remain alive after the
  task queue goes idle (the pool is parked and its workers reclaimed, so
  threads do not accumulate across tests/instances for the process lifetime).
- An explicit shutdown() reclaims all batch-* threads and is idempotent.
- Submitting a fresh task after an idle park lazily recreates a bounded pool
  (still "batch-" prefixed, still max_workers-capped) and works normally.
- The D10 persist-debounce behavior is preserved: a still-dirty state is
  flushed on shutdown even after the executor was parked, and shutdown() does
  not double-flush.
- An opaque raw-blob / RISC-V shaped background job still reclaims its
  worker threads once done.

No live IDA is used; all work is driven by _FakeIda-style fakes (plain
run_fn callables) against a real BatchManager.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from ida_pro_mcp.host.batch_manager import BatchManager


def _live_batch_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("batch-")]


def _assert_no_batch_threads(timeout: float = 2.0) -> None:
    """Poll (bounded) until every batch-* thread has exited.

    A parked executor's workers consume a shutdown sentinel and exit within
    ~0.1s; the bounded poll guards against CI timing jitter without a hard
    busy-wait that could flake.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _live_batch_threads():
            return
        time.sleep(0.02)
    alive = [t.name for t in _live_batch_threads()]
    raise AssertionError(f"batch-* threads still alive after teardown: {alive}")


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


# ---------------------------------------------------------------------------
# Idle pool parking (the core regression)
# ---------------------------------------------------------------------------


def test_idle_batch_pool_reclaims_worker_threads():
    """Once every submitted task has finished, the idle executor must be
    parked so no batch-* worker lingers for the process lifetime. On the old
    code the worker threads blocked on the queue forever (atexit only joined
    them at interpreter exit), so this failed."""
    mgr = BatchManager(max_workers=2)
    started = threading.Event()

    def _work(task):
        started.wait(timeout=5)
        return {"ok": True, "n": task.args.get("n")}

    try:
        ids = [mgr.submit("tool_call", {"n": i}, run_fn=_work) for i in range(4)]
        # Workers are genuinely busy, so the pool must be live.
        assert _wait_for(lambda: len(_live_batch_threads()) >= 1)
        started.set()
        for tid in ids:
            mgr.wait(tid, timeout=5)
        # The last completion parks the pool; workers drain their sentinels
        # and exit.
        _assert_no_batch_threads()
    finally:
        started.set()
        mgr.shutdown()


def test_explicit_shutdown_reclaims_threads_and_is_idempotent():
    """shutdown() joins batch-* workers (including one mid-task), and a
    repeated call (e.g. atexit after an explicit teardown) is a safe no-op."""
    mgr = BatchManager(max_workers=1)
    release = threading.Event()

    def _work(task):
        release.wait(timeout=5)
        return {"ok": True}

    mgr.submit("tool_call", {"x": 1}, run_fn=_work)
    assert _wait_for(lambda: len(_live_batch_threads()) >= 1)
    release.set()
    mgr.shutdown()  # joins the running worker
    _assert_no_batch_threads()
    # Second call must not raise or double-flush.
    mgr.shutdown()
    _assert_no_batch_threads()


def test_submit_after_idle_park_recreates_bounded_pool():
    """After the pool is parked idle, a fresh submit lazily recreates a
    bounded, still-"batch-"-prefixed executor and the task runs normally."""
    mgr = BatchManager(max_workers=1)
    release = threading.Event()

    def _work(task):
        release.wait(timeout=5)
        return {"ok": True}

    try:
        first = mgr.submit("tool_call", {}, run_fn=lambda task: {"ok": True})
        mgr.wait(first, timeout=5)
        _assert_no_batch_threads()
        assert mgr._executor is None, "idle pool should be parked"

        second = mgr.submit("tool_call", {}, run_fn=_work)
        assert mgr._executor is not None, "fresh submit must recreate the pool"
        assert mgr._executor._max_workers == 1, "recreated pool must stay bounded"
        release.set()
        mgr.wait(second, timeout=5)
        _assert_no_batch_threads()
    finally:
        release.set()
        mgr.shutdown()


def test_concurrent_burst_reclaims_threads_after_drain():
    """A burst that uses all max_workers concurrently must not leave workers
    behind once the queue drains (exercises parking under real concurrency)."""
    mgr = BatchManager(max_workers=3)
    started = threading.Event()
    release = threading.Event()
    barrier = threading.Barrier(3)

    def _slow(task):
        barrier.wait(timeout=5)  # force all 3 workers busy at once
        started.set()
        release.wait(timeout=5)
        return {"ok": True}

    try:
        ids = [mgr.submit("tool_call", {}, run_fn=_slow) for _ in range(3)]
        assert started.wait(timeout=5), "all three workers should be running"
        assert len(_live_batch_threads()) == 3
        release.set()
        for tid in ids:
            mgr.wait(tid, timeout=5)
        _assert_no_batch_threads()
    finally:
        release.set()
        mgr.shutdown()


# ---------------------------------------------------------------------------
# Opaque raw-blob / RISC-V shaped job
# ---------------------------------------------------------------------------


def test_opaque_riscv_blob_job_reclaims_thread():
    """An opaque raw-blob job (RISC-V flavored: no symbols, ELF section
    strings, decompiler unavailable) still reclaims its worker thread once the
    task is done. The executor is just a worker carrier; the payload shape must
    not change thread hygiene."""
    mgr = BatchManager(max_workers=1)
    try:
        def _analyze_opaque_blob(task):
            # Stand-in for arch_profile/code_helpers analysis of an opaque
            # RISC-V blob: no xrefs, no names, hex-only section view.
            blob = task.args.get("blob_hex", "")
            return {
                "status": "ok",
                "arch": "riscv",
                "mode": "opaque",
                "bitness": 64,
                "sections": [{"name": f".seg{i}", "range": f"0x{i:06x}-0x{i:06x}"} for i in range(3)],
                "symbols": 0,
                "strings": 0,
                "bytes_scanned": len(blob) // 2,
            }

        task_id = mgr.submit(
            "analysis",
            {"blob_hex": "13 01 00 00 93 01 00 00 97 00 00 00" * 64},
            run_fn=_analyze_opaque_blob,
        )
        res = mgr.wait(task_id, timeout=5)
        assert res["state"] == "done"
        assert res["result"]["arch"] == "riscv"
        assert res["result"]["symbols"] == 0
        _assert_no_batch_threads()
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------------------
# Persist-debounce preservation (D10)
# ---------------------------------------------------------------------------


def test_persist_flush_survives_idle_park(tmp_path, monkeypatch):
    """The D10 debounce must be unchanged by parking: a still-dirty state is
    flushed on shutdown, and shutdown() flushes exactly once even when the
    executor was already parked."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    writes = {"n": 0}
    real_replace = os.replace

    def counting_replace(src, dst):
        if str(dst).endswith(".json"):
            writes["n"] += 1
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", counting_replace)
    mgr = BatchManager(max_workers=1)
    try:
        task_id = mgr.submit("tool_call", {"x": 1}, run_fn=lambda task: {"ok": True})
        mgr.wait(task_id, timeout=5)
        # The pool is parked idle; the terminal write may be pending behind the
        # debounce window, so the file is not necessarily on disk yet.
        _assert_no_batch_threads()
        mgr.shutdown()
        assert writes["n"] == 1, "shutdown flushes the still-dirty terminal state once"
        data = json.loads(Path(mgr._persist_path()).read_text())
        assert len(data) == 1
        mgr.shutdown()  # idempotent: no second write
        assert writes["n"] == 1
    finally:
        mgr.shutdown()


def test_atexit_still_registered(monkeypatch):
    """The process-exit safety net stays in place: BatchManager still registers
    its own shutdown with atexit so a manager alive at interpreter exit joins
    its workers instead of hanging/orphaning them."""
    import atexit

    registered = []
    monkeypatch.setattr(
        atexit, "register", lambda func, *args, **kwargs: registered.append(func)
    )
    mgr = BatchManager(max_workers=1)
    try:
        assert any(
            getattr(getattr(func, "__self__", None), "_instance_id", None)
            == mgr._instance_id
            for func in registered
        )
    finally:
        mgr.shutdown()
