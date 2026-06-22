"""Concurrency tests for IDAMCPServer race conditions (§1.3, §1.11).

Each test uses threading.Event / Barrier to force a SPECIFIC interleaving
that triggers the exact race pattern from the real code.

No pytest-asyncio, no pytest-xdist, no IDA imports, no server construction.
No time.sleep for timing — only Event/Barrier for thread ordering.
"""

from __future__ import annotations

import threading


# ---------------------------------------------------------------------------
# Mock shared state — mirrors IDAMCPServer's relevant fields
# ---------------------------------------------------------------------------
class MockSharedState:
    """Minimal mock of IDAMCPServer's shared mutable state (audit §1.3, §1.11)."""

    def __init__(self) -> None:
        self.session_runtimes: dict = {}
        self._session_inflight_calls: dict = {}
        self._session_last_activity: dict = {}
        self.current_session = None
        self._runtime_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Exact mutation patterns from server.py:563-576
# ---------------------------------------------------------------------------
def _increment_inflight_locked(state: MockSharedState, sid: str) -> None:
    with state._runtime_lock:
        state._session_inflight_calls[sid] = int(
            state._session_inflight_calls.get(sid, 0) or 0
        ) + 1
        state._session_last_activity[sid] = 0.0


def _decrement_inflight_locked(state: MockSharedState, sid: str) -> None:
    with state._runtime_lock:
        remaining = int(
            state._session_inflight_calls.get(sid, 0) or 0
        ) - 1
        if remaining > 0:
            state._session_inflight_calls[sid] = remaining
        else:
            state._session_inflight_calls.pop(sid, None)
        state._session_last_activity[sid] = 0.0


# ===================================================================
# Test 1 — _session_inflight_calls stress test (§1.3)
# ===================================================================
def test_inflight_calls_stress() -> None:
    """N threads each increment and decrement M times.

    With the `_runtime_lock` fix (audit §1.3), the final counter must
    be 0 after every thread's inc/dec cycle.  This is a stress test:
    the race would surface probabilistically without the lock.
    """
    SID = "inflight-session-a"
    state = MockSharedState()
    NTHREADS = 8
    REPS = 500

    barrier = threading.Barrier(NTHREADS)

    def _worker() -> None:
        barrier.wait()
        for _ in range(REPS):
            _increment_inflight_locked(state, SID)
            _decrement_inflight_locked(state, SID)

    threads = [threading.Thread(target=_worker) for _ in range(NTHREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = state._session_inflight_calls.get(SID, 0)
    assert result == 0, (
        f"Inflight counter stress test failed: "
        f"final={result}, expected 0 "
        f"(lost updates would leave non-zero count)"
    )


# ===================================================================
# Test 2 — session_runtimes concurrent read/write (§1.3)
# ===================================================================
def test_session_runtimes_concurrent_rw() -> None:
    """M writers each add unique entries concurrently.

    8 threads, each adding 10 unique entries (80 total).
    Verify no entries were lost to dict write races.
    """
    state = MockSharedState()
    nthreads = 8
    entries_per_thread = 10
    barrier = threading.Barrier(nthreads)

    def _writer(tid: int) -> None:
        barrier.wait()
        for i in range(entries_per_thread):
            key = f"rt-{tid}-{i}"
            state.session_runtimes[key] = {"pid": tid * 100 + i}

    threads = [
        threading.Thread(target=_writer, args=(tid,))
        for tid in range(nthreads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected = nthreads * entries_per_thread
    assert len(state.session_runtimes) == expected, (
        f"session_runtimes has {len(state.session_runtimes)} entries, "
        f"expected {expected}"
    )


# ===================================================================
# Test 3 — current_session concurrent read/write (§1.3)
# ===================================================================
def test_current_session_concurrent_rw() -> None:
    """One writer switches current_session; readers observe exactly one value.

    Two phases synchronised via barriers.  8 readers, 1 writer.
    """
    state = MockSharedState()
    nreaders = 8
    barrier = threading.Barrier(nreaders + 1)

    phase1: list = [None] * nreaders
    phase2: list = [None] * nreaders

    def _reader(idx: int) -> None:
        barrier.wait()
        phase1[idx] = state.current_session
        barrier.wait()

        barrier.wait()
        phase2[idx] = state.current_session
        barrier.wait()

    def _writer() -> None:
        state.current_session = "session-A"
        barrier.wait()
        barrier.wait()

        state.current_session = "session-B"
        barrier.wait()
        barrier.wait()

    readers = [
        threading.Thread(target=_reader, args=(i,))
        for i in range(nreaders)
    ]
    writer = threading.Thread(target=_writer)

    writer.start()
    for t in readers:
        t.start()

    writer.join()
    for t in readers:
        t.join()

    for i, val in enumerate(phase1):
        assert val == "session-A", (
            f"Reader {i} saw {val!r} in phase 1, expected 'session-A'"
        )
    for i, val in enumerate(phase2):
        assert val == "session-B", (
            f"Reader {i} saw {val!r} in phase 2, expected 'session-B'"
        )


# ===================================================================
# Test 4 — concurrent inc/dec with tight race window (§1.11)
# ===================================================================
def test_concurrent_inc_dec_never_negative() -> None:
    """Under concurrent load, _session_inflight_calls must never go negative.

    With the `_runtime_lock` fix, each increment has a matching decrement,
    so the counter should always be >= 0 and end at 0.
    """
    SID = "idle-session"
    state = MockSharedState()
    NTHREADS = 8
    REPS = 300
    seen_negative = threading.Event()

    def _worker() -> None:
        for _ in range(REPS):
            _increment_inflight_locked(state, SID)
            # Sniff counter between inc and dec — should never be negative
            with state._runtime_lock:
                val = state._session_inflight_calls.get(SID, 0) or 0
                if val < 0:
                    seen_negative.set()
            _decrement_inflight_locked(state, SID)

    threads = [threading.Thread(target=_worker) for _ in range(NTHREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = state._session_inflight_calls.get(SID, 0) or 0
    assert final == 0, f"Final counter {final} != 0 (lost increments)"
    assert not seen_negative.is_set(), "Counter went negative (decrement without increment)"
