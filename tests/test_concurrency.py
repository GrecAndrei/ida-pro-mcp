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
def _increment_inflight(state: MockSharedState, sid: str) -> None:
    state._session_inflight_calls[sid] = int(
        state._session_inflight_calls.get(sid, 0) or 0
    ) + 1


def _decrement_inflight(state: MockSharedState, sid: str) -> None:
    remaining = int(
        state._session_inflight_calls.get(sid, 0) or 0
    ) - 1
    if remaining > 0:
        state._session_inflight_calls[sid] = remaining
    else:
        state._session_inflight_calls.pop(sid, None)


# ===================================================================
# Test 1 — _session_inflight_calls lost-update race (§1.3)
# ===================================================================
def test_inflight_calls_lost_update() -> None:
    """Force the classic read-modify-write lost update.

    Two threads both read the SAME value for increment, then both write
    their computed result.  The second write overwrites the first.

    The same pattern is repeated for decrement: both read value 2,
    both compute 1, both write 1 — leaving a non-zero counter.
    """
    SID = "inflight-session-a"
    state = MockSharedState()

    # -- Phase 1: lost increment -------------------------------------------
    a_read_inc = threading.Event()
    b_read_inc = threading.Event()

    def _inc_a() -> None:
        val = state._session_inflight_calls.get(SID, 0) or 0
        a_read_inc.set()
        b_read_inc.wait()  # B has also read pre-write value
        state._session_inflight_calls[SID] = int(val) + 1

    def _inc_b() -> None:
        a_read_inc.wait()  # A has read first
        val = state._session_inflight_calls.get(SID, 0) or 0
        b_read_inc.set()
        state._session_inflight_calls[SID] = int(val) + 1

    ta = threading.Thread(target=_inc_a)
    tb = threading.Thread(target=_inc_b)
    ta.start()
    tb.start()
    ta.join()
    tb.join()

    # Both incremented from 0 -> expected 2, but the second write
    # overwrote the first, leaving 1.  This IS the race.
    result = state._session_inflight_calls.get(SID, 0)
    assert result == 2, (
        f"Lost increment: both threads read 0 and wrote 1, "
        f"final={result}, expected 2"
    )

    # -- Phase 2: lost decrement ------------------------------------------
    state._session_inflight_calls[SID] = 2
    a_read_dec = threading.Event()
    b_read_dec = threading.Event()

    def _dec_a() -> None:
        remaining = int(state._session_inflight_calls.get(SID, 0) or 0) - 1
        a_read_dec.set()
        b_read_dec.wait()  # B has also read pre-decrement value
        if remaining > 0:
            state._session_inflight_calls[SID] = remaining
        else:
            state._session_inflight_calls.pop(SID, None)

    def _dec_b() -> None:
        a_read_dec.wait()  # A has read first
        remaining = int(state._session_inflight_calls.get(SID, 0) or 0) - 1
        b_read_dec.set()
        if remaining > 0:
            state._session_inflight_calls[SID] = remaining
        else:
            state._session_inflight_calls.pop(SID, None)

    ta = threading.Thread(target=_dec_a)
    tb = threading.Thread(target=_dec_b)
    ta.start()
    tb.start()
    ta.join()
    tb.join()

    # Both decremented from 2 -> expected 0, but both read 2 and wrote 1.
    result = state._session_inflight_calls.get(SID, 0)
    assert result == 0, (
        f"Lost decrement: both threads read 2 and wrote 1, "
        f"final={result}, expected 0"
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
# Test 4 — Simulate idle-index worker race (§1.11)
# ===================================================================
def test_idle_worker_race() -> None:
    """Force the idle-worker race pattern (server_runtime.py:778).

    After two concurrent increments lose an update (both read 0, both
    write 1), the counter shows 1 instead of 2.  Then thread A reads
    the counter for decrement and pops it to 0.  A concurrent reader
    (simulating the idle-index worker) now observes inflight=0 while
    thread B has NOT yet performed its decrement.

    This is exactly the §1.11 race: the idle worker sees a session as
    idle (inflight=0) when there is still an active tool call whose
    inflight count was lost to the race.

    Interleaving:
      1. A inc: reads 0, signals A-read-inc
      2. B inc: reads 0 (pre-A-write), signals B-read-inc
      3. A inc: writes 1, signals A-wrote-inc
      4. B inc: writes 1 (overwrites — lost update, counter=1 not 2)
      5. Worker: signals B-start-dec-release → A proceeds to dec read
      6. A dec: reads 1
      7. A dec: signals A-read-dec
      8. Worker: reads counter → (1, 2) — correct so far
      9. Worker: signals A-go-dec-write → A writes its decrement
     10. A dec: pops counter to 0
     11. A dec: signals A-done-dec
     12. Worker: reads counter → (0, 1) — RACE! B still active!
     13. Worker: signals B-go-dec → B reads for decrement
     14. B dec: reads 0 (A already popped), pops (no-op)
    """
    SID = "idle-session"
    state = MockSharedState()

    # Events for exact interleaving control
    inc_a_read = threading.Event()
    inc_b_read = threading.Event()
    inc_a_wrote = threading.Event()

    b_start_dec_release = threading.Event()  # worker → A: proceed to dec read
    a_read_dec = threading.Event()            # A → worker: read dec value
    a_go_dec_write = threading.Event()        # worker → A: now write dec
    a_done_dec = threading.Event()            # A → worker: dec write complete

    b_go_dec = threading.Event()              # worker → B: now do your dec

    worker_checks: list[tuple[int, int]] = []

    def _thread_a() -> None:
        # --- inc ---
        val = state._session_inflight_calls.get(SID, 0) or 0
        inc_a_read.set()
        inc_b_read.wait()
        state._session_inflight_calls[SID] = int(val) + 1
        inc_a_wrote.set()

        # --- dec ---
        b_start_dec_release.wait()  # worker says: proceed
        remaining = int(state._session_inflight_calls.get(SID, 0) or 0) - 1
        a_read_dec.set()           # worker: I've read the dec value
        a_go_dec_write.wait()      # worker says: now write it
        if remaining > 0:
            state._session_inflight_calls[SID] = remaining
        else:
            state._session_inflight_calls.pop(SID, None)
        a_done_dec.set()           # worker: dec write is done

    def _thread_b() -> None:
        # --- inc ---
        inc_a_read.wait()
        val = state._session_inflight_calls.get(SID, 0) or 0
        inc_b_read.set()
        state._session_inflight_calls[SID] = int(val) + 1

        # --- dec (held until worker observes the race window) ---
        inc_a_wrote.wait()
        b_go_dec.wait()  # worker says: now do your dec
        remaining = int(state._session_inflight_calls.get(SID, 0) or 0) - 1
        if remaining > 0:
            state._session_inflight_calls[SID] = remaining
        else:
            state._session_inflight_calls.pop(SID, None)

    def _worker() -> None:
        # Let A proceed to dec read
        b_start_dec_release.set()

        # Wait for A to read the dec value
        a_read_dec.wait()

        # Check 1: A has read 1 for decrement, hasn't written yet
        # B hasn't decremented at all. Counter should be 1.
        inflight_1 = int(state._session_inflight_calls.get(SID, 0) or 0)
        worker_checks.append((inflight_1, 2))

        # Let A write its decrement (pop to 0)
        a_go_dec_write.set()
        a_done_dec.wait()  # A has popped counter to 0

        # Check 2: A decremented, B is still active but counter is 0.
        # This is the race — idle worker sees inflight=0 during active req.
        inflight_2 = int(state._session_inflight_calls.get(SID, 0) or 0)
        worker_checks.append((inflight_2, 1))  # B still active

        # Now let B finish
        b_go_dec.set()

    ta = threading.Thread(target=_thread_a)
    tb = threading.Thread(target=_thread_b)
    tw = threading.Thread(target=_worker)

    ta.start()
    tb.start()
    tw.start()

    ta.join()
    tb.join()
    tw.join()

    # With the buggy code (no lock), the worker OBSERVES inflight=0
    # while B is still active.  This assertion catches that race.
    for inflight, active in worker_checks:
        assert inflight > 0 or active == 0, (
            f"Race detected: idle worker observed inflight=0 while "
            f"{active} request(s) were still active (§1.11). "
            f"All checks: {worker_checks}"
        )

    assert len(worker_checks) > 0, "Worker never ran — test setup error"
