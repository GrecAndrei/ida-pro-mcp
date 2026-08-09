"""
UsageIntelligence — passive live-call drift observer.

Watches the live tool-call stream for stuck / wasted-effort patterns and
emits notifications via notify_fn:

  - LOOP: same (tool, action) repeated without productive outcome
  - ANALYZE_WITHOUT_RECORD: many analysis calls, no blackboard writes
  - SAME_ADDR: same address analyzed multiple times
  - HIGH_ERROR_RATE: elevated share of recent calls returning errors
    (adaptive 20-40% threshold, stricter on small samples)

Drift detection is a live, per-session signal fed by observe() on every tool
call. The speculative SequenceModel / EffectivenessModel / AuditMiner that
previously tried to predict the LLM's next action and score tool-combo
"effectiveness" have been removed: an LLM chooses its next action from the
task, not from a Markov chain of its own history, and that steering was
unvalidated.

Usage:
    ui = UsageIntelligence(audit_dir, notify_fn)
    ui.start()
    ui.observe(tool, action, session_id, latency_ms=..., error=..., addr=...)
    ui.session_report(session_id)    -> dict
    ui.is_running()                  -> bool
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)

# ── Drift Detector ─────────────────────────────────────────────────────────────

class DriftDetector:
    """
    Watches the live call stream for stuck patterns and wasted effort.

    Patterns detected:
    - LOOP: same (tool, action) repeated N times without productive outcome
    - ANALYZE_WITHOUT_RECORD: many decompile/disasm calls, few blackboard writes
    - SAME_ADDR: same address analyzed multiple times
    - HIGH_ERROR_RATE: elevated share of recent calls returning errors
      (adaptive 20-40% threshold, stricter on small samples)
    (latencies are collected for the per-session report average; a dedicated
    LATENCY_SPIKE detector is intentionally not emitted.)
    """

    ANALYSIS_TOOLS = {"code", "search", "graph", "deobfuscate"}
    RECORD_TOOLS = {"blackboard", "modify", "annotation", "bookmarks"}
    # Upper bound on per-session distinct addresses retained for REPEATED_ADDR
    # drift detection. A long-lived session could otherwise retain an unbounded
    # Counter of every address it ever touched; the least-common entries are
    # trimmed once the cap is exceeded.
    _MAX_ADDRS = 200

    def __init__(self, window: int = 20):
        self._window = window
        # Per-session recent-call tails.  The recent window is tracked per
        # session (not host-global) so LOOP detection in a multi-session host
        # is not diluted or corrupted by other agents' interleaved calls.
        self._session_stats: dict[str, dict] = collections.defaultdict(lambda: {
            "analysis_calls": 0,
            "record_calls": 0,
            "error_calls": 0,
            "total_calls": 0,
            "addrs_seen": collections.Counter(),
            "latencies": collections.deque(maxlen=50),
            "recent": collections.deque(maxlen=window),
            "last_seen": 0.0,
        })
        self._lock = threading.Lock()

    def _analyze_without_record_threshold(self) -> int:
        return max(6, int(round(self._window * 0.5)))

    def _low_record_threshold(self) -> tuple[int, float]:
        return (max(12, int(round(self._window))), 0.1)

    def _repeated_addr_threshold(self) -> int:
        return max(3, int(round(self._window * 0.2)))

    def _error_rate_threshold(self, total: int) -> float:
        # Adaptive minimum error rate threshold based on sample size.
        if total <= 10:
            return 0.3
        return max(0.2, min(0.4, 3.0 / max(1.0, float(total)) + 0.15))

    def _loop_tail_len(self) -> int:
        return max(4, int(round(self._window * 0.3)))

    def observe(self, tool: str, action: str, session_id: str,
                latency_ms: float, error: str | None,
                addr: str | None = None):
        with self._lock:
            state = (tool, action)
            s = self._session_stats[session_id]
            s["recent"].append(state)
            s["last_seen"] = time.time()
            s["total_calls"] += 1
            if tool in self.ANALYSIS_TOOLS:
                s["analysis_calls"] += 1
            if tool in self.RECORD_TOOLS:
                s["record_calls"] += 1
            if error:
                s["error_calls"] += 1
            if addr:
                s["addrs_seen"][addr] += 1
                if len(s["addrs_seen"]) > self._MAX_ADDRS:
                    # Keep the Counter bounded by evicting the least-common
                    # addresses, oldest-first on count ties. Evicting the
                    # *newest* low-count address instead would drop a
                    # freshly-repeated address before its count can grow,
                    # silently breaking REPEATED_ADDR detection past the cap.
                    min_count = min(s["addrs_seen"].values())
                    excess = len(s["addrs_seen"]) - self._MAX_ADDRS
                    for stale_addr, count in list(s["addrs_seen"].items()):
                        if excess <= 0:
                            break
                        if count == min_count:
                            del s["addrs_seen"][stale_addr]
                            excess -= 1
            s["latencies"].append(latency_ms)

    def check(self, session_id: str) -> list[dict]:
        """Return list of drift signals for this session."""
        signals = []
        with self._lock:
            s = self._session_stats.get(session_id)
            if not s:
                return []

            total = s["total_calls"]
            if total < 5:
                return []

            # ANALYZE_WITHOUT_RECORD
            analysis = s["analysis_calls"]
            records = s["record_calls"]
            analyze_without_record_n = self._analyze_without_record_threshold()
            low_record_n, low_record_rate = self._low_record_threshold()
            if analysis >= analyze_without_record_n and records == 0:
                signals.append({
                    "type": "ANALYZE_WITHOUT_RECORD",
                    "message": f"{analysis} analysis calls, 0 blackboard writes. "
                               "Consider recording findings with blackboard(action='write').",
                    "severity": "warning",
                    "analysis_calls": analysis,
                    "record_calls": records,
                })
            elif analysis >= low_record_n and records / max(analysis, 1) < low_record_rate:
                signals.append({
                    "type": "LOW_RECORD_RATE",
                    "message": f"{analysis} analysis calls but only {records} recorded. "
                               f"Record rate: {records/analysis:.0%}. "
                               "Most findings are being lost.",
                    "severity": "info",
                    "record_rate": round(records / analysis, 3),
                })

            # SAME_ADDR repeated
            repeated_addr_n = self._repeated_addr_threshold()
            for addr, count in s["addrs_seen"].most_common(3):
                if count >= repeated_addr_n:
                    signals.append({
                        "type": "REPEATED_ADDR",
                        "message": f"Address {addr} analyzed {count} times. "
                                   "Consider marking it resolved or contradicted.",
                        "severity": "info",
                        "addr": addr,
                        "count": count,
                    })

            # HIGH_ERROR_RATE
            errors = s["error_calls"]
            err_thr = self._error_rate_threshold(total)
            if total >= max(8, self._analyze_without_record_threshold()) and errors / total > err_thr:
                signals.append({
                    "type": "HIGH_ERROR_RATE",
                    "message": f"{errors}/{total} calls ({errors/total:.0%}) returning errors. "
                               "Check session state and tool arguments.",
                    "severity": "warning",
                    "error_rate": round(errors / total, 1),
                })

            # LOOP detection from this session's recent window
            recent = list(s["recent"])
            loop_tail_len = self._loop_tail_len()
            if len(recent) >= loop_tail_len:
                tail = recent[-loop_tail_len:]
                if len(set(tail)) <= 2:
                    # Sorted so the message text is deterministic across checks
                    # (a set repr of (tool, action) tuples would otherwise
                    # render in an arbitrary, run-to-run-varying order).
                    repeating = sorted({f"{t}.{a}" for t, a in set(tail)})
                    signals.append({
                        "type": "LOOP",
                        "message": f"Repeating {repeating} in last {loop_tail_len} calls. "
                                   "Try a different approach or read ida_session_state.",
                        "severity": "warning",
                        "states": repeating,
                    })

        return signals

    def session_report(self, session_id: str) -> dict:
        with self._lock:
            s = self._session_stats.get(session_id)
            if not s:
                return {"session_id": session_id, "total_calls": 0}
            # Snapshot all mutable state under the lock: the shallow copy alone
            # would leave the latencies deque and addrs_seen Counter as live
            # references that a concurrent observe() can mutate during the
            # iteration below (RuntimeError: changed size during iteration).
            snapshot = {
                "total_calls": s["total_calls"],
                "analysis_calls": s["analysis_calls"],
                "record_calls": s["record_calls"],
                "error_calls": s["error_calls"],
                "latencies": list(s["latencies"]),
                "top_addrs": dict(s["addrs_seen"].most_common(5)),
            }
        latencies = snapshot["latencies"]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        return {
            "session_id": session_id,
            "total_calls": snapshot["total_calls"],
            "analysis_calls": snapshot["analysis_calls"],
            "record_calls": snapshot["record_calls"],
            "error_calls": snapshot["error_calls"],
            "record_rate": round(snapshot["record_calls"] / max(snapshot["analysis_calls"], 1), 3),
            "error_rate": round(snapshot["error_calls"] / max(snapshot["total_calls"], 1), 3),
            "avg_latency_ms": round(avg_lat, 1),
            "top_addresses": snapshot["top_addrs"],
            "drift_signals": self.check(session_id),
        }

    def prune(self, before: float) -> None:
        """Drop per-session state for sessions idle since ``before``.

        A long-lived host otherwise accumulates one stats entry per session
        forever and keeps re-checking long-dead sessions every drift pass.
        """
        with self._lock:
            stale = [
                sid for sid, s in self._session_stats.items()
                if float(s.get("last_seen") or 0.0) < before
            ]
            for sid in stale:
                self._session_stats.pop(sid, None)

    def evict_session(self, session_id: str) -> None:
        """Drop per-session state immediately when a session is closed.

        The idle sweep (prune) only reclaims sessions after a long idle gap;
        an explicitly closed or switched-away session should not keep its
        drift state (or keep emitting drift notifications) in the meantime.
        """
        with self._lock:
            self._session_stats.pop(session_id, None)


# ── UsageIntelligence ─────────────────────────────────────────────────────────

class UsageIntelligence:
    """
    Live drift observer. Runs a background thread that periodically checks
    each active session for drift signals and pushes warning notifications.
    Drift state is fed live by observe() on every tool call.
    """

    def __init__(self, audit_dir: str,
                 notify_fn: Callable[[dict], None] | None = None,
                 drift_check_interval: float = 60.0):
        # audit_dir is retained for API compatibility but unused: drift is a
        # live signal and no longer mined from historical logs.
        self._audit_dir = audit_dir
        self._notify = notify_fn or (lambda n: None)
        self._drift_interval = drift_check_interval

        self.drift = DriftDetector()

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active_sessions: set = set()
        self._last_drift_check = 0.0
        # (session_id, signal_type) -> notified, so a stuck session does not
        # re-emit the identical warning notification every drift interval.
        self._notified_signals: set[tuple[str, str]] = set()
        # Last-observed wall-clock per session, used to prune dead sessions.
        self._last_seen: dict[str, float] = {}
        self._sessions_lock = threading.Lock()

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            if not self._stop.is_set():
                return  # already running
            # stop() was called but the old loop has not finished exiting
            # yet. A bare is_alive() early-return would leave the observer
            # permanently dead (the _stop latch stays set), so wait out the
            # dying loop before spawning a fresh one.
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                # Loop is genuinely stuck; do not run a second concurrent
                # loop — leave the latch set and let a later start() retry.
                return
            self._thread = None
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="usage-intelligence"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def is_running(self) -> bool:
        """True while the background drift loop thread is alive.

        server_dispatch gates the STUCK_LOOP blocker on this so a stopped /
        never-started observer never raises AttributeError mid-dispatch.
        """
        return bool(self._thread is not None and self._thread.is_alive())

    def observe(self, tool: str, action: str, session_id: str,
                latency_ms: float = 0.0, error: str | None = None,
                addr: str | None = None):
        """Live observation — called on every tool call from server.py."""
        with self._sessions_lock:
            self._active_sessions.add(session_id)
            self._last_seen[session_id] = time.time()
        self.drift.observe(tool, action, session_id, latency_ms, error, addr)

    def predict_next(self, tool: str, action: str, top_k: int = 5) -> list[dict]:
        """No next-action prediction (the Markov/effectiveness models were
        removed as unvalidated LLM-steering). Retained as a no-op so callers
        that merge usage-intelligence predictions keep working."""
        return []

    def session_report(self, session_id: str) -> dict:
        return self.drift.session_report(session_id)

    def global_report(self) -> dict:
        return {
            "active_sessions": len(self._active_sessions),
        }

    def evict_session(self, session_id: str) -> None:
        """Drop a session's drift state when it is closed or abandoned.

        Called on session close/switch. Without this, a closed session stays
        'active' (and is re-checked for drift, able to emit notifications)
        until the idle sweep reclaims it. Note: server-side session close /
        switch paths must call this — it is a seam for the host integration.
        """
        self.drift.evict_session(session_id)
        with self._sessions_lock:
            self._active_sessions.discard(session_id)
            self._last_seen.pop(session_id, None)
            self._notified_signals = {
                k for k in self._notified_signals if k[0] != session_id
            }

    # ── background loop ───────────────────────────────────────────────────────

    def _loop(self):
        while not self._stop.is_set():
            try:
                now = time.time()
                if now - self._last_drift_check >= self._drift_interval:
                    self._check_all_sessions()
                    self._last_drift_check = now
            except Exception:
                # A failed drift sweep must not kill the observer loop, but it
                # also must not vanish silently: a persistent failure would
                # otherwise retry every 30s forever with zero observability.
                logger.exception("usage intelligence drift sweep failed")
            self._stop.wait(timeout=30)

    def _check_all_sessions(self):
        now = time.time()
        # Drop sessions idle long enough that their drift state is noise —
        # a long-lived host must not keep notifying about (and tracking)
        # long-dead sessions forever.
        stale_before = now - max(600.0, self._drift_interval * 10)
        self.drift.prune(stale_before)
        with self._sessions_lock:
            self._active_sessions = {
                sid for sid in self._active_sessions
                if self._last_seen.get(sid, 0.0) >= stale_before
            }
            active = list(self._active_sessions)
        for sid in active:
            signals = self.drift.check(sid)
            # Track which (session, signal) pairs are currently live so a
            # sustained warning is sent once, and re-sent only after it
            # actually clears and re-triggers.
            current: set[tuple[str, str]] = set()
            for sig in signals:
                if sig.get("severity") in ("warning",):
                    key = (sid, str(sig["type"]))
                    current.add(key)
                    if key not in self._notified_signals:
                        self._notified_signals.add(key)
                        self._notify({
                            "jsonrpc": "2.0",
                            "method": "notifications/message",
                            "params": {
                                "level": "warning",
                                "data": {
                                    "type": "usage_drift",
                                    "session_id": sid,
                                    "signal": sig["type"],
                                    "message": sig["message"],
                                },
                            },
                        })
            with self._sessions_lock:
                if current:
                    self._notified_signals = {
                        k for k in self._notified_signals if k[0] != sid or k in current
                    }
