"""
UsageIntelligence — passive live-call drift observer.

Watches the live tool-call stream for stuck / wasted-effort patterns and
emits notifications via notify_fn:

  - LOOP: same (tool, action) repeated without productive outcome
  - ANALYZE_WITHOUT_RECORD: many analysis calls, no blackboard writes
  - SAME_ADDR: same address analyzed multiple times
  - HIGH_ERROR_RATE: >30% of recent calls returning errors

Drift detection is a live, per-session signal fed by observe() on every tool
call. The speculative SequenceModel / EffectivenessModel / AuditMiner that
previously tried to predict the LLM's next action and score tool-combo
"effectiveness" have been removed: an LLM chooses its next action from the
task, not from a Markov chain of its own history, and that steering was
unvalidated.

Usage:
    ui = UsageIntelligence(audit_dir, notify_fn)
    ui.start()
    ui.observe(tool, action, session_id, latency_ms, error, addr)
    ui.session_drift_report(session_id)    -> dict
"""
from __future__ import annotations

import collections
import threading
import time
from collections.abc import Callable

# ── Drift Detector ─────────────────────────────────────────────────────────────

class DriftDetector:
    """
    Watches the live call stream for stuck patterns and wasted effort.

    Patterns detected:
    - LOOP: same (tool, action) repeated N times without productive outcome
    - ANALYZE_WITHOUT_RECORD: many decompile/disasm calls, few blackboard writes
    - SAME_ADDR: same address analyzed multiple times
    - HIGH_ERROR_RATE: >30% of recent calls returning errors
    - LATENCY_SPIKE: sudden increase in average latency
    """

    ANALYSIS_TOOLS = {"code", "search", "graph", "cfg_analysis",
                      "classify", "summarize", "deobfuscate"}
    RECORD_TOOLS = {"blackboard", "modify", "annotation", "bookmarks"}

    def __init__(self, window: int = 20):
        self._window = window
        self._recent: collections.deque = collections.deque(maxlen=window)
        self._session_stats: dict[str, dict] = collections.defaultdict(lambda: {
            "analysis_calls": 0,
            "record_calls": 0,
            "error_calls": 0,
            "total_calls": 0,
            "addrs_seen": collections.Counter(),
            "latencies": collections.deque(maxlen=50),
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
            self._recent.append(state)
            s = self._session_stats[session_id]
            s["total_calls"] += 1
            if tool in self.ANALYSIS_TOOLS:
                s["analysis_calls"] += 1
            if tool in self.RECORD_TOOLS:
                s["record_calls"] += 1
            if error:
                s["error_calls"] += 1
            if addr:
                s["addrs_seen"][addr] += 1
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

            # LOOP detection from recent window
            recent = list(self._recent)
            loop_tail_len = self._loop_tail_len()
            if len(recent) >= loop_tail_len:
                tail = recent[-loop_tail_len:]
                if len(set(tail)) <= 2:
                    signals.append({
                        "type": "LOOP",
                        "message": f"Repeating {set(tail)} in last {loop_tail_len} calls. "
                                   "Try a different approach or read ida://state.",
                        "severity": "warning",
                        "states": [f"{t}.{a}" for t, a in set(tail)],
                    })

        return signals

    def session_report(self, session_id: str) -> dict:
        with self._lock:
            s = dict(self._session_stats.get(session_id, {}))
        if not s:
            return {"session_id": session_id, "total_calls": 0}
        latencies = list(s.get("latencies", []))
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        top_addrs = dict(s.get("addrs_seen", {}).most_common(5))
        return {
            "session_id": session_id,
            "total_calls": s["total_calls"],
            "analysis_calls": s["analysis_calls"],
            "record_calls": s["record_calls"],
            "error_calls": s["error_calls"],
            "record_rate": round(s["record_calls"] / max(s["analysis_calls"], 1), 3),
            "error_rate": round(s["error_calls"] / max(s["total_calls"], 1), 3),
            "avg_latency_ms": round(avg_lat, 1),
            "top_addresses": top_addrs,
            "drift_signals": self.check(session_id),
        }


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

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="usage-intelligence"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def observe(self, tool: str, action: str, session_id: str,
                latency_ms: float = 0.0, error: str | None = None,
                addr: str | None = None):
        """Live observation — called on every tool call from server.py."""
        self._active_sessions.add(session_id)
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

    # ── background loop ───────────────────────────────────────────────────────

    def _loop(self):
        while not self._stop.is_set():
            try:
                now = time.time()
                if now - self._last_drift_check >= self._drift_interval:
                    self._check_all_sessions()
                    self._last_drift_check = now
            except Exception:
                pass
            self._stop.wait(timeout=30)

    def _check_all_sessions(self):
        for sid in list(self._active_sessions):
            signals = self.drift.check(sid)
            for sig in signals:
                if sig.get("severity") in ("warning",):
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
