"""
UsageIntelligence — passive long-running observer and learner.

Mines the audit JSONL log to build three models:

1. SequenceModel   — Markov chain over (tool, action) pairs.
                     Predicts what the LLM will call next.
                     Used to pre-warm suggestions and detect stuck loops.

2. EffectivenessModel — Scores tool combinations by outcome.
                        "decompile → classify → blackboard.write" = 0.73 effectiveness.
                        "search.strings → nothing" = 0.11 effectiveness.
                        Used to rank suggestions and detect wasted effort.

3. DriftDetector   — Watches live call stream for stuck patterns.
                     "47 decompile calls, 3 blackboard writes → nudge."
                     "Same address called 5 times → stuck."
                     Emits notifications via notify_fn.

All three update incrementally as new audit records arrive.
The learner runs in a background thread, tailing the audit log.

Usage:
    ui = UsageIntelligence(audit_dir, notify_fn)
    ui.start()
    # On each tool call:
    ui.observe(tool, action, session_id, latency_ms, error)
    # Get suggestions:
    ui.predict_next(tool, action)          → [(tool, action, prob), ...]
    ui.effectiveness(tool, action)         → float 0-1
    ui.session_drift_report(session_id)    → dict
"""
from __future__ import annotations

import collections
import glob
import json
import math
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Sequence Model ────────────────────────────────────────────────────────────

class SequenceModel:
    """
    Bigram Markov chain over (tool, action) pairs.

    Counts transitions: given state A, how often does state B follow?
    Smoothed with add-1 (Laplace) so unseen transitions have small probability.
    """

    def __init__(self):
        # counts[(from_state, to_state)] = int
        self._counts: Dict[Tuple, Dict[Tuple, int]] = collections.defaultdict(
            lambda: collections.defaultdict(int)
        )
        self._total: Dict[Tuple, int] = collections.defaultdict(int)
        self._lock = threading.Lock()

    def observe(self, prev: Tuple[str, str], curr: Tuple[str, str]):
        with self._lock:
            self._counts[prev][curr] += 1
            self._total[prev] += 1

    def predict(self, state: Tuple[str, str], top_k: int = 5) -> List[Tuple[Tuple, float]]:
        """Return top-k (next_state, probability) pairs."""
        with self._lock:
            counts = dict(self._counts.get(state, {}))
            total = self._total.get(state, 0)
        if not counts:
            return []
        # Laplace smoothing: add 1 to each seen transition
        smoothed = {k: v + 1 for k, v in counts.items()}
        total_smooth = sum(smoothed.values())
        ranked = sorted(smoothed.items(), key=lambda x: -x[1])[:top_k]
        return [(state, c / total_smooth) for state, c in ranked]

    def is_loop(self, recent: List[Tuple[str, str]], window: int = 5) -> bool:
        """Return True if the last `window` calls repeat the same state."""
        if len(recent) < window:
            return False
        tail = recent[-window:]
        return len(set(tail)) <= 2  # only 1-2 distinct states in last N calls

    def to_dict(self) -> Dict:
        with self._lock:
            return {
                "transitions": len(self._counts),
                "total_observations": sum(self._total.values()),
                "top_sequences": self._top_sequences(10),
            }

    def _top_sequences(self, n: int) -> List[Dict]:
        results = []
        for from_state, to_counts in self._counts.items():
            total = self._total[from_state]
            for to_state, count in to_counts.items():
                results.append({
                    "from": f"{from_state[0]}.{from_state[1]}",
                    "to": f"{to_state[0]}.{to_state[1]}",
                    "count": count,
                    "prob": round(count / total, 3) if total else 0,
                })
        results.sort(key=lambda x: -x["count"])
        return results[:n]


# ── Effectiveness Model ───────────────────────────────────────────────────────

class EffectivenessModel:
    """
    Scores tool calls by their outcome effectiveness.

    Effectiveness = probability that a call leads to a "productive" outcome
    within a 60-second window. Productive = followed by blackboard.write,
    modify.rename, or a low-latency result (< 2s, no error).

    Stored as exponential moving average per (tool, action) pair.
    """

    PRODUCTIVE_OUTCOMES = {
        ("blackboard", "write"),
        ("blackboard", "add_evidence"),
        ("modify", "rename"),
        ("modify", "comment"),
        ("funcs", "suggest_names"),
        ("annotation", "set"),
    }

    def __init__(self, alpha: float = 0.1):
        self._alpha = alpha  # EMA decay
        self._scores: Dict[Tuple[str, str], float] = {}
        self._call_counts: Dict[Tuple[str, str], int] = collections.defaultdict(int)
        self._lock = threading.Lock()

    def observe_outcome(self, state: Tuple[str, str], productive: bool):
        """Update EMA score for state based on whether outcome was productive."""
        with self._lock:
            current = self._scores.get(state, 0.5)
            reward = 1.0 if productive else 0.0
            self._scores[state] = current * (1 - self._alpha) + reward * self._alpha
            self._call_counts[state] += 1

    def score(self, tool: str, action: str) -> float:
        """Return effectiveness score 0-1 for (tool, action)."""
        with self._lock:
            return self._scores.get((tool, action), 0.5)

    def rank_suggestions(self, candidates: List[Tuple[str, str]]) -> List[Tuple[Tuple, float]]:
        """Rank candidate (tool, action) pairs by effectiveness score."""
        scored = [(c, self.score(c[0], c[1])) for c in candidates]
        return sorted(scored, key=lambda x: -x[1])

    def _adaptive_low_eff_threshold_locked(self) -> float:
        """Compute adaptive low-effectiveness threshold from current score distribution."""
        if not self._scores:
            return 0.3
        vals = sorted(float(v) for v in self._scores.values())
        # Lower quartile as adaptive "low effectiveness" boundary.
        q1_idx = max(0, min(len(vals) - 1, int(round(0.25 * (len(vals) - 1)))))
        q1 = vals[q1_idx]
        return max(0.05, min(0.6, q1))

    def _adaptive_min_samples_locked(self) -> int:
        """Adaptive minimum sample requirement based on observed call volume."""
        total = sum(int(c) for c in self._call_counts.values())
        if total <= 0:
            return 5
        # Scale with data volume but keep bounded.
        return max(3, min(12, int(round(math.sqrt(float(total)) / 2.0))))

    def low_effectiveness_tools(self, threshold: Optional[float] = None) -> List[Dict]:
        """Return tools with consistently low effectiveness."""
        with self._lock:
            thr = self._adaptive_low_eff_threshold_locked() if threshold is None else float(threshold)
            return self._low_eff_locked(thr)

    def _low_eff_locked(self, threshold: float) -> List[Dict]:
        """Must be called with self._lock held."""
        results = []
        min_samples = self._adaptive_min_samples_locked()
        for (tool, action), score in self._scores.items():
            count = self._call_counts[(tool, action)]
            if count >= min_samples and score < threshold:
                results.append({
                    "tool": tool, "action": action,
                    "score": round(score, 3), "calls": count,
                })
        return sorted(results, key=lambda x: x["score"])

    def to_dict(self) -> Dict:
        with self._lock:
            top = sorted(self._scores.items(), key=lambda x: -x[1])
            return {
                "scored_pairs": len(self._scores),
                "top_effective": [
                    {"tool": k[0], "action": k[1], "score": round(v, 3),
                     "calls": self._call_counts[k]}
                    for k, v in top[:10]
                ],
                "low_effective": self._low_eff_locked(self._adaptive_low_eff_threshold_locked()),
            }


# ── Drift Detector ────────────────────────────────────────────────────────────

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
        self._session_stats: Dict[str, Dict] = collections.defaultdict(lambda: {
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

    def _low_record_threshold(self) -> Tuple[int, float]:
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
                latency_ms: float, error: Optional[str],
                addr: Optional[str] = None):
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

    def check(self, session_id: str) -> List[Dict]:
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
                    "error_rate": round(errors / total, 3),
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

    def session_report(self, session_id: str) -> Dict:
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


# ── Audit Log Miner ───────────────────────────────────────────────────────────

class AuditMiner:
    """
    Reads audit JSONL files and feeds records into the models.
    Runs incrementally — tracks file position to avoid re-reading.
    """

    def __init__(self, audit_dir: str, seq: SequenceModel,
                 eff: EffectivenessModel, drift: DriftDetector):
        self._dir = audit_dir
        self._seq = seq
        self._eff = eff
        self._drift = drift
        self._positions: Dict[str, int] = {}  # file_path → byte offset
        self._prev_by_session: Dict[str, Tuple[str, str]] = {}

    def mine_incremental(self) -> int:
        """Read new records from all audit files. Returns count processed."""
        processed = 0
        for path in sorted(glob.glob(os.path.join(self._dir, "**/*.jsonl"),
                                     recursive=True)):
            processed += self._mine_file(path)
        return processed

    def mine_all(self) -> int:
        """Re-read all audit files from scratch (for initial load)."""
        self._positions.clear()
        self._prev_by_session.clear()
        return self.mine_incremental()

    def _mine_file(self, path: str) -> int:
        offset = self._positions.get(path, 0)
        count = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                f.seek(offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        self._process_record(rec)
                        count += 1
                    except Exception:
                        pass
                self._positions[path] = f.tell()
        except Exception:
            pass
        return count

    def _process_record(self, rec: Dict):
        tool = rec.get("tool", "")
        action = rec.get("action", "")
        session_id = rec.get("session_id") or "unknown"
        latency = rec.get("latency_ms", 0.0)
        error = rec.get("error")
        if not tool:
            return

        curr = (tool, action)

        # Sequence model
        prev = self._prev_by_session.get(session_id)
        if prev:
            self._seq.observe(prev, curr)
        self._prev_by_session[session_id] = curr

        # Effectiveness: was the previous call productive?
        # A call is productive if it's followed by a record action within the session
        if prev and curr in EffectivenessModel.PRODUCTIVE_OUTCOMES:
            self._eff.observe_outcome(prev, productive=True)
        elif prev and error:
            self._eff.observe_outcome(prev, productive=False)

        # Drift detector
        # Extract addr from args_preview if available
        addr = None
        preview = rec.get("args_preview", "")
        if preview and "addr" in preview:
            try:
                args = json.loads(preview)
                addr = args.get("addr") or args.get("address")
            except Exception:
                pass

        self._drift.observe(tool, action, session_id, latency, error, addr)


# ── UsageIntelligence ─────────────────────────────────────────────────────────

class UsageIntelligence:
    """
    Long-running observer and learner.

    Starts a background thread that:
    1. Does an initial mine of all audit logs on startup
    2. Polls for new audit records every 30 seconds
    3. Checks for drift signals every 60 seconds and pushes notifications

    Also accepts live observations via observe() for real-time drift detection
    without waiting for the audit log to be written.
    """

    def __init__(self, audit_dir: str,
                 notify_fn: Optional[Callable[[Dict], None]] = None,
                 drift_check_interval: float = 60.0):
        self._audit_dir = audit_dir
        self._notify = notify_fn or (lambda n: None)
        self._drift_interval = drift_check_interval

        self.seq = SequenceModel()
        self.eff = EffectivenessModel()
        self.drift = DriftDetector()
        self._miner = AuditMiner(audit_dir, self.seq, self.eff, self.drift)

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._active_sessions: set = set()
        self._last_drift_check = 0.0
        self._total_mined = 0

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
                latency_ms: float = 0.0, error: Optional[str] = None,
                addr: Optional[str] = None):
        """Live observation — called on every tool call from server.py."""
        self._active_sessions.add(session_id)
        self.drift.observe(tool, action, session_id, latency_ms, error, addr)
        # Update sequence model live too
        # (miner will also update from audit log, but live is faster)

    def predict_next(self, tool: str, action: str,
                     top_k: int = 5) -> List[Dict]:
        """Predict what the LLM will call next after (tool, action)."""
        predictions = self.seq.predict((tool, action), top_k=top_k)
        result = []
        for (next_tool, next_action), prob in predictions:
            eff = self.eff.score(next_tool, next_action)
            result.append({
                "tool": next_tool,
                "action": next_action,
                "probability": round(prob, 3),
                "effectiveness": round(eff, 3),
                "score": round(prob * 0.6 + eff * 0.4, 3),  # blend
            })
        result.sort(key=lambda x: -x["score"])
        return result

    def session_report(self, session_id: str) -> Dict:
        return self.drift.session_report(session_id)

    def global_report(self) -> Dict:
        return {
            "total_mined": self._total_mined,
            "sequence_model": self.seq.to_dict(),
            "effectiveness_model": self.eff.to_dict(),
            "active_sessions": len(self._active_sessions),
        }

    # ── background loop ───────────────────────────────────────────────────────

    def _loop(self):
        # Initial full mine
        try:
            self._total_mined += self._miner.mine_all()
        except Exception:
            pass

        while not self._stop.is_set():
            try:
                # Incremental mine
                new = self._miner.mine_incremental()
                self._total_mined += new

                # Drift check
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
