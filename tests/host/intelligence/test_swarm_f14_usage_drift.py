"""Regression tests for f14 usage-drift findings in host/intelligence/usage.py.

Covers the concurrency/snapshot race in session_report, the unbounded
addrs_seen Counter, the missing session-evict hook, the exception-swallowing
drift loop, the deterministic LOOP message, and the start()/stop() restart
hazard. Pure-Python, no live IDA needed.
"""
from __future__ import annotations

import threading
import time

from ida_pro_mcp.host.intelligence.usage import DriftDetector, UsageIntelligence


# ── finding: session_report must snapshot nested containers under the lock ──
class TestSessionReportSnapshot:
    def test_session_report_is_safe_under_concurrent_observe(self):
        d = DriftDetector()
        stop = threading.Event()

        def _observe_loop():
            i = 0
            while not stop.is_set():
                d.observe(
                    "code", "decompile", "s1",
                    latency_ms=float(i % 50), error=None,
                    addr=f"0x{i % 10000:x}",
                )
                i += 1

        t = threading.Thread(target=_observe_loop, daemon=True)
        t.start()
        try:
            for _ in range(300):
                report = d.session_report("s1")
                assert report["session_id"] == "s1"
                # Snapshot reads are atomic: invariants hold even though the
                # observer mutates the same state concurrently.
                assert 0 <= report["error_calls"] <= report["total_calls"]
                assert 0 <= report["analysis_calls"] <= report["total_calls"]
                assert isinstance(report["top_addresses"], dict)
                assert all(v >= 1 for v in report["top_addresses"].values())
                assert report["avg_latency_ms"] >= 0.0
        finally:
            stop.set()
            t.join(timeout=2)
        assert not t.is_alive()


# ── finding: per-session addrs_seen Counter is unbounded ──
class TestAddrsSeenBounded:
    def test_addrs_seen_counter_is_bounded(self):
        d = DriftDetector()
        for i in range(500):
            d.observe("code", "decompile", "s1", latency_ms=1.0, error=None,
                      addr=f"0x{i:04x}")
        stats = d._session_stats["s1"]
        assert len(stats["addrs_seen"]) <= DriftDetector._MAX_ADDRS

        # A repeatedly-analyzed address that first appears after the cap is
        # saturated must still accumulate: REPEATED_ADDR must keep working
        # past the cap rather than evicting the new hot address each time.
        for _ in range(300):
            d.observe("code", "decompile", "s1", latency_ms=1.0, error=None,
                      addr="0x7777")
        assert d._session_stats["s1"]["addrs_seen"]["0x7777"] == 300
        assert len(d._session_stats["s1"]["addrs_seen"]) <= DriftDetector._MAX_ADDRS
        assert any(
            s["type"] == "REPEATED_ADDR" and s["addr"] == "0x7777"
            for s in d.check("s1")
        )


# ── finding: _active_sessions / drift state never evicted on close ──
class TestEvictSession:
    def test_drift_detector_evict_session(self):
        d = DriftDetector()
        for _ in range(6):
            d.observe("code", "decompile", "s1", latency_ms=1.0, error=None,
                      addr="0x1000")
        d.observe("code", "decompile", "s2", latency_ms=1.0, error=None)
        assert d.session_report("s1")["total_calls"] == 6
        d.evict_session("s1")
        assert d.session_report("s1") == {"session_id": "s1", "total_calls": 0}
        assert d.check("s1") == []
        # s2 is unaffected.
        assert d.session_report("s2")["total_calls"] == 1

    def test_evict_session_clears_usage_intelligence_state(self):
        ui = UsageIntelligence("/tmp/audit", notify_fn=lambda n: None)
        for _ in range(10):
            ui.observe("code", "decompile", "s1", latency_ms=1.0, error=None)
        ui._check_all_sessions()
        assert ("s1", "ANALYZE_WITHOUT_RECORD") in ui._notified_signals
        assert ui.global_report() == {"active_sessions": 1}
        assert "s1" in ui._last_seen

        ui.evict_session("s1")
        assert ui.global_report() == {"active_sessions": 0}
        assert "s1" not in ui._last_seen
        assert not any(k[0] == "s1" for k in ui._notified_signals)
        assert ui.drift.session_report("s1") == {"session_id": "s1", "total_calls": 0}

        # A later drift sweep must not resurrect the evicted session.
        ui._check_all_sessions()
        assert ui.global_report() == {"active_sessions": 0}
        assert not any(k[0] == "s1" for k in ui._notified_signals)


# ── finding: _loop() swallows sweep exceptions with no logging ──
class _RaisingSweepUsage(UsageIntelligence):
    def _check_all_sessions(self):
        raise RuntimeError("boom")


class TestLoopExceptionHandling:
    def test_loop_survives_drift_sweep_exception(self, caplog):
        ui = _RaisingSweepUsage("/tmp/audit", drift_check_interval=0.01)
        ui.start()
        try:
            time.sleep(0.3)  # let the loop fire its (raising) sweep
            assert ui.is_running()
            assert not ui._stop.is_set()
        finally:
            ui.stop()
            ui._thread.join(timeout=5)
        assert not ui._thread.is_alive()
        assert any("drift sweep failed" in r.getMessage() for r in caplog.records)


# ── finding: start()/stop() restart hazard ──
class _SlowSweepUsage(UsageIntelligence):
    """Holds the loop thread inside a drift sweep so stop();start() lands in
    the 'old loop still dying' window deterministically."""

    def _check_all_sessions(self):
        time.sleep(0.5)
        super()._check_all_sessions()


class TestRestart:
    def test_start_after_stop_restarts_a_dying_observer(self):
        ui = _SlowSweepUsage("/tmp/audit", drift_check_interval=0.01)
        ui.start()
        time.sleep(0.2)  # loop is inside the sleeping sweep
        assert ui.is_running()
        ui.stop()  # latch set while the loop is still inside the sweep
        ui.start()  # must join the dying loop and spawn a fresh one
        try:
            assert ui.is_running()
            assert not ui._stop.is_set()
            # the restarted observer still accepts observations
            ui.observe("code", "decompile", "s1", latency_ms=1.0, error=None)
        finally:
            ui.stop()
            if ui._thread:
                ui._thread.join(timeout=5)


# ── finding: LOOP notification message embeds a non-deterministic set repr ──
class TestLoopMessageDeterminism:
    def test_loop_message_and_states_are_deterministic(self):
        d = DriftDetector()
        states = [("misc", "health"), ("misc", "cache_stats")] * 5
        for tool, action in states:
            d.observe(tool, action, "s1", latency_ms=1.0, error=None)
        sig = next(s for s in d.check("s1") if s["type"] == "LOOP")
        assert sig["states"] == sorted(sig["states"])
        assert sig["states"] == ["misc.cache_stats", "misc.health"]
        # The message must not embed an unordered set repr.
        assert "{" not in sig["message"]
