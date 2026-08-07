"""Behavioral tests for the live-call drift observer.

DriftDetector turns an observed tool-call stream into typed signals
(LOOP, ANALYZE_WITHOUT_RECORD, LOW_RECORD_RATE, REPEATED_ADDR,
HIGH_ERROR_RATE); UsageIntelligence wraps it with a background notifier.
Both are host-side pure-Python, so these tests need no IDA.
"""
from __future__ import annotations

from ida_pro_mcp.host.intelligence.usage import DriftDetector, UsageIntelligence


def _types(signals):
    return {s["type"] for s in signals}


class TestDriftDetector:
    def test_no_signals_below_minimum_calls(self):
        d = DriftDetector()
        for _i in range(4):
            d.observe("misc", "health", "s1", latency_ms=1.0, error=None)
        assert d.check("s1") == []

    def test_unknown_session_returns_empty(self):
        assert DriftDetector().check("nope") == []

    def test_analyze_without_record(self):
        d = DriftDetector()
        for _i in range(10):
            d.observe("code", "decompile", "s1", latency_ms=10.0, error=None, addr="0x1000")
        signals = d.check("s1")
        assert "ANALYZE_WITHOUT_RECORD" in _types(signals)
        sig = next(s for s in signals if s["type"] == "ANALYZE_WITHOUT_RECORD")
        assert sig["analysis_calls"] == 10
        assert sig["record_calls"] == 0

    def test_low_record_rate_when_some_records_exist(self):
        d = DriftDetector()
        for _i in range(20):
            d.observe("code", "decompile", "s1", latency_ms=10.0, error=None)
        d.observe("blackboard", "write", "s1", latency_ms=5.0, error=None)
        signals = d.check("s1")
        assert "LOW_RECORD_RATE" in _types(signals)
        sig = next(s for s in signals if s["type"] == "LOW_RECORD_RATE")
        assert sig["record_rate"] == round(1 / 20, 3)

    def test_repeated_addr(self):
        d = DriftDetector()
        for _i in range(6):
            d.observe("code", "decompile", "s1", latency_ms=1.0, error=None, addr="0x401000")
        signals = d.check("s1")
        assert "REPEATED_ADDR" in _types(signals)
        sig = next(s for s in signals if s["type"] == "REPEATED_ADDR")
        assert sig["addr"] == "0x401000"
        assert sig["count"] == 6

    def test_high_error_rate(self):
        d = DriftDetector()
        for _i in range(10):
            error = "boom" if _i < 4 else None
            d.observe("code", "decompile", "s1", latency_ms=1.0, error=error)
        signals = d.check("s1")
        assert "HIGH_ERROR_RATE" in _types(signals)
        sig = next(s for s in signals if s["type"] == "HIGH_ERROR_RATE")
        assert sig["error_rate"] == 0.4

    def test_loop_detection_on_recent_tail(self):
        d = DriftDetector()
        states = [("misc", "health"), ("misc", "cache_stats")] * 5
        for tool, action in states:
            d.observe(tool, action, "s1", latency_ms=1.0, error=None)
        signals = d.check("s1")
        assert "LOOP" in _types(signals)
        sig = next(s for s in signals if s["type"] == "LOOP")
        assert set(sig["states"]) == {"misc.health", "misc.cache_stats"}

    def test_session_report_shape(self):
        d = DriftDetector()
        for _i in range(6):
            d.observe("code", "decompile", "s1", latency_ms=20.0, error="x" if _i == 0 else None, addr="0x1000")
        report = d.session_report("s1")
        assert report["session_id"] == "s1"
        assert report["total_calls"] == 6
        assert report["analysis_calls"] == 6
        assert report["error_calls"] == 1
        assert report["error_rate"] == round(1 / 6, 3)
        assert report["avg_latency_ms"] == 20.0
        assert report["top_addresses"] == {"0x1000": 6}
        assert report["drift_signals"]

    def test_session_report_unknown(self):
        report = DriftDetector().session_report("nope")
        assert report == {"session_id": "nope", "total_calls": 0}


class TestUsageIntelligence:
    def test_observe_and_drift_notification(self):
        notifications = []
        ui = UsageIntelligence("/tmp/audit", notify_fn=notifications.append)
        for _i in range(8):
            ui.observe("code", "decompile", "s1", latency_ms=10.0, error=None)
        ui._check_all_sessions()  # synchronous drift sweep
        drift = [n for n in notifications if n.get("params", {}).get("data", {}).get("type") == "usage_drift"]
        assert drift
        assert drift[0]["params"]["data"]["session_id"] == "s1"

    def test_start_stop_loop(self):
        ui = UsageIntelligence("/tmp/audit")
        ui.start()
        assert ui._thread is not None and ui._thread.is_alive()
        ui.stop()
        ui._thread.join(timeout=5)
        assert not ui._thread.is_alive()

    def test_predict_next_is_noop(self):
        ui = UsageIntelligence("/tmp/audit")
        assert ui.predict_next("code", "decompile", top_k=5) == []

    def test_global_report_tracks_active_sessions(self):
        ui = UsageIntelligence("/tmp/audit")
        ui.observe("code", "decompile", "s1")
        ui.observe("code", "decompile", "s2")
        assert ui.global_report() == {"active_sessions": 2}
