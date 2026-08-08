"""Regression tests for p09 usage-intelligence fixes.

Covers:
  - UsageIntelligence.is_running() exists (server_dispatch gates the
    STUCK_LOOP blocker on it).
  - DriftDetector LOOP detection is per-session, not host-global.
  - _check_all_sessions de-duplicates repeated warning notifications.
  - DriftDetector.prune drops idle sessions so state does not grow unbounded.
"""
from __future__ import annotations

import time

from ida_pro_mcp.host.intelligence.usage import DriftDetector, UsageIntelligence


def _types(signals):
    return {s["type"] for s in signals}


def test_is_running_reflects_background_thread():
    ui = UsageIntelligence("/tmp/audit")
    assert ui.is_running() is False
    ui.start()
    try:
        assert ui.is_running() is True
    finally:
        ui.stop()
        if ui._thread is not None:
            ui._thread.join(timeout=5)
    assert ui.is_running() is False


def test_loop_detection_is_isolated_per_session():
    # Session s1 alternates two states (genuine micro-loop); session s2
    # interleaves a third state.  A host-global recent tail would dilute s1's
    # loop; per-session tails must keep it detected.
    d = DriftDetector()
    states = [("misc", "health"), ("misc", "cache_stats")] * 5
    for tool, action in states:
        d.observe(tool, action, "s1", latency_ms=1.0, error=None)
    for _i in range(10):
        d.observe("code", "decompile", "s2", latency_ms=1.0, error=None)
    assert "LOOP" in _types(d.check("s1"))
    # s2 has only repeated code.decompile calls, so its tail is a single state.
    assert "LOOP" in _types(d.check("s2"))


def test_loop_detection_not_polluted_by_other_session():
    # Session s1 calls three DIFFERENT states in rotation (not a loop); s2
    # interleaves the same states in an order that WOULD look like a loop under
    # a host-global recent tail.  Per-session scoping keeps s1's tail clean.
    d = DriftDetector()
    s1_states = [("misc", "health"), ("misc", "cache_stats"), ("search", "find")]
    for _i in range(10):
        tool, action = s1_states[_i % 3]
        d.observe(tool, action, "s1", latency_ms=1.0, error=None)
        d.observe("code", "decompile", "s2", latency_ms=1.0, error=None)
        d.observe("graph", "callgraph", "s2", latency_ms=1.0, error=None)
    assert "LOOP" not in _types(d.check("s1"))


def test_drift_notifications_are_deduplicated():
    notifications = []
    ui = UsageIntelligence("/tmp/audit", notify_fn=notifications.append)
    for _i in range(8):
        ui.observe("code", "decompile", "s1", latency_ms=10.0, error=None)
    ui._check_all_sessions()
    ui._check_all_sessions()
    drift = [
        n for n in notifications
        if n.get("params", {}).get("data", {}).get("type") == "usage_drift"
    ]
    assert len(drift) == 1  # identical warning must not spam every cycle


def test_prune_drops_idle_sessions():
    d = DriftDetector()
    d.observe("code", "decompile", "s1", latency_ms=1.0, error=None)
    d.observe("code", "decompile", "s2", latency_ms=1.0, error=None)
    assert "s1" in dict(d._session_stats)
    d.prune(time.time() + 100)
    assert dict(d._session_stats) == {}
    assert d.check("s1") == []
