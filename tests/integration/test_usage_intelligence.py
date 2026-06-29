"""Tests for UsageIntelligence drift detection (DriftDetector + live observer).

The speculative SequenceModel / EffectivenessModel / AuditMiner that tried to
predict the LLM's next action and score tool-combo effectiveness were removed
as unvalidated LLM-steering; only the live stuck-loop / wasted-effort drift
detector remains.
"""
import json
import tempfile

from tests._isolated_repo_loader import load_host_module

_mod = load_host_module("intelligence.usage")

DriftDetector = _mod.DriftDetector
UsageIntelligence = _mod.UsageIntelligence


# ── DriftDetector ─────────────────────────────────────────────────────────────

def test_drift_analyze_without_record():
    d = DriftDetector()
    for _ in range(12):
        d.observe("code", "decompile", "sess1", 100.0, None)
    signals = d.check("sess1")
    types = [s["type"] for s in signals]
    assert "ANALYZE_WITHOUT_RECORD" in types


def test_drift_no_signal_with_records():
    d = DriftDetector()
    for _ in range(5):
        d.observe("code", "decompile", "sess1", 100.0, None)
        d.observe("blackboard", "write", "sess1", 50.0, None)
    signals = d.check("sess1")
    types = [s["type"] for s in signals]
    assert "ANALYZE_WITHOUT_RECORD" not in types


def test_drift_repeated_addr():
    d = DriftDetector()
    for _ in range(5):
        d.observe("code", "decompile", "sess1", 100.0, None, addr="0x401000")
    signals = d.check("sess1")
    types = [s["type"] for s in signals]
    assert "REPEATED_ADDR" in types
    addr_sig = next(s for s in signals if s["type"] == "REPEATED_ADDR")
    assert addr_sig["addr"] == "0x401000"


def test_drift_high_error_rate():
    d = DriftDetector()
    for _ in range(4):
        d.observe("code", "decompile", "sess1", 100.0, "error: not found")
    for _ in range(6):
        d.observe("code", "decompile", "sess1", 100.0, None)
    signals = d.check("sess1")
    types = [s["type"] for s in signals]
    assert "HIGH_ERROR_RATE" in types


def test_drift_loop_detection():
    d = DriftDetector(window=10)
    for _ in range(7):
        d.observe("code", "decompile", "sess1", 100.0, None)
    signals = d.check("sess1")
    types = [s["type"] for s in signals]
    assert "LOOP" in types


def test_drift_session_report():
    d = DriftDetector()
    d.observe("code", "decompile", "sess1", 150.0, None, addr="0x401000")
    d.observe("blackboard", "write", "sess1", 50.0, None)
    report = d.session_report("sess1")
    assert report["total_calls"] == 2
    assert report["analysis_calls"] == 1
    assert report["record_calls"] == 1
    assert "0x401000" in report["top_addresses"]


def test_drift_empty_session():
    d = DriftDetector()
    report = d.session_report("nonexistent")
    assert report["total_calls"] == 0


# ── UsageIntelligence (live observer) ─────────────────────────────────────────

def test_usage_intel_start_stop():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.start()
    assert ui._thread is not None and ui._thread.is_alive()
    ui.stop()
    import time as _t
    _t.sleep(0.1)
    assert ui._stop.is_set()


def test_usage_intel_observe_and_predict_is_noop():
    # predict_next is now a no-op (Markov/effectiveness models removed).
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.observe("code", "decompile", "sess1", latency_ms=100.0)
    assert ui.predict_next("code", "decompile", top_k=3) == []


def test_usage_intel_session_report():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.observe("code", "decompile", "sess1", latency_ms=100.0)
    ui.observe("code", "decompile", "sess1", latency_ms=120.0)
    ui.observe("blackboard", "write", "sess1", latency_ms=30.0)
    report = ui.session_report("sess1")
    assert report["total_calls"] == 3
    assert report["analysis_calls"] == 2
    assert report["record_calls"] == 1


def test_usage_intel_global_report_drift_only():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.observe("code", "decompile", "sess1", latency_ms=100.0)
    report = ui.global_report()
    assert "active_sessions" in report
    # The removed sequence/effectiveness models are no longer reported.
    assert "sequence_model" not in report
    assert "effectiveness_model" not in report


def test_usage_intel_drift_notification():
    notifications = []
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir,
                           notify_fn=notifications.append)
    # Simulate stuck loop
    for _ in range(15):
        ui.observe("code", "decompile", "sess1", latency_ms=100.0)
    ui._check_all_sessions()
    assert len(notifications) >= 1
    assert notifications[0]["method"] == "notifications/message"
    assert notifications[0]["params"]["data"]["type"] == "usage_drift"


# ── ida://usage resource ──────────────────────────────────────────────────────

def test_usage_resource_no_intel():
    _rmod = load_host_module("resources")

    resolver = _rmod.ResourceResolver(lambda n, k: {})
    result = resolver.read("ida://usage")
    data = json.loads(result["text"])
    assert "error" in data


def test_usage_resource_with_intel():
    _rmod = load_host_module("resources")

    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.observe("code", "decompile", "sess1", latency_ms=100.0)

    resolver = _rmod.ResourceResolver(lambda n, k: {}, usage_intel=ui)
    result = resolver.read("ida://usage")
    data = json.loads(result["text"])
    assert "active_sessions" in data
    assert "sequence_model" not in data


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
