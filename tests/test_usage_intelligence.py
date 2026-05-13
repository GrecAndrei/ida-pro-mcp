"""Tests for UsageIntelligence: SequenceModel, EffectivenessModel, DriftDetector, AuditMiner."""
import json
import os
import sys
import tempfile
import time
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_path = os.path.join(os.path.dirname(__file__), "..", "src",
                     "ida_pro_mcp", "host", "usage_intelligence.py")
_spec = importlib.util.spec_from_file_location("_ui_test", _path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SequenceModel = _mod.SequenceModel
EffectivenessModel = _mod.EffectivenessModel
DriftDetector = _mod.DriftDetector
AuditMiner = _mod.AuditMiner
UsageIntelligence = _mod.UsageIntelligence


# ── SequenceModel ─────────────────────────────────────────────────────────────

def test_seq_predict_after_observations():
    m = SequenceModel()
    for _ in range(5):
        m.observe(("code", "decompile"), ("classify", "function"))
    for _ in range(2):
        m.observe(("code", "decompile"), ("modify", "rename"))
    preds = m.predict(("code", "decompile"), top_k=3)
    assert len(preds) >= 1
    top = preds[0]
    assert top[0] == ("classify", "function")
    assert top[1] > 0.5


def test_seq_predict_empty():
    m = SequenceModel()
    assert m.predict(("code", "decompile")) == []


def test_seq_is_loop_true():
    m = SequenceModel()
    recent = [("code", "decompile")] * 6
    assert m.is_loop(recent, window=5)


def test_seq_is_loop_false():
    m = SequenceModel()
    recent = [("code", "decompile"), ("classify", "function"),
              ("blackboard", "write"), ("modify", "rename"),
              ("code", "disasm")]
    assert not m.is_loop(recent, window=5)


def test_seq_to_dict():
    m = SequenceModel()
    m.observe(("code", "decompile"), ("classify", "function"))
    d = m.to_dict()
    assert d["transitions"] == 1
    assert d["total_observations"] == 1
    assert len(d["top_sequences"]) == 1


# ── EffectivenessModel ────────────────────────────────────────────────────────

def test_eff_default_score():
    m = EffectivenessModel()
    assert m.score("code", "decompile") == 0.5


def test_eff_productive_increases_score():
    m = EffectivenessModel(alpha=0.5)
    m.observe_outcome(("code", "decompile"), productive=True)
    assert m.score("code", "decompile") > 0.5


def test_eff_unproductive_decreases_score():
    m = EffectivenessModel(alpha=0.5)
    m.observe_outcome(("code", "decompile"), productive=False)
    assert m.score("code", "decompile") < 0.5


def test_eff_rank_suggestions():
    m = EffectivenessModel(alpha=0.5)
    for _ in range(5):
        m.observe_outcome(("classify", "function"), productive=True)
    for _ in range(5):
        m.observe_outcome(("search", "strings"), productive=False)
    ranked = m.rank_suggestions([("classify", "function"), ("search", "strings")])
    assert ranked[0][0] == ("classify", "function")


def test_eff_low_effectiveness_tools():
    m = EffectivenessModel(alpha=0.3)
    for _ in range(6):
        m.observe_outcome(("search", "strings"), productive=False)
    low = m.low_effectiveness_tools(threshold=0.4)
    assert any(t["tool"] == "search" for t in low)


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


# ── AuditMiner ────────────────────────────────────────────────────────────────

def _write_audit(path: str, records: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_audit_miner_basic():
    tmpdir = tempfile.mkdtemp()
    audit_path = os.path.join(tmpdir, "2026-05", "audit_2026-05-01.jsonl")
    records = [
        {"tool": "code", "action": "decompile", "session_id": "s1",
         "latency_ms": 120.0, "error": None, "args_preview": '{"addr":"0x401000"}'},
        {"tool": "classify", "action": "function", "session_id": "s1",
         "latency_ms": 80.0, "error": None},
        {"tool": "blackboard", "action": "write", "session_id": "s1",
         "latency_ms": 30.0, "error": None},
    ]
    _write_audit(audit_path, records)

    seq = SequenceModel()
    eff = EffectivenessModel()
    drift = DriftDetector()
    miner = AuditMiner(tmpdir, seq, eff, drift)
    count = miner.mine_all()
    assert count == 3

    # Sequence: code.decompile → classify.function should be observed
    preds = seq.predict(("code", "decompile"))
    assert len(preds) >= 1
    assert preds[0][0] == ("classify", "function")


def test_audit_miner_incremental():
    tmpdir = tempfile.mkdtemp()
    audit_path = os.path.join(tmpdir, "2026-05", "audit_2026-05-01.jsonl")
    records1 = [
        {"tool": "code", "action": "decompile", "session_id": "s1",
         "latency_ms": 100.0, "error": None},
    ]
    _write_audit(audit_path, records1)

    seq = SequenceModel()
    eff = EffectivenessModel()
    drift = DriftDetector()
    miner = AuditMiner(tmpdir, seq, eff, drift)
    count1 = miner.mine_all()
    assert count1 == 1

    # Append more records
    with open(audit_path, "a") as f:
        f.write(json.dumps({"tool": "classify", "action": "function",
                            "session_id": "s1", "latency_ms": 80.0, "error": None}) + "\n")

    count2 = miner.mine_incremental()
    assert count2 == 1  # only the new record


def test_audit_miner_effectiveness_update():
    tmpdir = tempfile.mkdtemp()
    audit_path = os.path.join(tmpdir, "2026-05", "audit_2026-05-01.jsonl")
    # code.decompile followed by blackboard.write (productive)
    records = [
        {"tool": "code", "action": "decompile", "session_id": "s1",
         "latency_ms": 100.0, "error": None},
        {"tool": "blackboard", "action": "write", "session_id": "s1",
         "latency_ms": 30.0, "error": None},
    ]
    _write_audit(audit_path, records)

    seq = SequenceModel()
    eff = EffectivenessModel(alpha=0.5)
    drift = DriftDetector()
    miner = AuditMiner(tmpdir, seq, eff, drift)
    miner.mine_all()

    # code.decompile should have increased effectiveness (followed by productive action)
    score = eff.score("code", "decompile")
    assert score > 0.5


# ── UsageIntelligence ─────────────────────────────────────────────────────────

def test_usage_intel_start_stop():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.start()
    assert ui._thread is not None and ui._thread.is_alive()
    ui.stop()
    import time as _t; _t.sleep(0.1)
    assert ui._stop.is_set()


def test_usage_intel_observe_and_predict():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)

    # Simulate observations
    for _ in range(5):
        ui.seq.observe(("code", "decompile"), ("classify", "function"))
    for _ in range(3):
        ui.seq.observe(("code", "decompile"), ("blackboard", "write"))

    preds = ui.predict_next("code", "decompile", top_k=3)
    assert len(preds) >= 1
    assert preds[0]["tool"] in ("classify", "blackboard")
    assert "probability" in preds[0]
    assert "effectiveness" in preds[0]
    assert "score" in preds[0]


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


def test_usage_intel_global_report():
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.seq.observe(("code", "decompile"), ("classify", "function"))
    report = ui.global_report()
    assert "sequence_model" in report
    assert "effectiveness_model" in report
    assert report["sequence_model"]["transitions"] == 1


def test_usage_intel_drift_notification():
    notifications = []
    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir,
                           notify_fn=lambda n: notifications.append(n))
    # Simulate stuck loop
    for _ in range(15):
        ui.observe("code", "decompile", "sess1", latency_ms=100.0)
    ui._check_all_sessions()
    assert len(notifications) >= 1
    assert notifications[0]["method"] == "notifications/message"
    assert notifications[0]["params"]["data"]["type"] == "usage_drift"


# ── ida://usage resource ──────────────────────────────────────────────────────

def test_usage_resource_no_intel():
    _res_path = os.path.join(os.path.dirname(__file__), "..", "src",
                             "ida_pro_mcp", "host", "resources.py")
    _rspec = importlib.util.spec_from_file_location("_res_ui", _res_path)
    _rmod = importlib.util.module_from_spec(_rspec)
    _rspec.loader.exec_module(_rmod)

    resolver = _rmod.ResourceResolver(lambda n, k: {})
    result = resolver.read("ida://usage")
    data = json.loads(result["text"])
    assert "error" in data


def test_usage_resource_with_intel():
    _res_path = os.path.join(os.path.dirname(__file__), "..", "src",
                             "ida_pro_mcp", "host", "resources.py")
    _rspec = importlib.util.spec_from_file_location("_res_ui2", _res_path)
    _rmod = importlib.util.module_from_spec(_rspec)
    _rspec.loader.exec_module(_rmod)

    tmpdir = tempfile.mkdtemp()
    ui = UsageIntelligence(audit_dir=tmpdir)
    ui.seq.observe(("code", "decompile"), ("classify", "function"))

    resolver = _rmod.ResourceResolver(lambda n, k: {}, usage_intel=ui)
    result = resolver.read("ida://usage")
    data = json.loads(result["text"])
    assert "sequence_model" in data
    assert data["sequence_model"]["transitions"] == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
