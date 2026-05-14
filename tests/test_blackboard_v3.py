"""
Tests for blackboard v3 improvements:
1. evidence field + source_type + version
2. next_target xref seeding when sparse
3. next_target time decay
4. rejection feedback loop (dead_end entries)
5. crawler feed stage
6. ida://state TTL cache
7. confidence calibration, campaign_summary, auto_tag_propagate, entropy scan
"""
import json
import math
import os
import struct
import sys
import tempfile
import time
import types
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── load modules ──────────────────────────────────────────────────────────────

def _load_bb():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "blackboard.py")
    spec = importlib.util.spec_from_file_location("_bb_v3", path)
    mod = importlib.util.module_from_spec(spec)
    _stub_names = ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
                   "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
                   "ida_hexrays", "ida_frame", "ida_struct", "ida_lines"]
    _saved = {m: sys.modules.get(m) for m in _stub_names}
    for m in _stub_names:
        if m not in sys.modules:
            sys.modules[m] = types.ModuleType(m)
    if not hasattr(sys.modules["idaapi"], "BADADDR"):
        sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
    try:
        spec.loader.exec_module(mod)
    finally:
        for m, orig in _saved.items():
            if orig is None:
                sys.modules.pop(m, None)
            else:
                sys.modules[m] = orig
    return mod

def _load_engine():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "host", "analysis_engine.py")
    spec = importlib.util.spec_from_file_location("_ae_v3", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _load_resources():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "host", "resources.py")
    spec = importlib.util.spec_from_file_location("_res_v3", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_bb = _load_bb()
_ae = _load_engine()
_res = _load_resources()

BlackboardStore = _bb.BlackboardStore
AnalysisEngine = _ae.AnalysisEngine
ProposalStore = _ae.ProposalStore
ResourceResolver = _res.ResourceResolver


def _store():
    return BlackboardStore(db_path=tempfile.mktemp(suffix=".db"))

def _engine(rpc=None, notify=None):
    bb = tempfile.mktemp(suffix=".bb.db")
    props = tempfile.mktemp(suffix=".props.db")
    return _ae.AnalysisEngine(
        session_id="v3test01",
        rpc_fn=rpc or (lambda t, a: {}),
        notify_fn=notify or (lambda n: None),
        bb_path=bb,
        proposals_path=props,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Evidence field + source_type + version
# ═══════════════════════════════════════════════════════════════════════════════

def test_write_with_evidence():
    s = _store()
    ev = [{"type": "constant", "value": "0x63636363", "weight": 0.9, "ts": time.time()}]
    eid = s.write("AES key schedule", category="hypothesis", addr="0x401000",
                  confidence=0.8, evidence=ev, source_type="engine_classifier")
    e = s.read(eid)
    assert e["evidence"] == ev
    assert e["source_type"] == "engine_classifier"
    assert e["version"] == 1


def test_add_evidence():
    s = _store()
    eid = s.write("AES key schedule", category="hypothesis", addr="0x401000",
                  confidence=0.8, embed=False)
    ok = s.add_evidence(eid, "constant", "0x63636363", weight=0.9)
    assert ok
    ok2 = s.add_evidence(eid, "import", "AES_set_encrypt_key", weight=0.8)
    assert ok2
    e = s.read(eid)
    assert len(e["evidence"]) == 2
    assert e["evidence"][0]["type"] == "constant"
    assert e["evidence"][1]["type"] == "import"


def test_add_evidence_nonexistent():
    s = _store()
    assert not s.add_evidence("nonexistent", "constant", "0x0")


def test_version_increments_on_update():
    s = _store()
    eid = s.write("Test", category="general", embed=False)
    e1 = s.read(eid)
    assert e1["version"] == 1
    s.update(eid, confidence=0.9)
    e2 = s.read(eid)
    assert e2["version"] == 2
    s.update(eid, confidence=0.95)
    e3 = s.read(eid)
    assert e3["version"] == 3


def test_source_type_defaults_to_source():
    s = _store()
    eid = s.write("Test", source="crawler", embed=False)
    e = s.read(eid)
    assert e["source_type"] == "crawler"


def test_stats_includes_source_types():
    s = _store()
    s.write("A", source_type="engine_classifier", embed=False)
    s.write("B", source_type="human", embed=False)
    s.write("C", source_type="engine_taint", embed=False)
    stats = s.stats()
    assert "source_types" in stats
    assert stats["source_types"].get("engine_classifier", 0) >= 1
    assert stats["source_types"].get("human", 0) >= 1


def test_stats_includes_evidence_count():
    s = _store()
    eid = s.write("A", embed=False)
    s.add_evidence(eid, "constant", "0x1234", weight=0.8)
    s.add_evidence(eid, "import", "recv", weight=0.9)
    stats = s.stats()
    assert stats["total_evidence_records"] >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# 2. next_target xref seeding
# ═══════════════════════════════════════════════════════════════════════════════

def test_next_target_seeds_from_xrefs_when_sparse():
    s = _store()
    # Only 1 entry — sparse blackboard
    s.write("Known func", category="hypothesis", addr="0x401000",
            confidence=0.8, embed=False)

    def rpc(tool, args):
        if tool == "data" and args.get("action") == "functions":
            return {"functions": [
                {"name": "sub_402000", "start_ea": 0x402000, "xref_count": 5},
                {"name": "sub_403000", "start_ea": 0x403000, "xref_count": 15},
                {"name": "main", "start_ea": 0x404000},  # named — skip
            ]}
        return {}

    targets = s.next_target(limit=5, rpc_fn=rpc)
    addrs = [t["addr"] for t in targets]
    # Should include seeded unnamed functions
    assert "0x402000" in addrs or "0x403000" in addrs


def test_next_target_seed_respects_seen_addrs():
    s = _store()
    # Already have an entry for 0x402000
    s.write("Known", category="hypothesis", addr="0x402000",
            confidence=0.8, embed=False)

    def rpc(tool, args):
        if tool == "data":
            return {"functions": [
                {"name": "sub_402000", "start_ea": 0x402000},
                {"name": "sub_403000", "start_ea": 0x403000},
            ]}
        return {}

    targets = s.next_target(limit=5, rpc_fn=rpc)
    addrs = [t["addr"] for t in targets]
    # 0x402000 already in blackboard — should not be seeded again
    assert addrs.count("0x402000") == 1  # only from blackboard, not seeded


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Time decay
# ═══════════════════════════════════════════════════════════════════════════════

def test_next_target_time_decay():
    """Old entries score lower than new entries with same confidence."""
    import sqlite3
    s = _store()
    eid_new = s.write("New finding", category="hypothesis", addr="0x401000",
                      confidence=0.8, embed=False)
    eid_old = s.write("Old finding", category="hypothesis", addr="0x402000",
                      confidence=0.8, embed=False)

    # Make old entry 30 days old
    old_ts = time.time() - 30 * 86400
    with sqlite3.connect(s.db_path) as conn:
        conn.execute("UPDATE blackboard SET created_at=? WHERE id=?", (old_ts, eid_old))
        conn.commit()

    targets = s.next_target(limit=5)
    scores = {t["addr"]: t["priority_score"] for t in targets}
    # New entry should score higher than old entry (same confidence, different age)
    assert scores["0x401000"] > scores["0x402000"]


def test_next_target_age_days_field():
    s = _store()
    s.write("Test", category="hypothesis", addr="0x401000",
            confidence=0.8, embed=False)
    targets = s.next_target(limit=5)
    assert "age_days" in targets[0]
    assert targets[0]["age_days"] >= 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Rejection feedback loop
# ═══════════════════════════════════════════════════════════════════════════════

def test_rejection_writes_dead_end():
    bb_path = tempfile.mktemp(suffix=".bb.db")
    # Initialize blackboard schema
    store = BlackboardStore(db_path=bb_path)

    ps = ProposalStore(db_path=tempfile.mktemp(suffix=".props.db"))
    pid = ps.add("rename_batch", "Rename sub_401000", "summary",
                 [{"id": "a", "addr": "0x401000", "suggested_name": "foo"}],
                 confidence=0.7)

    ok = ps.reject(pid, bb_path=bb_path)
    assert ok

    # Should have written a dead_end entry
    dead_ends = store.list(category="dead_end", include_resolved=True)
    assert len(dead_ends) >= 1
    assert dead_ends[0]["addr"] == "0x401000"
    assert dead_ends[0]["resolved"] == 1  # excluded from next_target


def test_rejection_dead_end_excluded_from_next_target():
    bb_path = tempfile.mktemp(suffix=".bb.db")
    store = BlackboardStore(db_path=bb_path)

    # Write a hypothesis for 0x401000
    store.write("Hypothesis", category="hypothesis", addr="0x401000",
                confidence=0.9, embed=False)

    ps = ProposalStore(db_path=tempfile.mktemp(suffix=".props.db"))
    pid = ps.add("rename_batch", "Rename", "s",
                 [{"id": "a", "addr": "0x401000", "suggested_name": "foo"}])
    ps.reject(pid, bb_path=bb_path)

    # The dead_end entry is resolved=1, so next_target should still show
    # the hypothesis (different entry, same addr) but not the dead_end
    targets = store.next_target(limit=10)
    cats = [t["category"] for t in targets]
    assert "dead_end" not in cats


def test_rejection_no_duplicate_dead_ends():
    bb_path = tempfile.mktemp(suffix=".bb.db")
    store = BlackboardStore(db_path=bb_path)

    ps = ProposalStore(db_path=tempfile.mktemp(suffix=".props.db"))
    for _ in range(3):
        pid = ps.add("rename_batch", "Rename", "s",
                     [{"id": "a", "addr": "0x401000", "suggested_name": "foo"}])
        ps.reject(pid, bb_path=bb_path)

    dead_ends = store.list(category="dead_end", include_resolved=True)
    # Should not create duplicate dead_end entries for same addr
    addrs = [e["addr"] for e in dead_ends]
    assert addrs.count("0x401000") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Confidence calibration
# ═══════════════════════════════════════════════════════════════════════════════

def test_calibrate_confidence_from_evidence():
    s = _store()
    eid = s.write("AES", category="hypothesis", confidence=0.5, embed=False)
    s.add_evidence(eid, "constant", "0x63636363", weight=0.9)
    s.add_evidence(eid, "import", "AES_set_encrypt_key", weight=0.8)
    s.add_evidence(eid, "classifier", "crypto_symmetric", weight=0.85)

    new_conf = s.calibrate_confidence(eid)
    assert new_conf is not None
    # Average of 0.9, 0.8, 0.85 = 0.85
    assert abs(new_conf - 0.85) < 0.01

    e = s.read(eid)
    assert e["calibrated"] == 1
    assert abs(e["confidence"] - 0.85) < 0.01


def test_calibrate_no_evidence_returns_existing():
    s = _store()
    eid = s.write("Test", confidence=0.7, embed=False)
    conf = s.calibrate_confidence(eid)
    assert conf == 0.7


def test_calibrate_nonexistent():
    s = _store()
    assert s.calibrate_confidence("nonexistent") is None


def test_stats_includes_calibrated_count():
    s = _store()
    eid = s.write("A", confidence=0.5, embed=False)
    s.add_evidence(eid, "constant", "0x1234", weight=0.8)
    s.calibrate_confidence(eid)
    stats = s.stats()
    assert stats["calibrated_entries"] >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Campaign summary
# ═══════════════════════════════════════════════════════════════════════════════

def test_campaign_summary_structure():
    s = _store()
    s.write("AES key schedule", category="hypothesis", addr="0x401000",
            confidence=0.9, embed=False)
    s.write("C2 IP", category="ioc", ioc_type="ip_port", ioc_value="1.2.3.4:80",
            addr="0x402000", confidence=0.99, embed=False)
    eid = s.write("Dead end", category="dead_end", addr="0x403000", embed=False)
    s.mark_resolved(eid)
    s.write("Stack overflow via recv→memcpy", category="vuln", addr="0x404000",
            confidence=0.85, embed=False)

    summary = s.campaign_summary()
    assert summary["total_entries"] == 4
    assert summary["resolved"] == 1
    assert summary["active_entries"] == 3
    assert len(summary["top_findings"]) >= 1
    assert len(summary["iocs"]) >= 1
    assert len(summary["vulns"]) >= 1
    assert "recommended_next_action" in summary
    assert "vuln" in summary["recommended_next_action"].lower()


def test_campaign_summary_recommends_hypothesis_when_no_vuln():
    s = _store()
    s.write("Hypothesis", category="hypothesis", addr="0x401000",
            confidence=0.8, embed=False)
    summary = s.campaign_summary()
    assert "hypothesis" in summary["recommended_next_action"].lower() or \
           "hypothes" in summary["recommended_next_action"].lower()


def test_campaign_summary_source_types():
    s = _store()
    s.write("A", source_type="engine_classifier", embed=False)
    s.write("B", source_type="human", embed=False)
    summary = s.campaign_summary()
    assert "source_types" in summary
    assert summary["source_types"].get("engine_classifier", 0) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Auto-tag propagation
# ═══════════════════════════════════════════════════════════════════════════════

def test_auto_tag_propagate():
    s = _store()
    # High-confidence entry with tags at 0x401000
    s.write("AES init", category="hypothesis", addr="0x401000",
            confidence=0.9, tags=["crypto_symmetric", "aes"], embed=False)
    # Low-confidence entry at same address
    eid2 = s.write("Unknown func", category="general", addr="0x401000",
                   confidence=0.4, tags=["unknown"], embed=False)

    updated = s.auto_tag_propagate()
    assert updated >= 1

    e2 = s.read(eid2)
    assert "crypto_symmetric" in e2["tags"]
    assert "aes" in e2["tags"]
    assert "unknown" in e2["tags"]  # original tag preserved


def test_auto_tag_propagate_no_cross_address():
    s = _store()
    s.write("AES init", category="hypothesis", addr="0x401000",
            confidence=0.9, tags=["crypto_symmetric"], embed=False)
    eid2 = s.write("Network func", category="general", addr="0x402000",
                   confidence=0.4, tags=["network"], embed=False)

    s.auto_tag_propagate()

    e2 = s.read(eid2)
    # Tags should NOT propagate across different addresses
    assert "crypto_symmetric" not in e2["tags"]


def test_auto_tag_propagate_returns_count():
    s = _store()
    s.write("A", addr="0x401000", confidence=0.9, tags=["crypto"], embed=False)
    s.write("B", addr="0x401000", confidence=0.4, tags=[], embed=False)
    s.write("C", addr="0x401000", confidence=0.4, tags=[], embed=False)
    updated = s.auto_tag_propagate()
    assert updated >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# 8. ida://state TTL cache
# ═══════════════════════════════════════════════════════════════════════════════

def test_state_cache_hit():
    """Second read within TTL should not call data/functions again."""
    call_counts = {"data": 0}

    def exec_fn(name, kwargs):
        if name == "data":
            call_counts["data"] += 1
        if name == "idb":
            return {"filename": "test.exe", "processor": "ARM", "bits": 32}
        if name == "data":
            return {"functions": [{"name": "sub_401000", "start_ea": 0x401000}]}
        return {}

    _res.invalidate_state_cache()
    resolver = ResourceResolver(exec_fn)
    resolver.read("ida://state")
    first_count = call_counts["data"]
    resolver.read("ida://state")
    second_count = call_counts["data"]
    # Second read should use cache — no additional data calls
    assert second_count == first_count


def test_state_cache_invalidation():
    """After invalidate_state_cache(), next read should re-fetch."""
    call_counts = {"data": 0}

    def exec_fn(name, kwargs):
        if name == "data":
            call_counts["data"] += 1
            return {"functions": [{"name": "sub_401000", "start_ea": 0x401000}]}
        if name == "idb":
            return {"filename": "test.exe"}
        return {}

    _res.invalidate_state_cache()
    resolver = ResourceResolver(exec_fn)
    resolver.read("ida://state")
    _res.invalidate_state_cache()
    resolver.read("ida://state")
    # Should have called data twice (once per read after invalidation)
    assert call_counts["data"] >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Entropy scan stage
# ═══════════════════════════════════════════════════════════════════════════════

def test_entropy_scan_detects_high_entropy():
    notifications = []
    eng = _engine(notify=lambda n: notifications.append(n))

    # High-entropy data (random-ish bytes)
    import os as _os
    high_entropy_bytes = bytes(range(256)) * 4  # 1024 bytes, entropy ~8
    hex_data = high_entropy_bytes.hex()

    def rpc(tool, args):
        if tool == "idb" and args.get("action") == "segments":
            return {"segments": [
                {"name": ".text", "start_ea": 0x401000, "end_ea": 0x402000}
            ]}
        if tool == "memory":
            return {"bytes": hex_data}
        return {}

    eng._rpc = rpc
    # Initialize blackboard
    store = BlackboardStore(db_path=eng._bb_path)
    eng._stage_entropy_scan()

    # Should have written a region entry
    regions = store.list(category="region", include_resolved=True)
    assert len(regions) >= 1
    assert regions[0]["entropy"] > 6.0

    # Should have pushed a notification
    entropy_notifs = [n for n in notifications
                      if n.get("params", {}).get("data", {}).get("type") == "high_entropy_region"]
    assert len(entropy_notifs) >= 1


def test_entropy_scan_skips_low_entropy():
    notifications = []
    eng = _engine(notify=lambda n: notifications.append(n))

    # Low-entropy data (all zeros)
    low_entropy_bytes = bytes(1024)
    hex_data = low_entropy_bytes.hex()

    def rpc(tool, args):
        if tool == "idb":
            return {"segments": [
                {"name": ".bss", "start_ea": 0x403000, "end_ea": 0x404000}
            ]}
        if tool == "memory":
            return {"bytes": hex_data}
        return {}

    eng._rpc = rpc
    store = BlackboardStore(db_path=eng._bb_path)
    eng._stage_entropy_scan()

    regions = store.list(category="region", include_resolved=True)
    assert len(regions) == 0


def test_byte_entropy_all_zeros():
    eng = _engine()
    assert eng._byte_entropy(bytes(256)) == 0.0


def test_byte_entropy_uniform():
    eng = _engine()
    # All 256 byte values equally — maximum entropy
    data = bytes(range(256))
    entropy = eng._byte_entropy(data)
    assert entropy > 7.9  # close to 8.0


# ═══════════════════════════════════════════════════════════════════════════════
# 10. blackboard() tool function — new actions
# ═══════════════════════════════════════════════════════════════════════════════

def test_tool_add_evidence():
    s = _store()
    eid = s.write("Test", embed=False)
    result = _bb.blackboard(action="add_evidence", entry_id=eid,
                            evidence_type="constant", evidence_value="0x1234",
                            evidence_weight=0.9, db_path=s.db_path)
    assert result["ok"] is True
    e = s.read(eid)
    assert len(e["evidence"]) == 1


def test_tool_calibrate():
    s = _store()
    eid = s.write("Test", confidence=0.5, embed=False)
    s.add_evidence(eid, "constant", "0x1234", weight=0.8)
    result = _bb.blackboard(action="calibrate", entry_id=eid, db_path=s.db_path)
    assert result["ok"] is True
    assert result["confidence"] == 0.8


def test_tool_campaign_summary():
    s = _store()
    s.write("Hypothesis", category="hypothesis", addr="0x401000",
            confidence=0.9, embed=False)
    result = _bb.blackboard(action="campaign_summary", db_path=s.db_path)
    assert result["ok"] is True
    assert "total_entries" in result
    assert "recommended_next_action" in result


def test_tool_auto_tag_propagate():
    s = _store()
    s.write("A", addr="0x401000", confidence=0.9, tags=["crypto"], embed=False)
    s.write("B", addr="0x401000", confidence=0.4, tags=[], embed=False)
    result = _bb.blackboard(action="auto_tag_propagate", db_path=s.db_path)
    assert result["ok"] is True
    assert result["updated"] >= 1


def test_tool_write_with_evidence_and_source_type():
    s = _store()
    ev = [{"type": "classifier", "value": "crypto_symmetric", "weight": 0.85}]
    result = _bb.blackboard(
        action="write", title="AES init",
        category="hypothesis", addr="0x401000",
        confidence=0.85, evidence=ev, source_type="engine_classifier",
        db_path=s.db_path,
    )
    assert result["ok"] is True
    e = s.read(result["entry_id"])
    assert e["source_type"] == "engine_classifier"
    assert len(e["evidence"]) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# KG write actions via blackboard tool
# ═══════════════════════════════════════════════════════════════════════════════

def test_tool_add_system():
    s = _store()
    result = _bb.blackboard(
        action="add_system", title="Crypto subsystem",
        content="AES + SHA functions",
        members=["0x401000", "0x402000"],
        confidence=0.8, db_path=s.db_path,
    )
    assert result["ok"] is True
    assert "system_id" in result
    # Verify via kg_systems
    r2 = _bb.blackboard(action="kg_systems", db_path=s.db_path)
    assert r2["ok"] is True
    assert any(sys["name"] == "Crypto subsystem" for sys in r2["systems"])


def test_tool_add_gap_and_fill():
    s = _store()
    r1 = _bb.blackboard(
        action="add_gap", title="WPA key derivation",
        content="All WPA2 firmware must derive PTK/GTK",
        hints=["Look for HMAC-SHA1"],
        confidence=0.9, gap_type="security", db_path=s.db_path,
    )
    assert r1["ok"] is True
    gid = r1["gap_id"]

    # Fill it
    r2 = _bb.blackboard(action="fill_gap", gap_id=gid,
                        addr="0x401234", db_path=s.db_path)
    assert r2["ok"] is True

    # Verify filled
    r3 = _bb.blackboard(action="kg_gaps", resolved=True, db_path=s.db_path)
    assert r3["ok"] is True
    assert any(g["filled_by"] == "0x401234" for g in r3["gaps"])


def test_tool_add_struct():
    s = _store()
    result = _bb.blackboard(
        action="add_struct", title="wifi_frame_t",
        members=[{"offset": 0, "size": 2, "name": "frame_ctrl"}],
        size_bytes=24, confidence=0.75, db_path=s.db_path,
    )
    assert result["ok"] is True
    r2 = _bb.blackboard(action="kg_structs", db_path=s.db_path)
    assert any(s["name"] == "wifi_frame_t" for s in r2["structs"])


def test_tool_add_state_machine():
    s = _store()
    result = _bb.blackboard(
        action="add_state_machine", title="Auth SM",
        addr="0x80420000",
        states=[{"value": 0, "name": "IDLE"}, {"value": 1, "name": "AUTH"}],
        confidence=0.7, db_path=s.db_path,
    )
    assert result["ok"] is True
    r2 = _bb.blackboard(action="kg_state_machines", db_path=s.db_path)
    assert any(sm["name"] == "Auth SM" for sm in r2["state_machines"])


def test_tool_add_peripheral():
    s = _store()
    result = _bb.blackboard(
        action="add_peripheral", title="AES accelerator",
        addr="0xA0010000", periph_type="crypto",
        confidence=0.8, db_path=s.db_path,
    )
    assert result["ok"] is True
    r2 = _bb.blackboard(action="kg_peripherals", db_path=s.db_path)
    assert any(p["periph_type"] == "crypto" for p in r2["peripherals"])


def test_tool_add_attack_surface():
    s = _store()
    result = _bb.blackboard(
        action="add_attack_surface", title="Mgmt frame handler",
        addr="0x401000", reachable_from="air_unauthenticated",
        input_type="management_frame", confidence=0.9, db_path=s.db_path,
    )
    assert result["ok"] is True
    r2 = _bb.blackboard(action="kg_attack_surface", db_path=s.db_path)
    assert any(a["reachable_from"] == "air_unauthenticated" for a in r2["attack_surface"])


def test_tool_kg_summary():
    s = _store()
    _bb.blackboard(action="add_system", title="Crypto", db_path=s.db_path)
    _bb.blackboard(action="add_gap", title="WPA", confidence=0.9, db_path=s.db_path)
    result = _bb.blackboard(action="kg_summary", db_path=s.db_path)
    assert result["ok"] is True
    assert result["systems"] == 1
    assert result["gaps_open"] == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
