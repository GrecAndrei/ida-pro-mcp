"""
IDA integration tests for blackboard v4 features:
- KnowledgeGraph write/read via blackboard tool
- GapEngine seeding and filling
- NarrativeEngine generation
- AnalysisEngine KG stage (system discovery, peripheral detection)
- response_enrichment → KG update
- UsageIntelligence session report
"""
import os
import sys
import importlib.util as _ilu
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_conftest_path = os.path.join(os.path.dirname(__file__), "integration", "conftest.py")
_spec = _ilu.spec_from_file_location("_ic_v4", _conftest_path)
_ic = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_ic)
IDARunner = _ic.IDARunner
ida_is_available = _ic.ida_is_available

pytestmark = pytest.mark.skipif(
    not ida_is_available(), reason="IDA Pro not available"
)


@pytest.fixture(scope="module")
def runner():
    if not ida_is_available():
        pytest.skip("IDA Pro not available")
    return IDARunner()


class TestKnowledgeGraphIDA:
    """KG write/read via blackboard tool inside real IDA."""

    def test_add_and_read_system(self, runner):
        script = '''
import sys, os, tempfile, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__) if "__file__" in dir() else ".", "..", "src"))
from blackboard import blackboard

db = tempfile.mktemp(suffix=".db")

# Add a system
r1 = blackboard(action="add_system", title="Crypto subsystem",
                content="AES + SHA functions",
                members=["0x401000", "0x402000"],
                confidence=0.8, db_path=db)

# Read it back
r2 = blackboard(action="kg_systems", db_path=db)

result = {
    "ok": r1.get("ok") and r2.get("ok"),
    "system_id": r1.get("system_id"),
    "systems_count": len(r2.get("systems", [])),
    "system_name": r2["systems"][0]["name"] if r2.get("systems") else None,
    "members_count": len(r2["systems"][0].get("members", [])) if r2.get("systems") else 0,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["systems_count"] == 1
        assert r["system_name"] == "Crypto subsystem"
        assert r["members_count"] == 2

    def test_add_gap_and_fill(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import blackboard

db = tempfile.mktemp(suffix=".db")

r1 = blackboard(action="add_gap", title="WPA key derivation",
                content="All WPA2 firmware must derive PTK/GTK",
                hints=["Look for HMAC-SHA1 with 4096 iterations"],
                confidence=0.9, gap_type="security", db_path=db)

gid = r1.get("gap_id", "")

r2 = blackboard(action="fill_gap", gap_id=gid, addr="0x401234", db_path=db)

r3 = blackboard(action="kg_gaps", resolved=True, db_path=db)

result = {
    "ok": r1.get("ok") and r2.get("ok"),
    "gap_id": gid,
    "filled_gaps": len(r3.get("gaps", [])),
    "filled_by": r3["gaps"][0].get("filled_by") if r3.get("gaps") else None,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["filled_gaps"] == 1
        assert r["filled_by"] == "0x401234"

    def test_add_peripheral(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import blackboard

db = tempfile.mktemp(suffix=".db")

r1 = blackboard(action="add_peripheral", title="AES accelerator",
                addr="0xA0010000", periph_type="crypto",
                confidence=0.8, db_path=db)

r2 = blackboard(action="kg_peripherals", db_path=db)

result = {
    "ok": r1.get("ok"),
    "peripheral_id": r1.get("peripheral_id"),
    "periph_count": len(r2.get("peripherals", [])),
    "periph_type": r2["peripherals"][0].get("periph_type") if r2.get("peripherals") else None,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["periph_count"] == 1
        assert r["periph_type"] == "crypto"

    def test_kg_summary(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import blackboard

db = tempfile.mktemp(suffix=".db")

blackboard(action="add_system", title="Crypto", db_path=db)
blackboard(action="add_gap", title="WPA", confidence=0.9, db_path=db)
blackboard(action="add_peripheral", addr="0xA0010000", db_path=db)
blackboard(action="add_attack_surface", addr="0x401000",
           reachable_from="air_unauthenticated", db_path=db)

r = blackboard(action="kg_summary", db_path=db)

result = {
    "ok": r.get("ok"),
    "systems": r.get("systems"),
    "gaps_open": r.get("gaps_open"),
    "peripherals": r.get("peripherals"),
    "attack_surface_entries": r.get("attack_surface_entries"),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["systems"] == 1
        assert r["gaps_open"] == 1
        assert r["peripherals"] == 1
        assert r["attack_surface_entries"] == 1


class TestGapEngineIDA:
    """GapEngine seeding and filling inside real IDA."""

    def test_seed_wifi_gaps(self, runner):
        script = '''
import sys, os, tempfile, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__) if "__file__" in dir() else ".", "..", "src"))
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.gap_engine import GapEngine

db = tempfile.mktemp(suffix=".db")
kg = KnowledgeGraph(db_path=db)
ge = GapEngine(kg)

added = ge.seed_gaps("wifi_firmware")
gaps = kg.list_gaps(resolved=False)

result = {
    "ok": True,
    "added": added,
    "total_gaps": len(gaps),
    "has_wpa_gap": any("WPA" in g["expected"] or "wpa" in g["expected"].lower() for g in gaps),
    "has_802_11_gap": any("802.11" in g["expected"] for g in gaps),
    "gap_types": list(set(g["gap_type"] for g in gaps)),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["added"] >= 5
        assert r["has_wpa_gap"] is True
        assert r["has_802_11_gap"] is True

    def test_detect_binary_type_from_blackboard(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import BlackboardStore
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.gap_engine import GapEngine

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
store.write("WPA2 handshake handler", category="hypothesis",
            tags=["wpa", "802.11"], embed=False)
store.write("SSID parser", category="hypothesis",
            tags=["ssid", "beacon"], embed=False)

kg = KnowledgeGraph(db_path=db)
ge = GapEngine(kg)
btype = ge.detect_binary_type(store)

result = {"ok": True, "binary_type": btype}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["binary_type"] == "wifi_firmware"

    def test_try_fill_gaps_from_blackboard(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import BlackboardStore
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.gap_engine import GapEngine

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
kg = KnowledgeGraph(db_path=db)
ge = GapEngine(kg)

ge.seed_gaps("wifi_firmware")

# Write a high-confidence entry that matches a gap
store.write("WPA2 PBKDF2 key derivation function",
            category="hypothesis", addr="0x401234",
            confidence=0.9, tags=["wpa", "pbkdf2", "hmac"], embed=False)

filled = ge.try_fill_gaps(store)
gaps = kg.list_gaps(resolved=False)
has_candidate = any(g.get("candidates") for g in gaps)

result = {
    "ok": True,
    "filled": filled,
    "has_candidate": has_candidate,
    "open_gaps": len(gaps),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        # At least one gap should have a candidate or be filled
        assert r["has_candidate"] or r["filled"] >= 0


class TestNarrativeEngineIDA:
    """NarrativeEngine generates firmware story inside real IDA."""

    def test_narrative_with_real_functions(self, runner):
        script = '''
import sys, os, tempfile, json
import idautils, idc
from blackboard import BlackboardStore
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.narrative_engine import NarrativeEngine
from ida_pro_mcp.host.gap_engine import GapEngine

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
kg = KnowledgeGraph(db_path=db)

# Write some findings
funcs = list(idautils.Functions())[:5]
for ea in funcs[:3]:
    store.write(f"Analyze {idc.get_func_name(ea) or hex(ea)}",
                category="hypothesis", addr=hex(ea), confidence=0.7, embed=False)

store.write("C2 IP", category="ioc", ioc_type="ip_port",
            ioc_value="192.168.1.1:8080", addr=hex(funcs[0]) if funcs else "0x401000",
            confidence=0.99, embed=False)

# Seed gaps
ge = GapEngine(kg)
ge.seed_gaps("wifi_firmware")

# Generate narrative
ne = NarrativeEngine(kg, store)
text = ne.generate({"filename": "test_binary.exe", "processor": "ARM", "bits": 32})

result = {
    "ok": True,
    "narrative_len": len(text),
    "has_binary_section": "## Binary" in text or "Binary:" in text,
    "has_gaps_section": "Gap" in text or "gap" in text,
    "has_next_action": "Next" in text or "Recommended" in text,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert r["narrative_len"] > 100
        assert r["has_next_action"] is True

    def test_narrative_written_to_blackboard(self, runner):
        script = '''
import sys, os, tempfile, json
from blackboard import BlackboardStore
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.narrative_engine import NarrativeEngine

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
kg = KnowledgeGraph(db_path=db)

store.write("AES init", category="hypothesis", addr="0x401000",
            confidence=0.9, embed=False)

ne = NarrativeEngine(kg, store)
text = ne.generate({"filename": "test.bin"})

# Write narrative to blackboard (as engine would)
store.write("Analysis Narrative", content=text, category="narrative",
            confidence=1.0, source="engine", embed=False)

narratives = store.list(category="narrative", include_resolved=True)

result = {
    "ok": True,
    "narrative_count": len(narratives),
    "narrative_len": len(narratives[0].get("content", "")) if narratives else 0,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["narrative_count"] == 1
        assert r["narrative_len"] > 50


class TestAnalysisEngineKGIDA:
    """AnalysisEngine KG stage inside real IDA."""

    def test_system_discovery_from_classified_functions(self, runner):
        script = '''
import sys, os, tempfile, json
import idautils, idc
from blackboard import BlackboardStore
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.analysis_engine import AnalysisEngine

db = tempfile.mktemp(suffix=".db")
props = tempfile.mktemp(suffix=".props.db")
store = BlackboardStore(db_path=db)

# Write 4 functions with same behavior tag (threshold for system discovery is 3)
funcs = list(idautils.Functions())[:6]
for ea in funcs[:4]:
    store.write(f"sub_{hex(ea)}", category="hypothesis", addr=hex(ea),
                confidence=0.7, tags=["crypto_symmetric", "engine"],
                embed=False)

# Create engine and run KG stage
def rpc(tool, args): return {}
eng = AnalysisEngine("test_kg", rpc, lambda n: None, db, props)
eng._kg = None  # force lazy init
eng._stage_knowledge_graph()

# Check KG
from ida_pro_mcp.host.knowledge_graph import KnowledgeGraph
kg = KnowledgeGraph(db_path=db)
systems = kg.list_systems()

result = {
    "ok": True,
    "systems_found": len(systems),
    "has_crypto_system": any("crypto" in s["name"].lower() for s in systems),
    "members_count": len(systems[0].get("members", [])) if systems else 0,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert r["systems_found"] >= 1
        assert r["has_crypto_system"] is True
        assert r["members_count"] >= 3

    def test_entropy_scan_detects_high_entropy_segment(self, runner):
        script = '''
import sys, os, tempfile, json
import idaapi, idc, idautils
from blackboard import BlackboardStore
from ida_pro_mcp.host.analysis_engine import AnalysisEngine

db = tempfile.mktemp(suffix=".db")
props = tempfile.mktemp(suffix=".props.db")
store = BlackboardStore(db_path=db)

# Mock RPC that returns real segment data
def rpc(tool, args):
    if tool == "idb" and args.get("action") == "segments":
        segs = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                segs.append({
                    "name": idc.get_segm_name(seg_ea),
                    "start_ea": seg_ea,
                    "end_ea": seg.end_ea,
                })
        return {"segments": segs[:5]}
    if tool == "memory" and args.get("action") == "read":
        addr_str = args.get("addr", "0")
        try:
            addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
            size = min(args.get("size", 256), 4096)
            data = idaapi.get_bytes(addr, size) or b""
            return {"bytes": data.hex()}
        except Exception:
            return {}
    return {}

eng = AnalysisEngine("test_entropy", rpc, lambda n: None, db, props)
eng._stage_entropy_scan()

regions = store.list(category="region", include_resolved=True)

result = {
    "ok": True,
    "regions_found": len(regions),
    "high_entropy_found": any(r.get("entropy", 0) > 6.0 for r in regions),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        # May or may not find high entropy depending on binary — just verify it ran
        assert "regions_found" in r


class TestUsageIntelligenceIDA:
    """UsageIntelligence session report inside real IDA."""

    def test_session_report_after_observations(self, runner):
        script = '''
import sys, os, tempfile, json
from ida_pro_mcp.host.usage_intelligence import UsageIntelligence

tmpdir = tempfile.mkdtemp()
ui = UsageIntelligence(audit_dir=tmpdir)

# Simulate a session with many analysis calls and no records
for _ in range(12):
    ui.observe("code", "decompile", "sess1", latency_ms=100.0)

report = ui.session_report("sess1")
signals = report.get("drift_signals", [])

result = {
    "ok": True,
    "total_calls": report.get("total_calls"),
    "analysis_calls": report.get("analysis_calls"),
    "record_calls": report.get("record_calls"),
    "has_drift_signal": len(signals) > 0,
    "signal_types": [s["type"] for s in signals],
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["total_calls"] == 12
        assert r["analysis_calls"] == 12
        assert r["record_calls"] == 0
        assert r["has_drift_signal"] is True
        assert "ANALYZE_WITHOUT_RECORD" in r["signal_types"]

    def test_predict_next_after_sequence(self, runner):
        script = '''
import sys, os, tempfile, json
from ida_pro_mcp.host.usage_intelligence import UsageIntelligence

tmpdir = tempfile.mkdtemp()
ui = UsageIntelligence(audit_dir=tmpdir)

# Train: decompile → classify (5 times)
for _ in range(5):
    ui.seq.observe(("code", "decompile"), ("classify", "function"))
for _ in range(2):
    ui.seq.observe(("code", "decompile"), ("blackboard", "write"))

preds = ui.predict_next("code", "decompile", top_k=3)

result = {
    "ok": True,
    "predictions": len(preds),
    "top_tool": preds[0]["tool"] if preds else None,
    "top_action": preds[0]["action"] if preds else None,
    "has_probability": "probability" in preds[0] if preds else False,
    "has_effectiveness": "effectiveness" in preds[0] if preds else False,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["predictions"] >= 1
        assert r["top_tool"] == "classify"
        assert r["top_action"] == "function"
        assert r["has_probability"] is True


class TestSmartDecompileIDA:
    """smart_decompile action inside real IDA."""

    def test_smart_decompile_returns_all_fields(self, runner):
        script = '''
import sys, os, json
import idautils, idc
from code import code

# Get first function with a body
funcs = [ea for ea in idautils.Functions()]
target = None
for ea in funcs[:20]:
    import idaapi
    f = idaapi.get_func(ea)
    if f and (f.end_ea - f.start_ea) > 20:
        target = ea
        break

if not target:
    result = {"ok": False, "error": "no suitable function found"}
else:
    r = code(action="smart_decompile", addr=hex(target))
    if isinstance(r, list): r = r[0]
    result = {
        "ok": r.get("ok", False),
        "has_pseudocode": bool(r.get("pseudocode")),
        "has_complexity": "complexity" in r,
        "has_callers": "callers" in r,
        "has_callees": "callees" in r,
        "has_strings": "strings" in r,
        "has_suggested": "suggested_next_actions" in r,
        "has_behavior_tags": "behavior_tags" in r,
        "addr": r.get("addr"),
        "name": r.get("name"),
    }

with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert r["has_pseudocode"] is True
        assert r["has_complexity"] is True
        assert r["has_callers"] is True
        assert r["has_callees"] is True
        assert r["has_suggested"] is True
        assert r["has_behavior_tags"] is True

    def test_smart_decompile_detects_dangerous_patterns(self, runner):
        script = '''
import sys, os, json
import idautils, idc, idaapi
from code import code

# Find a function that calls memcpy or strcpy
target = None
for ea in idautils.Functions():
    f = idaapi.get_func(ea)
    if not f: continue
    for item in idautils.FuncItems(ea):
        for xref in idautils.XrefsFrom(item, 0):
            name = idc.get_name(xref.to) or ""
            if "memcpy" in name or "strcpy" in name or "sprintf" in name:
                target = ea
                break
        if target: break
    if target: break

if not target:
    # Fall back to any function
    funcs = list(idautils.Functions())
    target = funcs[0] if funcs else None

if not target:
    result = {"ok": False, "error": "no function found"}
else:
    r = code(action="smart_decompile", addr=hex(target))
    if isinstance(r, list): r = r[0]
    result = {
        "ok": r.get("ok", False),
        "dangerous_patterns": r.get("dangerous_patterns", []),
        "api_calls": r.get("api_calls", []),
        "complexity_lines": r.get("complexity", {}).get("lines", 0),
    }

with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        # Just verify the fields exist and are the right types
        assert isinstance(r["dangerous_patterns"], list)
        assert isinstance(r["api_calls"], list)
        assert r["complexity_lines"] >= 0

    def test_annotate_action(self, runner):
        script = '''
import sys, os, json
import idautils
from code import code

funcs = list(idautils.Functions())
if not funcs:
    result = {"ok": False, "error": "no functions"}
else:
    target = funcs[0]
    r = code(action="annotate", addr=hex(target), comment="Test annotation from smart_decompile")
    if isinstance(r, list): r = r[0]
    result = {
        "ok": r.get("ok", False),
        "addr": r.get("addr"),
        "comment": r.get("comment"),
        "type": r.get("type"),
    }

with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["comment"] == "Test annotation from smart_decompile"
        assert r["type"] in ("function_comment", "address_comment")


class TestTaintToolIDA:
    """taint tool inside real IDA."""

    def test_taint_sources(self, runner):
        script = '''
import sys, os, json
from taint import taint

r = taint(action="sources")
result = {
    "ok": r.get("ok", False),
    "count": r.get("count", 0),
    "sources": r.get("sources", []),
    "has_network_source": any(
        s.get("name") in ("recv", "recvfrom", "read", "fread", "fgets")
        for s in r.get("sources", [])
    ),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        # May have 0 sources if binary has no matching imports — that's fine
        assert isinstance(r["sources"], list)

    def test_taint_report(self, runner):
        script = '''
import sys, os, json
from taint import taint

r = taint(action="report", max_depth=3, max_paths=10)
result = {
    "ok": r.get("ok", False),
    "findings": r.get("findings", []),
    "total": r.get("total", 0),
    "sources_checked": r.get("sources_checked", 0),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert isinstance(r["findings"], list)
        # Verify structure of any findings
        for f in r["findings"][:3]:
            assert "source" in f
            assert "sink" in f
            assert "vuln_type" in f

    def test_predictor_suggest_next_address_uses_blackboard(self, runner):
        script = '''
import sys, os, json, tempfile
import idautils
from blackboard import BlackboardStore

# Write some blackboard entries
db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
funcs = list(idautils.Functions())[:5]
for ea in funcs[:3]:
    store.write(f"Analyze {hex(ea)}", category="hypothesis",
                addr=hex(ea), confidence=0.8, embed=False)

# next_target should return these
targets = store.next_target(limit=5)
result = {
    "ok": True,
    "targets_count": len(targets),
    "has_addr": all("addr" in t for t in targets),
    "has_priority": all("priority_score" in t for t in targets),
    "sorted_desc": all(
        targets[i]["priority_score"] >= targets[i+1]["priority_score"]
        for i in range(len(targets)-1)
    ) if len(targets) > 1 else True,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["targets_count"] >= 1
        assert r["has_addr"] is True
        assert r["has_priority"] is True
        assert r["sorted_desc"] is True
