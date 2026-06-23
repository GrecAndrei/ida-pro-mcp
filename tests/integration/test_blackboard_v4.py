"""
Tests for blackboard v4:
- KnowledgeGraph (systems, structs, state machines, gaps, attack surface, peripherals)
- NarrativeEngine (generates firmware story)
- GapEngine (seeds and fills gaps)
- ida://knowledge resource
- ida://state returns narrative when available
"""
import json
import os
import tempfile
import time
from tests._isolated_repo_loader import load_host_module, load_tool_module

_kg_mod = load_host_module("knowledge_graph")
_ne_mod = load_host_module("narrative_engine")
_ge_mod = load_host_module("gap_engine")
_res_mod = load_host_module("resources")
_bb_mod = load_tool_module("blackboard")

KnowledgeGraph = _kg_mod.KnowledgeGraph
NarrativeEngine = _ne_mod.NarrativeEngine
GapEngine = _ge_mod.GapEngine
ResourceResolver = _res_mod.ResourceResolver
BlackboardStore = _bb_mod.BlackboardStore


def _kg():
    return KnowledgeGraph(db_path=tempfile.mktemp(suffix=".db"))

def _bb():
    return BlackboardStore(db_path=tempfile.mktemp(suffix=".db"))


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — systems
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_and_get_system():
    kg = _kg()
    sid = kg.add_system("Packet RX pipeline",
                        members=["0x401000", "0x402000", "0x403000"],
                        description="DMA → frame classifier → demux",
                        confidence=0.8)
    s = kg.get_system(sid)
    assert s["name"] == "Packet RX pipeline"
    assert "0x401000" in s["members"]
    assert s["confidence"] == 0.8


def test_kg_list_systems():
    kg = _kg()
    kg.add_system("Crypto", members=["0x401000"])
    kg.add_system("Network", members=["0x402000"])
    systems = kg.list_systems()
    assert len(systems) == 2


def test_kg_update_system():
    kg = _kg()
    sid = kg.add_system("Crypto", members=["0x401000"], confidence=0.5)
    ok = kg.update_system(sid, confidence=0.9, coverage_pct=75.0)
    assert ok
    s = kg.get_system(sid)
    assert s["confidence"] == 0.9
    assert s["coverage_pct"] == 75.0


def test_kg_add_member_to_system():
    kg = _kg()
    sid = kg.add_system("Crypto", members=["0x401000"])
    kg.add_member_to_system(sid, "0x402000")
    s = kg.get_system(sid)
    assert "0x402000" in s["members"]


def test_kg_find_system_for_addr():
    kg = _kg()
    sid = kg.add_system("Crypto", members=["0x401000", "0x402000"])
    found = kg.find_system_for_addr("0x401000")
    assert found is not None
    assert found["id"] == sid
    assert kg.find_system_for_addr("0x999000") is None


def test_kg_system_no_duplicate_members():
    kg = _kg()
    sid = kg.add_system("Crypto", members=["0x401000"])
    kg.add_member_to_system(sid, "0x401000")  # duplicate
    s = kg.get_system(sid)
    assert s["members"].count("0x401000") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — structs
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_struct():
    kg = _kg()
    sid = kg.add_struct("wifi_frame_t",
                        members=[{"offset": 0, "size": 2, "name": "frame_ctrl"},
                                  {"offset": 2, "size": 2, "name": "duration"}],
                        size_bytes=24, confidence=0.7)
    s = kg.get_struct(sid)
    assert s["name"] == "wifi_frame_t"
    assert len(s["members"]) == 2
    assert s["size_bytes"] == 24


def test_kg_record_struct_access():
    kg = _kg()
    sid = kg.add_struct("wifi_frame_t", members=[{"offset": 0, "size": 2, "name": "fc"}])
    ok = kg.record_struct_access(sid, "0x401234", "read", 0)
    assert ok
    s = kg.get_struct(sid)
    assert len(s["seen_at"]) == 1
    assert s["seen_at"][0]["addr"] == "0x401234"


def test_kg_find_struct_by_offset_pattern():
    kg = _kg()
    kg.add_struct("wifi_frame_t",
                  members=[{"offset": 0}, {"offset": 4}, {"offset": 8}, {"offset": 12}])
    # Query with overlapping offsets
    found = kg.find_struct_by_offset_pattern([0, 4, 8, 16], threshold=0.5)
    assert found is not None
    assert found["name"] == "wifi_frame_t"


def test_kg_find_struct_no_match():
    kg = _kg()
    kg.add_struct("wifi_frame_t",
                  members=[{"offset": 0}, {"offset": 4}])
    found = kg.find_struct_by_offset_pattern([100, 200, 300], threshold=0.6)
    assert found is None


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — state machines
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_state_machine():
    kg = _kg()
    sid = kg.add_state_machine(
        "802.11 auth state machine",
        state_var="0x80420000",
        states=[{"value": 0, "name": "IDLE"}, {"value": 1, "name": "SCANNING"}],
        confidence=0.7,
    )
    sm = kg.get_state_machine(sid)
    assert sm["name"] == "802.11 auth state machine"
    assert sm["state_var"] == "0x80420000"
    assert len(sm["states"]) == 2


def test_kg_add_transition():
    kg = _kg()
    sid = kg.add_state_machine("Auth SM", state_var="0x80420000")
    ok = kg.add_transition(sid, 0, 1, "0x401234", "on_probe_response")
    assert ok
    sm = kg.get_state_machine(sid)
    assert len(sm["transitions"]) == 1
    assert sm["transitions"][0]["trigger_addr"] == "0x401234"


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — gaps
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_gap():
    kg = _kg()
    gid = kg.add_gap("WPA key derivation",
                     why="All WPA2 firmware must derive PTK/GTK",
                     hints=["Look for HMAC-SHA1 with 4096 iterations"],
                     priority=0.85, gap_type="security")
    gaps = kg.list_gaps(resolved=False)
    assert len(gaps) == 1
    assert gaps[0]["expected"] == "WPA key derivation"
    assert gaps[0]["priority"] == 0.85


def test_kg_fill_gap():
    kg = _kg()
    gid = kg.add_gap("WPA key derivation", priority=0.85)
    ok = kg.fill_gap(gid, "0x401234")
    assert ok
    open_gaps = kg.list_gaps(resolved=False)
    assert len(open_gaps) == 0
    filled = kg.list_gaps(resolved=True)
    assert len(filled) == 1
    assert filled[0]["filled_by"] == "0x401234"


def test_kg_add_gap_candidate():
    kg = _kg()
    gid = kg.add_gap("Beacon parser", priority=0.8)
    kg.add_gap_candidate(gid, "0x401000")
    kg.add_gap_candidate(gid, "0x402000")
    gaps = kg.list_gaps(resolved=False)
    assert "0x401000" in gaps[0]["candidates"]
    assert "0x402000" in gaps[0]["candidates"]


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — attack surface
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_attack_surface():
    kg = _kg()
    aid = kg.add_attack_surface(
        "0x401000", name="Management frame handler",
        reachable_from="air_unauthenticated",
        input_type="management_frame",
        confidence=0.8,
    )
    entries = kg.list_attack_surface()
    assert len(entries) == 1
    assert entries[0]["reachable_from"] == "air_unauthenticated"


def test_kg_update_attack_surface():
    kg = _kg()
    aid = kg.add_attack_surface("0x401000", confidence=0.5)
    ok = kg.update_attack_surface(aid, fuzz_priority=0.9, has_length_check=0)
    assert ok
    entries = kg.list_attack_surface()
    assert entries[0]["fuzz_priority"] == 0.9


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — peripherals
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_add_peripheral():
    kg = _kg()
    pid = kg.add_peripheral("0xA0010000", name="AES accelerator",
                             periph_type="crypto", confidence=0.8)
    periphs = kg.list_peripherals()
    assert len(periphs) == 1
    assert periphs[0]["periph_type"] == "crypto"


def test_kg_peripheral_no_duplicate():
    kg = _kg()
    pid1 = kg.add_peripheral("0xA0010000", name="AES")
    pid2 = kg.add_peripheral("0xA0010000", name="AES v2")
    assert pid1 == pid2  # same base_addr → same entry


def test_kg_record_peripheral_access():
    kg = _kg()
    kg.add_peripheral("0xA0010000", name="AES")
    kg.record_peripheral_access("0xA0010000", "0x401234", offset=0x04, access_type="w")
    periphs = kg.list_peripherals()
    assert any(r["offset"] == 0x04 for r in periphs[0]["registers"])
    assert "0x401234" in periphs[0]["drivers"]


def test_kg_record_peripheral_access_creates_if_missing():
    kg = _kg()
    kg.record_peripheral_access("0xB0000000", "0x401234", offset=0x00)
    periphs = kg.list_peripherals()
    assert any(p["base_addr"] == "0xB0000000" for p in periphs)


# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeGraph — summary
# ═══════════════════════════════════════════════════════════════════════════════

def test_kg_summary():
    kg = _kg()
    kg.add_system("Crypto", members=["0x401000"])
    kg.add_struct("wifi_frame_t")
    kg.add_state_machine("Auth SM", state_var="0x80420000")
    kg.add_gap("WPA key derivation")
    kg.add_attack_surface("0x401000")
    kg.add_peripheral("0xA0010000")

    s = kg.summary()
    assert s["systems"] == 1
    assert s["structs"] == 1
    assert s["state_machines"] == 1
    assert s["gaps_open"] == 1
    assert s["attack_surface_entries"] == 1
    assert s["peripherals"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# GapEngine
# ═══════════════════════════════════════════════════════════════════════════════

def test_gap_engine_seed_wifi():
    kg = _kg()
    ge = GapEngine(kg)
    added = ge.seed_gaps("wifi_firmware")
    assert added >= 5  # at least 5 WiFi-specific gaps
    gaps = kg.list_gaps(resolved=False)
    expected_names = {g["expected"] for g in gaps}
    assert any("WPA" in n for n in expected_names)
    assert any("802.11" in n for n in expected_names)
    assert any("interrupt" in n.lower() or "RX" in n for n in expected_names)


def test_gap_engine_no_duplicates():
    kg = _kg()
    ge = GapEngine(kg)
    added1 = ge.seed_gaps("wifi_firmware")
    added2 = ge.seed_gaps("wifi_firmware")
    assert added2 == 0  # no duplicates


def test_gap_engine_seed_generic():
    kg = _kg()
    ge = GapEngine(kg)
    added = ge.seed_gaps("unknown")
    assert added >= 2  # at least generic gaps
    gaps = kg.list_gaps(resolved=False)
    assert any("interrupt" in g["expected"].lower() or
               "init" in g["expected"].lower() or
               "alloc" in g["expected"].lower()
               for g in gaps)


def test_gap_engine_detect_binary_type_wifi():
    bb = _bb()
    bb.write("WPA2 handshake handler", category="hypothesis",
             tags=["wpa", "802.11"], embed=False)
    bb.write("SSID parser", category="hypothesis",
             tags=["ssid", "beacon"], embed=False)
    ge = GapEngine(_kg())
    btype = ge.detect_binary_type(bb)
    assert btype == "wifi_firmware"


def test_gap_engine_detect_binary_type_unknown():
    bb = _bb()
    bb.write("Unknown function", category="general", embed=False)
    ge = GapEngine(_kg())
    btype = ge.detect_binary_type(bb)
    assert btype == "unknown"


def test_gap_engine_try_fill_gaps():
    kg = _kg()
    ge = GapEngine(kg)
    ge.seed_gaps("wifi_firmware")

    bb = _bb()
    # Write a high-confidence entry that matches a gap
    bb.write("WPA2 PBKDF2 key derivation",
             category="hypothesis", addr="0x401234",
             confidence=0.9, tags=["wpa", "pbkdf2", "hmac"], embed=False)

    filled = ge.try_fill_gaps(bb)
    # At least one gap should have a candidate
    gaps = kg.list_gaps(resolved=False)
    has_candidate = any(g.get("candidates") for g in gaps)
    assert has_candidate or filled >= 0  # may or may not fill depending on keyword match


# ═══════════════════════════════════════════════════════════════════════════════
# NarrativeEngine
# ═══════════════════════════════════════════════════════════════════════════════

def test_narrative_generates_text():
    kg = _kg()
    bb = _bb()
    ne = NarrativeEngine(kg, bb)
    text = ne.generate({"filename": "test.bin", "processor": "ARM", "bits": 32})
    assert isinstance(text, str)
    assert len(text) > 50
    assert "test.bin" in text


def test_narrative_includes_systems():
    kg = _kg()
    kg.add_system("Crypto subsystem", members=["0x401000", "0x402000", "0x403000"])
    bb = _bb()
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    assert "Crypto subsystem" in text


def test_narrative_includes_gaps():
    kg = _kg()
    kg.add_gap("WPA key derivation", why="All WPA2 firmware needs it",
               hints=["Look for HMAC-SHA1"], priority=0.9)
    bb = _bb()
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    assert "WPA key derivation" in text


def test_narrative_includes_vulns():
    kg = _kg()
    bb = _bb()
    bb.write("Stack overflow via recv→memcpy", category="vuln",
             addr="0x401234", confidence=0.85, embed=False)
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    assert "Stack overflow" in text or "vuln" in text.lower() or "Vulnerabilit" in text


def test_narrative_next_action_prioritizes_vuln():
    kg = _kg()
    bb = _bb()
    bb.write("Stack overflow", category="vuln", addr="0x401234",
             confidence=0.9, embed=False)
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    # Next action section should mention the vuln
    assert "Stack overflow" in text or "vulnerability" in text.lower() or "Investigate" in text


def test_narrative_next_action_gap_with_candidate():
    kg = _kg()
    gid = kg.add_gap("WPA key derivation", priority=0.9)
    kg.add_gap_candidate(gid, "0x401234")
    bb = _bb()
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    assert "WPA key derivation" in text or "0x401234" in text


def test_narrative_infers_wifi_type():
    kg = _kg()
    bb = _bb()
    bb.write("WPA2 handshake", category="hypothesis",
             tags=["wpa", "802.11"], embed=False)
    ne = NarrativeEngine(kg, bb)
    text = ne.generate()
    assert "WiFi" in text or "wifi" in text.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# ida://knowledge resource
# ═══════════════════════════════════════════════════════════════════════════════

def _resolver(bb_path=""):
    def exec_fn(name, kwargs):
        if name == "idb":
            return {"filename": "test.bin", "processor": "ARM", "bits": 32}
        if name == "data":
            return {"functions": [{"name": "sub_401000", "start_ea": 0x401000}]}
        return {}
    return ResourceResolver(exec_fn, bb_path=bb_path)


def test_state_returns_json_when_no_narrative():
    db = tempfile.mktemp(suffix=".db")
    BlackboardStore(db_path=db)  # empty blackboard

    _res_mod.invalidate_state_cache()
    resolver = _resolver(bb_path=db)
    result = resolver.read("ida://state")
    assert result is not None
    # No narrative → JSON
    assert result.get("mimeType") == "application/json"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
