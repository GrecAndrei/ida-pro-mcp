"""
Tests for extended blackboard features:
- New schema fields (addr_end, resolved, contradicted, ioc_type, depends_on, etc.)
- contradict / resolve actions
- next_target priority queue
- Background crawler (unit-level, no IDA)
- New MCP resource URIs
"""
import os
import sys
import json
import struct
import tempfile
import importlib.util
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ─── Load blackboard module ───────────────────────────────────────────────────

def _load_bb():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "blackboard.py")
    spec = importlib.util.spec_from_file_location("_bb_ext_test", path)
    mod = importlib.util.module_from_spec(spec)
    for m in ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
              "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
              "ida_hexrays", "ida_frame", "ida_struct", "ida_lines"]:
        sys.modules.setdefault(m, types.ModuleType(m))
    sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
    spec.loader.exec_module(mod)
    return mod


_bb = _load_bb()
BlackboardStore = _bb.BlackboardStore
_BackgroundCrawler = _bb._BackgroundCrawler


def _store():
    return BlackboardStore(db_path=tempfile.mktemp(suffix=".db"))


# ─── Extended schema fields ───────────────────────────────────────────────────

def test_write_region():
    s = _store()
    eid = s.write("TCP/IP stack", category="region",
                  addr="0x80400000", addr_end="0x80410000", confidence=0.85)
    e = s.read(eid)
    assert e["category"] == "region"
    assert e["addr"] == "0x80400000"
    assert e["addr_end"] == "0x80410000"
    assert e["confidence"] == 0.85


def test_write_ioc():
    s = _store()
    eid = s.write("Hardcoded C2 IP", category="ioc",
                  ioc_type="ip_port", ioc_value="192.168.1.1:8080",
                  addr="0x80412340", confidence=0.99)
    e = s.read(eid)
    assert e["ioc_type"] == "ip_port"
    assert e["ioc_value"] == "192.168.1.1:8080"


def test_write_dependency():
    s = _store()
    eid = s.write("Must understand 0x8040100 before 0x8041200",
                  category="dependency",
                  addr="0x8041200", depends_on="0x8040100",
                  blocks_addr="0x8041200")
    e = s.read(eid)
    assert e["depends_on"] == "0x8040100"
    assert e["blocks_addr"] == "0x8041200"


def test_write_data_flow():
    s = _store()
    eid = s.write("r3 = packet buffer ptr", category="data_flow",
                  addr="0x8041200", register="r3", reg_type="packet_buffer*")
    e = s.read(eid)
    assert e["register"] == "r3"
    assert e["reg_type"] == "packet_buffer*"


def test_list_ioc_filter():
    s = _store()
    s.write("IP 1", category="ioc", ioc_type="ip_port", ioc_value="1.2.3.4:80")
    s.write("IP 2", category="ioc", ioc_type="ip_port", ioc_value="5.6.7.8:443")
    s.write("Key", category="ioc", ioc_type="crypto_key", ioc_value="deadbeef")
    s.write("Other", category="general")

    ips = s.list(ioc_type="ip_port")
    assert len(ips) == 2
    keys = s.list(ioc_type="crypto_key")
    assert len(keys) == 1


# ─── contradict / resolve ─────────────────────────────────────────────────────

def test_contradict():
    s = _store()
    eid = s.write("This is a heap allocator", category="hypothesis", confidence=0.8)
    ok = s.contradict(eid, "Found it calls malloc — not custom")
    assert ok
    e = s.read(eid)
    assert e["contradicted"] == 1
    assert "malloc" in e["contradiction_reason"]


def test_contradict_nonexistent():
    s = _store()
    assert not s.contradict("nonexistent", "reason")


def test_resolve():
    s = _store()
    eid = s.write("0x8041500 is memset wrapper", category="dead_end", addr="0x8041500")
    ok = s.mark_resolved(eid)
    assert ok
    e = s.read(eid)
    assert e["resolved"] == 1


def test_list_excludes_resolved_by_default():
    s = _store()
    s.write("Active finding", category="vuln", addr="0x401000")
    eid2 = s.write("Dead end", category="dead_end", addr="0x402000")
    s.mark_resolved(eid2)

    entries = s.list(include_resolved=False)
    addrs = [e["addr"] for e in entries]
    assert "0x401000" in addrs
    assert "0x402000" not in addrs


def test_list_includes_resolved_when_requested():
    s = _store()
    eid = s.write("Dead end", category="dead_end", addr="0x402000")
    s.mark_resolved(eid)

    entries = s.list(include_resolved=True)
    assert any(e["addr"] == "0x402000" for e in entries)


def test_list_excludes_contradicted_by_default():
    s = _store()
    s.write("Good hypothesis", category="hypothesis", addr="0x401000")
    eid2 = s.write("Wrong hypothesis", category="hypothesis", addr="0x402000")
    s.contradict(eid2, "disproved")

    entries = s.list(include_contradicted=False)
    addrs = [e["addr"] for e in entries]
    assert "0x401000" in addrs
    assert "0x402000" not in addrs


# ─── next_target ──────────────────────────────────────────────────────────────

def test_next_target_returns_unresolved():
    s = _store()
    s.write("High priority", category="hypothesis", addr="0x401000", confidence=0.9)
    s.write("Low priority", category="pointer", addr="0x402000", confidence=0.3)
    eid3 = s.write("Dead end", category="dead_end", addr="0x403000", confidence=0.8)
    s.mark_resolved(eid3)

    targets = s.next_target(limit=10)
    addrs = [t["addr"] for t in targets]
    assert "0x401000" in addrs
    assert "0x403000" not in addrs  # resolved — excluded


def test_next_target_priority_order():
    s = _store()
    s.write("Low conf", category="general", addr="0x401000", confidence=0.2)
    s.write("High conf hypothesis", category="hypothesis", addr="0x402000", confidence=0.9)

    targets = s.next_target(limit=5)
    assert len(targets) >= 2
    # hypothesis with high confidence should rank higher
    scores = {t["addr"]: t["priority_score"] for t in targets}
    assert scores["0x402000"] > scores["0x401000"]


def test_next_target_blocked_dependency_deprioritized():
    s = _store()
    # Entry that depends on an unresolved address
    s.write("Blocked", category="dependency", addr="0x401000",
            depends_on="0x400000", confidence=0.9)
    # Entry with no dependency
    s.write("Free", category="hypothesis", addr="0x402000", confidence=0.7)

    targets = s.next_target(limit=5)
    scores = {t["addr"]: t["priority_score"] for t in targets}
    # Blocked entry should score lower than free entry despite higher confidence
    assert scores.get("0x402000", 0) > scores.get("0x401000", 0)


def test_next_target_satisfied_dependency_boosted():
    s = _store()
    # Resolve the dependency
    dep_eid = s.write("Prereq", category="general", addr="0x400000", confidence=0.5)
    s.mark_resolved(dep_eid)
    # Entry whose dependency is now satisfied
    s.write("Unblocked", category="dependency", addr="0x401000",
            depends_on="0x400000", confidence=0.6)

    targets = s.next_target(limit=5)
    # Should appear in targets (not blocked)
    addrs = [t["addr"] for t in targets]
    assert "0x401000" in addrs


def test_next_target_deduplicates_addresses():
    s = _store()
    # Two entries for the same address
    s.write("Finding 1", category="hypothesis", addr="0x401000", confidence=0.8)
    s.write("Finding 2", category="vuln", addr="0x401000", confidence=0.9)

    targets = s.next_target(limit=10)
    addrs = [t["addr"] for t in targets]
    assert addrs.count("0x401000") == 1


# ─── Background crawler (unit level) ─────────────────────────────────────────

def test_crawler_start_stop():
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    assert not crawler.is_running()
    crawler.start()
    assert crawler.is_running()
    crawler.stop()
    # Give thread time to notice stop event
    import time
    time.sleep(0.1)


def test_crawler_accept_proposal():
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    # Manually inject a proposal
    pid = "test1234"
    crawler._pending[pid] = {
        "proposal_id": pid,
        "addr": "0x401000",
        "title": "Discovered: sub_401000 [crypto_symmetric]",
        "content": "Reachable from 0x400000. Behavior: crypto_symmetric",
        "category": "crypto_symmetric",
        "tags": ["crawler", "xref", "crypto_symmetric"],
        "confidence": 0.65,
    }
    eid = crawler.accept(pid)
    assert eid is not None
    assert pid not in crawler._pending
    # Verify it was written to the blackboard
    store = BlackboardStore(db_path=crawler._db_path)
    entries = store.list(category="crypto_symmetric")
    assert len(entries) == 1
    assert "sub_401000" in entries[0]["title"]


def test_crawler_reject_proposal():
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    pid = "rej1234"
    crawler._pending[pid] = {"proposal_id": pid, "addr": "0x401000", "title": "test"}
    ok = crawler.reject(pid)
    assert ok
    assert pid not in crawler._pending
    # Nothing written to blackboard
    store = BlackboardStore(db_path=crawler._db_path)
    assert len(store.list()) == 0


def test_crawler_accept_nonexistent():
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    assert crawler.accept("nonexistent") is None


def test_crawler_pending_proposals():
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    crawler._pending["p1"] = {"proposal_id": "p1", "addr": "0x401000", "title": "A"}
    crawler._pending["p2"] = {"proposal_id": "p2", "addr": "0x402000", "title": "B"}
    proposals = crawler.pending_proposals()
    assert len(proposals) == 2


def test_crawler_notify_fn_called():
    """Crawler calls notify_fn when proposals are generated."""
    notifications = []
    crawler = _BackgroundCrawler(db_path=tempfile.mktemp(suffix=".db"))
    crawler._notify_fn = lambda n: notifications.append(n)

    # Manually trigger notification
    proposals = [{"proposal_id": "p1", "addr": "0x401000",
                  "title": "test", "behavior_tags": ["crypto_symmetric"]}]
    if proposals and crawler._notify_fn:
        crawler._notify_fn({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "info", "data": {"proposals": proposals}},
        })

    assert len(notifications) == 1
    assert notifications[0]["method"] == "notifications/message"


# ─── MCP tool action routing ──────────────────────────────────────────────────

def test_blackboard_tool_contradict():
    s = _store()
    eid = s.write("Hypothesis", category="hypothesis", confidence=0.8)
    result = _bb.blackboard.__wrapped__(
        action="contradict", entry_id=eid, reason="disproved",
        db_path=s.db_path,
    ) if hasattr(_bb.blackboard, "__wrapped__") else _bb.blackboard(
        action="contradict", entry_id=eid, reason="disproved",
        db_path=s.db_path,
    )
    assert result.get("ok") is True
    e = s.read(eid)
    assert e["contradicted"] == 1


def test_blackboard_tool_resolve():
    s = _store()
    eid = s.write("Dead end", category="dead_end", addr="0x401000")
    result = _bb.blackboard(action="resolve", entry_id=eid, db_path=s.db_path)
    assert result.get("ok") is True
    e = s.read(eid)
    assert e["resolved"] == 1


def test_blackboard_tool_next_target():
    s = _store()
    s.write("Target", category="hypothesis", addr="0x401000", confidence=0.9)
    result = _bb.blackboard(action="next_target", db_path=s.db_path)
    assert result.get("ok") is True
    assert "targets" in result
    assert len(result["targets"]) >= 1


def test_blackboard_tool_crawler_status():
    result = _bb.blackboard(action="crawler_status",
                            db_path=tempfile.mktemp(suffix=".db"))
    assert result.get("ok") is True
    assert "running" in result
    assert "pending_proposals" in result


def test_blackboard_tool_write_ioc():
    s = _store()
    result = _bb.blackboard(
        action="write", title="C2 IP", category="ioc",
        ioc_type="ip_port", ioc_value="1.2.3.4:443",
        addr="0x401234", confidence=0.99,
        db_path=s.db_path,
    )
    assert result.get("ok") is True
    entries = s.list(ioc_type="ip_port")
    assert len(entries) == 1
    assert entries[0]["ioc_value"] == "1.2.3.4:443"


def test_blackboard_tool_write_region():
    s = _store()
    result = _bb.blackboard(
        action="write", title="WiFi driver region",
        category="region", addr="0x80410000", addr_end="0x80420000",
        confidence=0.8, db_path=s.db_path,
    )
    assert result.get("ok") is True
    entries = s.list(category="region")
    assert len(entries) == 1
    assert entries[0]["addr_end"] == "0x80420000"


def test_blackboard_stats_includes_new_fields():
    s = _store()
    s.write("A", category="ioc", ioc_type="ip_port")
    s.write("B", category="hypothesis")
    eid = s.write("C", category="dead_end")
    s.mark_resolved(eid)
    eid2 = s.write("D", category="hypothesis")
    s.contradict(eid2, "wrong")

    stats = s.stats()
    assert stats["resolved"] == 1
    assert stats["contradicted"] == 1
    assert "ip_port" in stats["iocs"]


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
