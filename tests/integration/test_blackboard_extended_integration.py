"""
IDA integration tests for extended blackboard features.
Requires licensed IDA Pro configured via IDA_DIR or IDADIR.
"""
import pytest

from tests._isolated_repo_loader import load_test_module

_integration_conftest = load_test_module(
    "integration/conftest.py",
    module_name="_integration_conftest2",
)
IDARunner = _integration_conftest.IDARunner
ida_is_available = _integration_conftest.ida_is_available

pytestmark = pytest.mark.skipif(
    not ida_is_available(), reason="IDA Pro not available"
)


@pytest.fixture(scope="module")
def runner():
    if not ida_is_available():
        pytest.skip("IDA Pro not available")
    return IDARunner()


class TestBlackboardExtendedIDA:
    """End-to-end tests for extended blackboard schema inside real IDA."""

    def test_write_and_read_region(self, runner):
        script = '''
from blackboard import blackboard, BlackboardStore
import tempfile, os

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)

eid = store.write("TCP/IP stack", category="region",
                  addr="0x80400000", addr_end="0x80410000", confidence=0.85)
e = store.read(eid)
result = {
    "ok": True,
    "eid": eid,
    "category": e["category"],
    "addr": e["addr"],
    "addr_end": e["addr_end"],
    "confidence": e["confidence"],
}
with open(RESULT_PATH, "w") as f:
    import json; json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["category"] == "region"
        assert r["addr_end"] == "0x80410000"

    def test_write_ioc(self, runner):
        script = '''
from blackboard import BlackboardStore
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)
eid = store.write("C2 IP", category="ioc",
                  ioc_type="ip_port", ioc_value="192.168.1.1:8080",
                  addr="0x401234", confidence=0.99)
entries = store.list(ioc_type="ip_port")
result = {"ok": True, "count": len(entries),
          "ioc_value": entries[0]["ioc_value"] if entries else None}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["count"] == 1
        assert r["ioc_value"] == "192.168.1.1:8080"

    def test_contradict_and_resolve(self, runner):
        script = '''
from blackboard import BlackboardStore
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)

eid1 = store.write("Hypothesis A", category="hypothesis", addr="0x401000", confidence=0.8)
eid2 = store.write("Dead end", category="dead_end", addr="0x402000", confidence=0.5)

store.contradict(eid1, "disproved by decompilation")
store.mark_resolved(eid2)

e1 = store.read(eid1)
e2 = store.read(eid2)

result = {
    "ok": True,
    "contradicted": e1["contradicted"],
    "contradiction_reason": e1["contradiction_reason"],
    "resolved": e2["resolved"],
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["contradicted"] == 1
        assert "disproved" in r["contradiction_reason"]
        assert r["resolved"] == 1

    def test_next_target_with_real_functions(self, runner):
        script = '''
import idautils, idc
from blackboard import BlackboardStore
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)

# Write entries for real function addresses
funcs = list(idautils.Functions())[:5]
for ea in funcs:
    name = idc.get_func_name(ea) or hex(ea)
    store.write(f"Analyze {name}", category="hypothesis",
                addr=hex(ea), confidence=0.7)

# Mark first one as resolved
if funcs:
    entries = store.list(addr=hex(funcs[0]))
    if entries:
        store.mark_resolved(entries[0]["id"])

targets = store.next_target(limit=10)
result = {
    "ok": True,
    "total_written": len(funcs),
    "targets_count": len(targets),
    "resolved_excluded": not any(t["addr"] == hex(funcs[0]) for t in targets) if funcs else True,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert r["targets_count"] >= 1
        assert r["resolved_excluded"] is True

    def test_dependency_priority(self, runner):
        script = '''
from blackboard import BlackboardStore
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)

# Blocked entry (depends on unresolved)
store.write("Blocked analysis", category="dependency",
            addr="0x401000", depends_on="0x400000", confidence=0.9)
# Free entry
store.write("Free analysis", category="hypothesis",
            addr="0x402000", confidence=0.6)

targets = store.next_target(limit=5)
scores = {t["addr"]: t["priority_score"] for t in targets}

result = {
    "ok": True,
    "blocked_score": scores.get("0x401000", 0),
    "free_score": scores.get("0x402000", 0),
    "free_ranks_higher": scores.get("0x402000", 0) > scores.get("0x401000", 0),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["free_ranks_higher"] is True

    def test_crawler_accept_reject(self, runner):
        script = '''
from blackboard import _BackgroundCrawler, BlackboardStore
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")
crawler = _BackgroundCrawler(db_path=db)

# Inject proposals manually
crawler._pending["p1"] = {
    "proposal_id": "p1", "addr": "0x401000",
    "title": "Discovered: sub_401000 [crypto_symmetric]",
    "content": "test", "category": "crypto_symmetric",
    "tags": ["crawler"], "confidence": 0.65,
}
crawler._pending["p2"] = {
    "proposal_id": "p2", "addr": "0x402000",
    "title": "Discovered: sub_402000 [network_http]",
    "content": "test", "category": "network_http",
    "tags": ["crawler"], "confidence": 0.7,
}

# Accept p1, reject p2
eid = crawler.accept("p1")
crawler.reject("p2")

store = BlackboardStore(db_path=db)
entries = store.list()

result = {
    "ok": True,
    "accepted_written": eid is not None,
    "total_entries": len(entries),
    "p1_pending": "p1" in crawler._pending,
    "p2_pending": "p2" in crawler._pending,
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["accepted_written"] is True
        assert r["total_entries"] == 1  # only p1 written
        assert r["p1_pending"] is False
        assert r["p2_pending"] is False

    def test_blackboard_mcp_tool_actions(self, runner):
        """Test all new MCP tool actions via the blackboard() function."""
        script = '''
from blackboard import blackboard
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")

# Write a region
r1 = blackboard(action="write", title="WiFi driver",
                category="region", addr="0x80410000", addr_end="0x80420000",
                confidence=0.8, db_path=db)

# Write an IOC
r2 = blackboard(action="write", title="Hardcoded key",
                category="ioc", ioc_type="crypto_key", ioc_value="deadbeef",
                addr="0x80412340", confidence=0.99, db_path=db)

# Write a hypothesis
r3 = blackboard(action="write", title="This is AES",
                category="hypothesis", addr="0x80415000",
                confidence=0.85, db_path=db)

# Contradict it
r4 = blackboard(action="contradict", entry_id=r3["entry_id"],
                reason="No AES constants found", db_path=db)

# Get next target
r5 = blackboard(action="next_target", db_path=db)

# Stats
r6 = blackboard(action="stats", db_path=db)

result = {
    "ok": True,
    "write_region": r1.get("ok"),
    "write_ioc": r2.get("ok"),
    "contradict": r4.get("ok"),
    "next_target_count": len(r5.get("targets", [])),
    "stats_total": r6.get("total_entries"),
    "stats_contradicted": r6.get("contradicted"),
    "stats_iocs": r6.get("iocs", {}),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=60)
        assert r.get("ok") is True
        assert r["write_region"] is True
        assert r["write_ioc"] is True
        assert r["contradict"] is True
        assert r["next_target_count"] >= 1
        assert r["stats_total"] == 3
        assert r["stats_contradicted"] == 1
        assert "crypto_key" in r["stats_iocs"]

    def test_crawler_starts_and_has_status(self, runner):
        """Crawler can be started and queried for status inside IDA."""
        script = '''
from blackboard import blackboard
import tempfile, os, json

db = tempfile.mktemp(suffix=".db")

r_start = blackboard(action="start_crawler", db_path=db)
r_status = blackboard(action="crawler_status", db_path=db)
r_stop = blackboard(action="stop_crawler", db_path=db)

result = {
    "ok": True,
    "started": r_start.get("ok"),
    "was_running": r_status.get("running"),
    "stopped": r_stop.get("ok"),
}
with open(RESULT_PATH, "w") as f:
    json.dump(result, f); f.flush(); os.fsync(f.fileno())
'''
        r = runner.run_script(script, timeout=30)
        assert r.get("ok") is True
        assert r["started"] is True
        assert r["stopped"] is True
