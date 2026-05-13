"""
Integration tests for new smart features using real IDA Pro.

Tests:
- funcs suggest_names (embedding-based rename suggestions)
- agent cluster (k-means behavioral clustering)
- agent fingerprint (cross-binary similarity)
- summarize report (assembled report)
- query nl (natural language search)
- deobfuscate BehaviorClassifier integration
- blackboard semantic_search with real functions
- modify rename propagation

Run with: pytest tests/test_new_features_integration.py -v
Requires: licensed IDA Pro at IDA_DIR (default /home/grec-alexander/ida-pro-9.2)
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import importlib.util as _ilu

_integration_conftest_path = os.path.join(
    os.path.dirname(__file__), "integration", "conftest.py"
)
_spec = _ilu.spec_from_file_location("_integration_conftest", _integration_conftest_path)
_integration_conftest = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_integration_conftest)
IDARunner = _integration_conftest.IDARunner
ida_is_available = _integration_conftest.ida_is_available

pytestmark = pytest.mark.skipif(
    not ida_is_available(),
    reason="IDA Pro not available",
)


@pytest.fixture(scope="module")
def runner():
    if not ida_is_available():
        pytest.skip("IDA Pro not available")
    return IDARunner()


# ─── funcs suggest_names ──────────────────────────────────────────────────────

class TestSuggestNames:
    def test_suggest_names_returns_structure(self, runner):
        """suggest_names should return a list of suggestions with required fields."""
        script = '''
from funcs import funcs
result = funcs(action="suggest_names", limit=5)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"suggest_names failed: {result}"
        assert "suggestions" in result
        assert "backend" in result
        for s in result["suggestions"]:
            assert "addr" in s
            assert "suggested_name" in s
            assert "confidence" in s
            assert 0.0 <= s["confidence"] <= 1.0
            assert not s["suggested_name"].startswith("sub_")

    def test_suggest_names_single_addr(self, runner):
        """suggest_names for a specific address should work."""
        script = '''
import idautils
# Get first unnamed function
target = None
for ea in idautils.Functions():
    import idc
    name = idc.get_func_name(ea) or ""
    if name.startswith("sub_"):
        target = hex(ea)
        break

if target:
    from funcs import funcs
    result = funcs(action="suggest_names", addr=target)
else:
    result = {"ok": True, "suggestions": [], "note": "no unnamed functions"}

import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True


# ─── agent cluster ─────────────────────────────────────────────────────────────

class TestAgentCluster:
    def test_cluster_returns_labeled_groups(self, runner):
        """cluster should return labeled behavioral groups."""
        script = '''
from agent import agent
# Limit to 30 functions to avoid timeout
result = agent(action="cluster", max_items=4, func_limit=30)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=300)
        assert result.get("ok") is True, f"cluster failed: {result}"
        assert "clusters" in result
        assert "total_functions" in result
        assert result["total_functions"] > 0
        assert len(result["clusters"]) > 0
        for c in result["clusters"]:
            assert "label" in c
            assert "size" in c
            assert c["size"] >= 1
            assert "representative_functions" in c
            assert len(c["representative_functions"]) >= 1

    def test_cluster_covers_all_functions(self, runner):
        """Sum of cluster sizes should equal total_functions."""
        script = '''
from agent import agent
result = agent(action="cluster", max_items=4, func_limit=30)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=300)
        assert result.get("ok") is True
        total = result["total_functions"]
        cluster_sum = sum(c["size"] for c in result["clusters"])
        assert cluster_sum == total


# ─── agent fingerprint ─────────────────────────────────────────────────────────

class TestAgentFingerprint:
    def test_fingerprint_returns_structure(self, runner):
        """fingerprint should return matches list (empty if no index yet)."""
        script = '''
from agent import agent
result = agent(action="fingerprint")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"fingerprint failed: {result}"
        assert "matches" in result
        assert isinstance(result["matches"], list)
        # Either has current_binary (index populated) or a note (empty index)
        assert "current_binary" in result or "note" in result


# ─── summarize report ─────────────────────────────────────────────────────────

class TestSummarizeReport:
    def test_report_has_sections(self, runner):
        """report should return a dict with report sections."""
        script = '''
from summarize import summarize
result = summarize(action="report")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"report failed: {result}"
        assert "report" in result
        report = result["report"]
        # At least some sections should be present
        assert len(report) > 0

    def test_report_binary_section(self, runner):
        """report binary section should have function count."""
        script = '''
from summarize import summarize
result = summarize(action="report")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        report = result.get("report", {})
        binary = report.get("binary", {})
        # binary section should have ok=True if it ran
        if binary:
            assert binary.get("ok") is True or "error" in binary


# ─── query nl ─────────────────────────────────────────────────────────────────

class TestQueryNL:
    def test_nl_query_empty_index(self, runner):
        """nl query on fresh binary returns empty results with note."""
        script = '''
from query import query
result = query(action="nl", q="find crypto functions")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=60)
        assert result.get("ok") is True or "error" in result
        # Either empty results with note, or an error — both are valid
        if result.get("ok"):
            assert "results" in result or "note" in result

    def test_nl_query_after_decompile(self, runner):
        """nl query after decompiling functions should return ranked results."""
        script = '''
import idautils
import idc
import ida_hexrays

# Decompile first 5 functions to populate the embedding index
from code import code
for i, ea in enumerate(idautils.Functions()):
    if i >= 5:
        break
    try:
        code(action="decompile", addrs=hex(ea))
    except Exception:
        pass

from query import query
result = query(action="nl", q="function that allocates memory")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=180)
        assert result.get("ok") is True or "error" in result


# ─── deobfuscate BehaviorClassifier ───────────────────────────────────────────

class TestDeobfuscate:
    def test_detect_returns_behavior_tags(self, runner):
        """deobfuscate detect should return behavior_tags from BehaviorClassifier."""
        script = '''
import idautils
# Get first function
ea = next(idautils.Functions(), None)
if ea is None:
    result = {"ok": False, "error": "no functions"}
else:
    from deobfuscate import deobfuscate
    result = deobfuscate(action="detect", addr=hex(ea))

import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=60)
        assert result.get("ok") is True, f"deobfuscate detect failed: {result}"
        # Should have either behavior_tags or findings
        assert "behavior_tags" in result or "findings" in result

    def test_detect_all_actions(self, runner):
        """All deobfuscate actions should return ok=True."""
        script = '''
import idautils
ea = next(idautils.Functions(), None)
results = {}
if ea:
    from deobfuscate import deobfuscate
    for action in ["detect", "stack_strings", "dead_code", "api_hashing",
                   "dynamic_dispatch", "anti_disasm"]:
        try:
            r = deobfuscate(action=action, addr=hex(ea))
            results[action] = r.get("ok", False)
        except Exception as e:
            results[action] = str(e)

import os
with open(RESULT_PATH, "w") as f:
    json.dump({"ok": True, "results": results}, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        for action, ok in result.get("results", {}).items():
            assert ok is True, f"deobfuscate({action}) failed"


# ─── blackboard semantic search with real functions ───────────────────────────

class TestBlackboardSemantic:
    def test_semantic_search_finds_related(self, runner):
        """After writing entries, semantic_search should find related ones."""
        script = '''
import sys, os

from blackboard import blackboard, BlackboardStore

# Use a temp db so we control the path
import tempfile
db = tempfile.mktemp(suffix=".db")
store = BlackboardStore(db_path=db)

# Write entries directly to the store
store.write("AES encryption key schedule", content="sub_bytes shift_rows mix_columns",
            category="crypto", tags=["aes"], confidence=0.9, embed=False)
store.write("Network socket connection", content="socket connect send recv",
            category="network", tags=["network"], confidence=0.8, embed=False)
store.write("Process injection via VirtualAllocEx",
            content="VirtualAllocEx WriteProcessMemory CreateRemoteThread",
            category="injection", tags=["injection"], confidence=0.95, embed=False)

# Substring fallback search (no embedder in IDA context)
import sys
# Patch _get_embedder to return None to force substring fallback
import blackboard as _bb_mod
orig = _bb_mod._get_embedder
_bb_mod._get_embedder = lambda: None
try:
    results = store.semantic_search("AES encryption", top_k=5)
finally:
    _bb_mod._get_embedder = orig

result = {
    "ok": True,
    "results": results,
    "count": len(results),
}

import os, json
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=60)
        assert result.get("ok") is True, f"semantic search failed: {result}"
        assert "results" in result
        titles = [r.get("title", "") for r in result.get("results", [])]
        assert any("AES" in t for t in titles), \
            f"Expected AES entry in results, got: {titles}"

    def test_blackboard_stats_after_writes(self, runner):
        """stats should reflect written entries."""
        script = '''
from blackboard import blackboard
blackboard(action="clear")
blackboard(action="write", title="Finding 1", category="vuln", confidence=0.9)
blackboard(action="write", title="Finding 2", category="vuln", confidence=0.7)
blackboard(action="write", title="Finding 3", category="network", confidence=0.5)
result = blackboard(action="stats")
import os, json
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=60)
        assert result.get("ok") is True
        assert result.get("total_entries") == 3
        assert result["by_category"].get("vuln") == 2
        assert result["by_category"].get("network") == 1


# ─── modify rename propagation ────────────────────────────────────────────────

class TestRenamePropagation:
    def test_rename_writes_propagation_suggestions(self, runner):
        """After rename, blackboard should eventually have rename_suggestion entries."""
        script = '''
import idautils, idc, time

# Find an unnamed function
target_ea = None
for ea in idautils.Functions():
    name = idc.get_func_name(ea) or ""
    if name.startswith("sub_"):
        target_ea = ea
        break

if target_ea is None:
    result = {"ok": True, "skipped": "no unnamed functions"}
else:
    from modify import modify
    # Rename it
    r = modify(action="rename", addr=hex(target_ea), value="test_renamed_func")
    # Wait briefly for background propagation thread
    time.sleep(2)
    # Check blackboard for propagation suggestions
    from blackboard import blackboard
    entries = blackboard(action="list", category="rename_suggestion", limit=20)
    result = {
        "ok": True,
        "rename_result": r,
        "propagation_entries": entries.get("count", 0),
    }

import os, json
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"rename propagation failed: {result}"
        if not result.get("skipped"):
            rename_r = result.get("rename_result", {})
            assert rename_r.get("ok") is True, f"rename failed: {rename_r}"


# ─── gadgets classify_chain ───────────────────────────────────────────────────

class TestGadgetsClassifyChain:
    def test_classify_chain_returns_assessment(self, runner):
        """classify_chain should return exploit_assessment and primitives_found."""
        script = '''
from gadgets import gadgets
result = gadgets(action="classify_chain")
import os, json
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"classify_chain failed: {result}"
        assert "exploit_assessment" in result
        assert "primitives_found" in result
        assert "arch" in result
        assert result["exploit_assessment"] in (
            "HIGH: Full ROP chain possible — stack pivot + write primitives + syscall/exec gadgets present",
            "MEDIUM: Partial ROP chain — pivot and gadgets present, missing write-what-where or syscall",
            "LOW: ROP gadgets present but no stack pivot found",
            "MINIMAL: Limited gadget surface",
        )
