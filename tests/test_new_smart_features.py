"""
Tests for new smart features:
- BlackboardStore.semantic_search (with stored vectors)
- auto_capture_memory / auto_capture_calc
- _kmeans_numpy clustering
- BehaviorClassifier custom anchors (gadgets exploit scoring)
- rename propagation blackboard writes
- query_lang AND-splitting fix
"""
import os
import sys
import json
import struct
import tempfile
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ─── Blackboard tests (no IDA needed) ────────────────────────────────────────

import importlib.util

def _load_blackboard():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "blackboard.py")
    spec = importlib.util.spec_from_file_location("_bb_test", path)
    mod = importlib.util.module_from_spec(spec)
    # Stub out IDA imports
    import types
    for m in ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
              "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
              "ida_hexrays", "ida_frame", "ida_struct", "ida_lines"]:
        sys.modules.setdefault(m, types.ModuleType(m))
    sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
    spec.loader.exec_module(mod)
    return mod


_bb_mod = _load_blackboard()
BlackboardStore = _bb_mod.BlackboardStore
auto_capture_memory = _bb_mod.auto_capture_memory
auto_capture_calc = _bb_mod.auto_capture_calc


def _make_store():
    tmp = tempfile.mktemp(suffix=".db")
    return BlackboardStore(db_path=tmp)


def test_blackboard_write_and_read():
    store = _make_store()
    eid = store.write("Test finding", content="details", category="vuln", addr="0x401000",
                      tags=["overflow"], confidence=0.9)
    assert len(eid) == 8
    entry = store.read(eid)
    assert entry["title"] == "Test finding"
    assert entry["category"] == "vuln"
    assert entry["addr"] == "0x401000"
    assert entry["confidence"] == 0.9
    assert "overflow" in entry["tags"]


def test_blackboard_list_by_category():
    store = _make_store()
    store.write("A", category="vuln")
    store.write("B", category="vuln")
    store.write("C", category="other")
    entries = store.list(category="vuln")
    assert len(entries) == 2
    assert all(e["category"] == "vuln" for e in entries)


def test_blackboard_list_by_addr():
    store = _make_store()
    store.write("At addr", addr="0x401234")
    store.write("Other", addr="0x500000")
    entries = store.list(addr="0x401234")
    assert len(entries) == 1
    assert entries[0]["addr"] == "0x401234"


def test_blackboard_update():
    store = _make_store()
    eid = store.write("Old title", confidence=0.3)
    ok = store.update(eid, title="New title", confidence=0.9)
    assert ok
    entry = store.read(eid)
    assert entry["title"] == "New title"
    assert entry["confidence"] == 0.9


def test_blackboard_delete():
    store = _make_store()
    eid = store.write("To delete")
    assert store.delete(eid)
    assert store.read(eid) is None
    assert not store.delete("nonexistent")


def test_blackboard_clear_by_category():
    store = _make_store()
    store.write("A", category="test")
    store.write("B", category="test")
    store.write("C", category="keep")
    count = store.clear(category="test")
    assert count == 2
    assert len(store.list(category="keep")) == 1


def test_blackboard_stats():
    store = _make_store()
    store.write("X", category="vuln", confidence=0.8)
    store.write("Y", category="vuln", confidence=0.6)
    s = store.stats()
    assert s["total_entries"] == 2
    assert s["by_category"]["vuln"] == 2
    assert 0.6 <= s["avg_confidence"] <= 0.8


def test_blackboard_prune_by_capacity():
    store = _make_store()
    for i in range(5):
        store.write(f"Entry {i}", confidence=0.5)
    result = store.prune(max_entries=3)
    assert result["pruned"] == 2
    assert result["remaining"] == 3
    assert len(store.list()) == 3


def test_blackboard_exists_similar():
    store = _make_store()
    store.write("Buffer overflow at 0x401234", addr="0x401234", category="vuln")
    # Exact title match
    assert store.exists_similar("0x401234", "vuln", "Buffer overflow at 0x401234")
    # High Jaccard similarity (same words, just reordered — Jaccard = 1.0)
    assert store.exists_similar("0x401234", "vuln", "overflow Buffer at 0x401234")
    # Different addr — should not match
    assert not store.exists_similar("0x500000", "vuln", "Buffer overflow at 0x401234")
    # Different category — should not match
    assert not store.exists_similar("0x401234", "other", "Buffer overflow at 0x401234")


def test_blackboard_auto_merge():
    store = _make_store()
    store.write("Buffer overflow at 0x401234", addr="0x401234", category="vuln")
    store.write("Buffer overflow at 0x401234", addr="0x401234", category="vuln")
    result = store.auto_merge(addr="0x401234", category="vuln")
    assert result["merged"] >= 1
    assert len(store.list(addr="0x401234")) == 1


def test_blackboard_semantic_search_fallback():
    """Without embedder, semantic_search falls back to substring match."""
    store = _make_store()
    store.write("AES encryption key schedule", category="crypto", embed=False)
    store.write("Network socket connection", category="network", embed=False)
    # Patch _get_embedder to return None to force fallback path
    orig = _bb_mod._get_embedder
    _bb_mod._get_embedder = lambda: None
    try:
        # "AES encryption" is a substring of the title
        results = store.semantic_search("AES encryption", top_k=5)
    finally:
        _bb_mod._get_embedder = orig
    assert any("AES" in r["title"] for r in results)


def test_blackboard_semantic_search_with_vectors():
    """With stored vectors, semantic_search uses cosine similarity."""
    store = _make_store()

    import sqlite3, time, uuid

    def _pack(v):
        return struct.pack(f"{len(v)}f", *v)

    v1 = [1.0, 0.0, 0.0, 0.0]
    v2 = [0.9, 0.1, 0.0, 0.0]
    v3 = [0.0, 0.0, 1.0, 0.0]  # orthogonal
    now = time.time()

    # Use the store's write method with embed=False, then manually update the vector
    for title, vec in [("Crypto function", v1), ("AES encrypt", v2), ("Network handler", v3)]:
        eid = store.write(title, category="test", embed=False)
        conn = sqlite3.connect(store.db_path)
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (_pack(vec), eid))
        conn.commit()
        conn.close()

    # Patch _get_embedder to return a fake that embeds as [1,0,0,0]
    orig = _bb_mod._get_embedder
    class _FakeEmb:
        def embed(self, text):
            return [1.0, 0.0, 0.0, 0.0]
    _bb_mod._get_embedder = lambda: _FakeEmb()
    try:
        results = store.semantic_search("crypto key", top_k=2, threshold=0.5)
        titles = [r["title"] for r in results]
        assert "Crypto function" in titles or "AES encrypt" in titles
        assert "Network handler" not in titles
    finally:
        _bb_mod._get_embedder = orig


def test_auto_capture_memory_pointers():
    store = _make_store()
    result = {
        "ok": True,
        "_action": "pointers",
        "pointers": [
            {"addr": "0x401000", "target": "0x402000", "name": "malloc"},
            {"addr": "0x401008", "target": "0x403000", "name": ""},
        ]
    }
    # Patch BlackboardStore constructor to use our store
    orig_cls = _bb_mod.BlackboardStore
    _bb_mod.BlackboardStore = lambda **kw: store
    try:
        auto_capture_memory(result, addr="0x401000")
    finally:
        _bb_mod.BlackboardStore = orig_cls
    entries = store.list(category="pointer")
    assert len(entries) >= 1
    assert any("malloc" in e["title"] or "0x402000" in e["title"] for e in entries)


def test_auto_capture_memory_entropy():
    store = _make_store()
    result = {"ok": True, "_action": "entropy", "entropy": 7.9}
    orig_cls = _bb_mod.BlackboardStore
    _bb_mod.BlackboardStore = lambda **kw: store
    try:
        auto_capture_memory(result, addr="0x401000")
    finally:
        _bb_mod.BlackboardStore = orig_cls
    entries = store.list(category="entropy")
    assert len(entries) == 1
    assert "7.9" in entries[0]["title"]


def test_auto_capture_calc_resolved():
    store = _make_store()
    result = {"ok": True, "_action": "resolve", "resolved": "0x401234", "name": "main"}
    orig_cls = _bb_mod.BlackboardStore
    _bb_mod.BlackboardStore = lambda **kw: store
    try:
        auto_capture_calc(result)
    finally:
        _bb_mod.BlackboardStore = orig_cls
    entries = store.list(category="address")
    assert len(entries) == 1
    assert "0x401234" in entries[0]["title"]


def test_auto_capture_calc_chain():
    store = _make_store()
    result = {
        "ok": True,
        "_action": "chain",
        "chain": [{"addr": "0x401000"}, {"addr": "0x402000"}, {"addr": "0x403000"}]
    }
    orig_cls = _bb_mod.BlackboardStore
    _bb_mod.BlackboardStore = lambda **kw: store
    try:
        auto_capture_calc(result)
    finally:
        _bb_mod.BlackboardStore = orig_cls
    entries = store.list(category="pointer_chain")
    assert len(entries) == 1
    assert "3 hops" in entries[0]["title"]


def test_auto_capture_dedup():
    """auto_capture should not write duplicate entries."""
    store = _make_store()
    result = {"ok": True, "_action": "resolve", "resolved": "0x401234", "name": "main"}
    orig_cls = _bb_mod.BlackboardStore
    _bb_mod.BlackboardStore = lambda **kw: store
    try:
        auto_capture_calc(result)
        auto_capture_calc(result)  # second call — should be deduped
    finally:
        _bb_mod.BlackboardStore = orig_cls
    entries = store.list(category="address")
    assert len(entries) == 1  # not 2


# ─── K-means clustering tests ─────────────────────────────────────────────────

def _load_agent_kmeans():
    """Load just the _kmeans_numpy function from agent.py without executing IDA imports."""
    # We only need _kmeans_numpy which has no IDA dependencies.
    # Extract it by compiling just the function definition.
    import ast, types as _types

    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "agent.py")
    src = open(path).read()

    # Find and extract just the _kmeans_numpy function
    tree = ast.parse(src)
    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_kmeans_numpy":
            func_node = node
            break

    assert func_node is not None, "_kmeans_numpy not found in agent.py"

    # Build a minimal module with just that function + numpy import
    mini_src = "import numpy as np\n" + ast.get_source_segment(src, func_node)
    mod = _types.ModuleType("_agent_kmeans_only")
    exec(compile(mini_src, "<agent_kmeans>", "exec"), mod.__dict__)
    return mod


_agent_mod = _load_agent_kmeans()
_kmeans_numpy = _agent_mod._kmeans_numpy


def test_kmeans_basic_separation():
    """Two clearly separated clusters should be assigned correctly."""
    import numpy as np
    # Cluster A: near [1, 0]
    # Cluster B: near [0, 1]
    vecs = [[1.0, 0.0], [0.9, 0.1], [0.95, 0.05],
            [0.0, 1.0], [0.1, 0.9], [0.05, 0.95]]
    labels, centroids = _kmeans_numpy(vecs, k=2)
    assert len(labels) == 6
    assert len(centroids) == 2
    # All A-cluster items should have the same label
    assert labels[0] == labels[1] == labels[2]
    # All B-cluster items should have the same label
    assert labels[3] == labels[4] == labels[5]
    # The two groups should have different labels
    assert labels[0] != labels[3]


def test_kmeans_k_equals_n():
    """When k >= n, each point gets its own cluster."""
    vecs = [[1.0, 0.0], [0.0, 1.0]]
    labels, centroids = _kmeans_numpy(vecs, k=5)
    assert len(labels) == 2
    assert labels[0] != labels[1]


def test_kmeans_single_cluster():
    vecs = [[1.0, 0.0], [0.9, 0.1], [0.95, 0.05]]
    labels, centroids = _kmeans_numpy(vecs, k=1)
    assert all(l == 0 for l in labels)
    assert len(centroids) == 1


def test_kmeans_deterministic():
    """Same input should produce same output (seed=42)."""
    vecs = [[float(i % 3), float(i // 3)] for i in range(9)]
    l1, _ = _kmeans_numpy(vecs, k=3)
    l2, _ = _kmeans_numpy(vecs, k=3)
    assert l1 == l2


# ─── Query lang AND-splitting fix ─────────────────────────────────────────────

def _load_query_lang():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "query_lang.py")
    spec = importlib.util.spec_from_file_location("_ql_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ql_mod = _load_query_lang()
QueryParser = _ql_mod.QueryParser


def test_query_parser_single_condition():
    p = QueryParser()
    conds = p._parse_conditions("size > 100")
    assert len(conds) == 1
    assert conds[0]["key"] == "size"
    assert conds[0]["op"] == ">"
    assert conds[0]["value"] == 100


def test_query_parser_and_split_two():
    p = QueryParser()
    conds = p._parse_conditions("size > 100 AND segment == \".text\"")
    assert len(conds) == 2
    assert conds[0]["key"] == "size"
    assert conds[1]["key"] == "segment"
    assert conds[1]["value"] == ".text"


def test_query_parser_and_split_three():
    p = QueryParser()
    conds = p._parse_conditions("size > 100 AND entropy >= 5.5 AND segment == \".text\"")
    assert len(conds) == 3
    keys = [c["key"] for c in conds]
    assert "size" in keys
    assert "entropy" in keys
    assert "segment" in keys


def test_query_parser_and_in_string_not_split():
    """AND inside a quoted string should not be treated as a separator."""
    p = QueryParser()
    conds = p._parse_conditions("name == \"COMMAND AND CONTROL\"")
    assert len(conds) == 1
    assert conds[0]["value"] == "COMMAND AND CONTROL"


def test_query_parser_contains():
    p = QueryParser()
    conds = p._parse_conditions("apis contains VirtualAlloc")
    assert len(conds) == 1
    assert conds[0]["op"] == "contains"
    assert conds[0]["value"] == "VirtualAlloc"


def test_query_parser_regex():
    p = QueryParser()
    conds = p._parse_conditions("name ~ sub_[0-9a-f]+")
    assert len(conds) == 1
    assert conds[0]["op"] == "~"


def test_full_query_parse():
    p = QueryParser()
    plan = p.parse("MATCH function * WHERE size > 100 AND segment == \".text\" LIMIT 10")
    assert plan is not None
    assert plan["target"] == "function"
    assert plan["limit"] == 10
    assert len(plan["conditions"]) == 2


# ─── Gadgets exploit scoring (no IDA) ─────────────────────────────────────────

def _load_gadgets():
    """Extract _score_gadgets_behavior from gadgets.py without executing IDA imports."""
    import ast, types as _types

    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "gadgets.py")
    src = open(path).read()
    tree = ast.parse(src)

    # Extract _score_gadgets_behavior and _classify_gadget_chain
    funcs_to_extract = {"_score_gadgets_behavior", "_classify_gadget_chain"}
    extracted = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in funcs_to_extract:
            seg = ast.get_source_segment(src, node)
            if seg:
                extracted.append(seg)

    mini_src = "\n".join(extracted)
    mod = _types.ModuleType("_gadgets_only")
    # Provide make_error stub
    mod.__dict__["make_error"] = lambda code, msg, *a, **kw: {"ok": False, "error": msg}
    class _MCPError:
        IDA_ERROR = "IDA_ERROR"
    mod.__dict__["MCPError"] = _MCPError
    from typing import Optional, Dict, List, Any
    mod.__dict__["Optional"] = Optional
    mod.__dict__["Dict"] = Dict
    mod.__dict__["List"] = List
    mod.__dict__["Any"] = Any
    exec(compile(mini_src, "<gadgets_score>", "exec"), mod.__dict__)
    return mod


_gadgets_mod = _load_gadgets()
_score_gadgets_behavior = _gadgets_mod._score_gadgets_behavior


def test_score_gadgets_behavior_empty():
    result = _score_gadgets_behavior([], "rop")
    assert result is None


def test_score_gadgets_behavior_no_embedder():
    """When intelligence.py is unavailable, returns None gracefully."""
    import unittest.mock as mock
    with mock.patch.dict("sys.modules", {"ida_pro_mcp.host.intelligence": None,
                                          "host.intelligence": None}):
        result = _score_gadgets_behavior([{"gadget": "pop rdi; ret"}], "rop")
        # Should return None (import failed) without raising
        assert result is None or isinstance(result, dict)


def test_score_gadgets_behavior_with_fake_embedder():
    """With a fake embedder, _score_gadgets_behavior returns a dict."""
    import types, unittest.mock as mock

    class _FakeEmb:
        backend = "test"
        def embed(self, text):
            return [1.0, 0.0]
        @staticmethod
        def cosine(a, b):
            return sum(x*y for x,y in zip(a,b))

    class _FakeClassifier:
        ANCHORS = {"rop_chain": "pop rdi ret gadget"}
        _shared = None
        _shared_lock = __import__("threading").Lock()
        def __init__(self, emb): self._embedder = emb
        @classmethod
        def instance(cls, emb): return cls(emb)
        def classify(self, text, **kw): return [{"behavior": "rop_chain", "confidence": 0.8}]
        def classify_vec(self, vec, **kw): return [{"behavior": "rop_chain", "confidence": 0.8}]
        def clear_cache(self): pass

    fake_intel = types.ModuleType("ida_pro_mcp.host.intelligence")
    fake_intel.BgeCodeEmbedder = _FakeEmb
    fake_intel.BehaviorClassifier = _FakeClassifier

    with mock.patch.dict("sys.modules", {"ida_pro_mcp.host.intelligence": fake_intel}):
        result = _score_gadgets_behavior(
            [{"gadget": "pop rdi; ret"}, {"gadget": "pop rsi; ret"}], "rop"
        )
    assert result is not None
    assert "classifications" in result
    assert result["top_primitive"] == "rop_chain"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
