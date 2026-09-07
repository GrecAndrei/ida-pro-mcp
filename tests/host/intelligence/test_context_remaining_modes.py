"""Cross-mode coverage for ContextAssembler's bounded control paths."""

from __future__ import annotations

from ida_pro_mcp.host.intelligence import context as context_mod, core as core_mod
from ida_pro_mcp.host.intelligence.context import ContextAssembler
from tests.host.intelligence.test_context_enrichment import (
    _FakeEmbedder,
    _InlineThread,
    _make_assembler,
)


def test_index_lru_keeps_current_and_discards_oldest(tmp_path):
    obj = _make_assembler(embedder=_FakeEmbedder(), max_indexes=2)
    first = obj._get_index(str(tmp_path / "first.idb"))
    obj._get_index(str(tmp_path / "second.idb"))
    current = obj._get_index(str(tmp_path / "third.idb"))

    assert current is obj._indexes[str(tmp_path / "third.idb")]
    assert str(tmp_path / "first.idb") not in obj._indexes
    assert str(tmp_path / "second.idb") in obj._indexes
    assert first._db_path.endswith("first.idb.embeddings.db")


def test_embedding_persistence_handles_missing_gate_quality_rows_and_thread_failure(
    tmp_path, monkeypatch
):
    obj = _make_assembler(embedder=_FakeEmbedder())
    idx = obj._get_index(str(tmp_path / "persist.idb"))
    del obj._persist_gate
    monkeypatch.setattr(context_mod.threading, "Thread", _InlineThread)

    assert obj._schedule_embedding_persist(
        idx,
        "0x1000",
        "target",
        [1.0, 0.0],
        "p",
        "sig",
        "s",
        "document",
    ) is True
    with idx._conn() as conn:
        assert conn.execute(
            "SELECT name FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()[0] == "target"

        conn.execute(
            "UPDATE func_embeddings SET index_quality='full' WHERE ea=?",
            ("0x1000",),
        )
        conn.commit()

    # A request-time write must not overwrite an index_many/full row.
    assert obj._schedule_embedding_persist(
        idx,
        "0x1000",
        "lower-quality",
        [0.0, 1.0],
        "new",
        "new-sig",
        "new-hash",
        "new-document",
    ) is True
    with idx._conn() as conn:
        assert conn.execute(
            "SELECT name FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()[0] == "target"

    class BrokenThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("thread unavailable")

    monkeypatch.setattr(context_mod.threading, "Thread", BrokenThread)
    assert obj._schedule_embedding_persist(
        idx,
        "0x2000",
        "target",
        [1.0, 0.0],
        "p",
        "sig",
        "s",
        "document",
    ) is False


def test_context_telemetry_profiles_perf_budget_and_cleanup(monkeypatch):
    obj = _make_assembler()
    assert obj._invalidate_session_caches("") is None
    assert obj._semantic_circuit_open("") is False
    assert obj._adaptive_semantic_budget("", default_max=20) == 20
    obj._perf_end("", "ignored", obj._perf_start())

    obj._retrieval_metrics["s1"].update(
        {
            "semantic_linked.total": 12,
            "semantic_linked.accepted": 12,
            "semantic_linked.kept": 1,
        }
    )
    obj._perf_buckets["s1"].update(
        {
            "assemble.count": 2,
            "assemble.sum_ms": 100.0,
            "decompile_enrich.count": 2,
            "decompile_enrich.sum_ms": 160.0,
            "search_enrich.count": 1,
            "search_enrich.sum_ms": 20.0,
        }
    )
    monkeypatch.setattr(core_mod, "INTEL_PROFILE", True)
    profile = obj._semantic_quality_profile("s1")
    assert profile["perf_q50"] > 0
    budget = obj._adaptive_semantic_budget("s1", default_max=24)
    assert 6 <= budget <= 48

    obj._update_semantic_circuit_breaker("s1")
    assert obj._semantic_circuit_open("s1") is True
    obj._semantic_budget_cache.clear()
    reduced = obj._adaptive_semantic_budget("s1", default_max=24)
    assert reduced < 24

    obj._activity["s1"].append({"action": "old"})
    obj._related_addr_graph["s1"]["0x1"].add("0x2")
    obj._retrieval_metrics["s1"]["x"] = 1
    obj._session_semantic_threshold["s1"] = 0.7
    obj._semantic_budget_cache["s1"] = (0.0, 20)
    obj._perf_buckets["s1"]["x"] = 1
    obj._session_stats_cache["s1"] = (0.0, {})
    obj.drop_session("s1")
    assert "s1" not in obj._activity
    assert "s1" not in obj._related_addr_graph
    assert "s1" not in obj._retrieval_metrics
    assert "s1" not in obj._session_last_seen


def test_housekeeping_prunes_stale_session_state_and_relation_failures(monkeypatch):
    obj = _make_assembler(_related_graph_max_edges=1)
    obj._session_last_seen["stale"] = 1.0
    obj._session_last_seen["fresh"] = 10_000.0
    obj._activity["stale"].append({"action": "old"})
    graph = obj._related_addr_graph["s1"]
    graph["0x1"].update({"0x2", "0x3"})
    graph["0x2"].add("0x1")
    obj._last_housekeeping_ts = 0.0
    obj._run_housekeeping("s1")
    assert sum(len(neighbors) for neighbors in graph.values()) <= 1
    assert "stale" not in obj._session_last_seen
    assert "stale" not in obj._activity

    assert obj._record_related_addresses("", "0x1", ["0x2"]) is None
    assert obj._get_bb_by_related_addresses("s1", "0x1", None) == []

    class BrokenStore:
        def list(self, **kwargs):
            raise RuntimeError("store unavailable")

    obj._related_addr_graph["s1"]["0x1"].add("0x2")
    assert obj._get_bb_by_related_addresses("s1", "0x1", BrokenStore()) == []


def test_enrichment_failure_and_compact_result_modes(monkeypatch):
    class NoEmbedder:
        def embed_vector(self, _text):
            return None

    class BrokenClassifier:
        def classify(self, *args, **kwargs):
            raise RuntimeError("classifier unavailable")

    class BrokenStore:
        def list(self, **kwargs):
            raise RuntimeError("blackboard unavailable")

        def semantic_search(self, **kwargs):
            raise RuntimeError("semantic backend unavailable")

    obj = _make_assembler(embedder=NoEmbedder(), classifier=BrokenClassifier())
    pack = {}
    obj._enrich_decompile(
        pack,
        {"name": "target"},
        "void target(void) { return 0; } " * 8,
        "0x1000",
        "",
        BrokenStore(),
        "s1",
    )
    assert "behavior_classifications" not in pack
    assert "similar_functions" not in pack

    # A decompile-chain payload can supply its pseudocode through results;
    # compact mode still records the call but does not expose verbose output.
    calls = []

    def mark_called(*args, **kwargs):
        calls.append((args, kwargs))

    obj._enrich_decompile = mark_called
    obj._run_housekeeping = lambda *_args: None
    obj._enrich_address_list = lambda *_args: [{"ea": "0x2000"}]
    compact = obj.assemble(
        "code",
        "decompile_chain",
        {"results": [{"pseudocode": "int f(void) { return 1; } " * 5}]},
        "0x1000",
        "s1",
        "some.idb",
        mode="compact",
    )
    assert compact == {}
    assert calls


def test_assembler_singleton_and_state_boundaries(monkeypatch):
    old = context_mod._assembler
    try:
        context_mod._assembler = None
        sentinel = object()
        monkeypatch.setattr(context_mod, "ContextAssembler", lambda: sentinel)
        assert context_mod.get_assembler() is sentinel
        context_mod._assembler = None
        assert context_mod._shutdown_intelligence_singleton() is None
    finally:
        context_mod._assembler = old


def test_context_assembler_real_init_and_status(monkeypatch):
    monkeypatch.setattr(context_mod, "BgeCodeEmbedder", _FakeEmbedder)
    monkeypatch.setattr(context_mod.BehaviorClassifier, "instance", lambda _emb: None)
    asm = ContextAssembler()
    assert asm._embedder is not None
    assert asm._max_indexes == 4
    assert asm.status["backend"] == "fake"
    assert asm.ensure_embedding_server() is True
    asm.stop()


def test_context_assembler_housekeeping_and_merging_edges(tmp_path, monkeypatch):
    import time
    import types

    obj = _make_assembler(embedder=_FakeEmbedder())

    # 1. line 202-205: _schedule_embedding_persist worker exception
    idx = obj._get_index(str(tmp_path / "persist_fail.idb"))
    monkeypatch.setattr(context_mod.threading, "Thread", _InlineThread)
    monkeypatch.setattr(idx, "_conn", lambda: (_ for _ in ()).throw(RuntimeError("conn fail")))
    assert obj._schedule_embedding_persist(idx, "0x1000", "func", [1.0], "p", "s", "sh", "doc") is True

    # 2. lines 263, 289-290, 319-320 in _merge_related_findings
    pack = {}
    obj._merge_related_findings(pack, [], "address_linked")
    assert pack == {}

    # line 263: negative confidence causes filtered_entries to be empty
    obj._merge_related_findings(pack, [{"id": "neg", "confidence": -1.0}], "address_linked")
    assert pack == {}

    pack = {"related_findings": [{"id": "f1", "confidence": 0.5, "retrieval_source": "address_linked"}]}
    obj._merge_related_findings(pack, [{"id": "f1", "confidence": 0.9}], "address_linked")
    assert pack["related_findings"][0]["confidence"] == 0.9

    monkeypatch.setattr(obj, "_retrieval_metrics_lock", types.SimpleNamespace(
        __enter__=lambda: (_ for _ in ()).throw(RuntimeError("lock fail")),
        __exit__=lambda *a: None,
    ))
    obj._merge_related_findings(pack, [{"id": "f2", "confidence": 0.5}], "address_linked", session_id="s1")

    # 3. lines 375-376: _session_retrieval_stats exception
    assert obj._get_semantic_threshold("") == 0.5
    obj._retrieval_metrics["s1"] = {"address_linked.total": 1}
    monkeypatch.setattr(obj, "_get_semantic_threshold", lambda _s: (_ for _ in ()).throw(RuntimeError("stats fail")))
    assert obj._session_retrieval_stats("s1") == {}

    # 4. lines 399, 419, 422-423, 435 in housekeeping and _drop_session_state
    obj._drop_session_state("")
    obj._related_graph_max_edges = 2
    obj._related_addr_graph["s1"]["0x1000"] = {"0x1004", "0x1008", "0x100c"}
    obj._related_addr_graph["s1"]["0x2000"] = {"0x2004"}
    obj._related_addr_graph["s1"]["0x3000"] = {"0x3004"}
    obj._related_addr_graph["s1"]["0x4000"] = {"0x4004"}
    obj._session_last_seen.clear()
    obj._session_last_seen["s_stale"] = 10.0
    obj._session_last_seen["s_revived"] = 10.0
    obj._last_housekeeping_ts = 0.0

    # Revive s_revived when dropping stale sessions (triggers line 419)
    real_drop = obj._drop_session_state
    revived_hit = []

    def drop_and_revive(sid):
        revived_hit.append(sid)
        if sid == "s_stale":
            obj._session_last_seen["s_revived"] = time.time() + 1000.0
        real_drop(sid)

    obj._drop_session_state = drop_and_revive
    obj._run_housekeeping("s1")
    assert revived_hit == ["s_stale"]

    # Housekeeping exception handler (lines 422-423)
    obj._last_housekeeping_ts = 0.0
    obj._drop_session_state = lambda sid: (_ for _ in ()).throw(RuntimeError("drop fail"))
    obj._session_last_seen["s_fail"] = 10.0
    obj._run_housekeeping("s1")

    # 5. lines 561-562, 573, 587-588, 592, 601, 630-631, 645-646
    obj._update_semantic_circuit_breaker("")
    obj._tune_semantic_threshold("")
    monkeypatch.setattr(obj, "_session_retrieval_stats", lambda _s: (_ for _ in ()).throw(RuntimeError("tune fail")))
    obj._tune_semantic_threshold("s1")
    obj._adaptive_semantic_budget("s1")
    obj._update_semantic_circuit_breaker("s1")
    real_addr_lock = obj._related_addr_lock
    obj._related_addr_lock = types.SimpleNamespace(
        __enter__=lambda: (_ for _ in ()).throw(RuntimeError("addr lock fail")),
        __exit__=lambda *a: None,
    )
    obj._record_related_addresses("s1", "0x1000", ["0x2000"])
    obj._related_addr_lock = real_addr_lock

    # 6. lines 672, 677 in _get_bb_by_related_addresses
    class MockBB:
        def list(self, addr, limit=3):
            return [{"id": "dup_id", "addr": addr}, {"id": "dup_id", "addr": addr}, {"id": f"unique_{addr}"}]

    obj._related_addr_graph["s_rel"]["0x1000"] = {"0x1004", "0x1008"}
    found_bb = obj._get_bb_by_related_addresses("s_rel", "0x1000", MockBB(), top_k=2)
    assert len(found_bb) == 2

    # 7. line 687 in record_call and line 753 in check_stuck
    obj.record_call("", "tool", "action", "0x1000")
    obj.record_call("   ", "tool", "action", "0x1000")
    for i in range(6):
        obj.record_call("s_not_stuck", f"tool_{i}", f"action_{i}", f"0x{i+1}000")
    assert obj.check_stuck("s_not_stuck", "0x9999", "tool_x", "action_x") is None


def test_context_assembler_search_and_decompile_branches(tmp_path, monkeypatch):
    import types

    obj = _make_assembler(embedder=_FakeEmbedder())
    idb = str(tmp_path / "search.idb")
    idx = obj._get_index(idb)

    # 1. lines 832-837: dict items in search payload (ea, addr, address, from, to)
    search_payload = {
        "results": [
            {"ea": "0x1000"},
            {"addr": "0x2000"},
            {"address": "0x3000"},
            {"from": "0x4000"},
            {"to": "0x5000"},
        ]
    }
    with idx._conn() as conn:
        for ea in ("0x1000", "0x2000", "0x3000", "0x4000", "0x5000"):
            conn.execute(
                "INSERT OR REPLACE INTO func_embeddings(ea, name, vec_blob, func_size, bb_count, has_loops, api_count, string_count, segment, cyclomatic) VALUES (?, ?, ?, 100, 5, 1, 3, 2, '.text', 4)",
                (ea, f"sub_{ea}", b"\x00" * 8),
            )
        conn.commit()
    idx._load_cache()

    pack_search = obj.assemble("search", "find", search_payload, "0x1000", "s1", idb)
    assert "hit_details" in pack_search

    # Search enrichment exception (lines 844-845)
    real_enrich = obj._enrich_address_list
    obj._enrich_address_list = lambda *a: (_ for _ in ()).throw(RuntimeError("search enrich fail"))
    assert obj.assemble("search", "find", search_payload, "0x1000", "s1", idb) == {}
    obj._enrich_address_list = real_enrich

    # Next target suggestion exception (lines 863-864)
    real_suggest = obj.suggest_next_targets
    obj.suggest_next_targets = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("target fail"))
    obj._activity["s1"] = [{"_n": 4}]
    obj.assemble("code", "disasm", {}, "0x1000", "s1", idb)
    obj.suggest_next_targets = real_suggest

    # 2. Decompile enrichment:
    # line 936 (query_vec is None), lines 964-965 (similarity exception),
    # lines 972-974 (relation linked findings), lines 995-996 (semantic bb search exception)
    class NoneEmbedder(_FakeEmbedder):
        def embed_vector(self, text):
            return None

    obj_no_vec = _make_assembler(embedder=NoneEmbedder())
    p_none = {}
    obj_no_vec._enrich_decompile(p_none, {}, "int test() { return 1; } " * 10, "0x1000", idb, None, "s1")

    # Similarity search exception (lines 964-965)
    monkeypatch.setattr(idx, "similar_vec", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("similar fail")))
    p_sim_err = {}
    obj._enrich_decompile(p_sim_err, {}, "int test() { return 1; } " * 10, "0x1000", idb, None, "s1")

    # Relation linked findings (lines 972-974) and semantic search exception (lines 995-996)
    class RelationBB:
        def list(self, addr, limit=3):
            return [{"id": "f_rel", "addr": addr, "confidence": 0.8}]

        def semantic_search(self, *a, **k):
            raise RuntimeError("semantic fail")

    obj._related_addr_graph["s1"]["0x1000"] = {"0x2000"}
    p_rel = {}
    obj._enrich_decompile(p_rel, {}, "int test() { return 1; } " * 10, "0x1000", idb, RelationBB(), "s1")
    assert any(f.get("id") == "f_rel" for f in p_rel.get("related_findings", []))

    # Relation linked exception handler (lines 973-974)
    real_rel = obj._get_bb_by_related_addresses
    obj._get_bb_by_related_addresses = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("rel fail"))
    obj._enrich_decompile({}, {}, "int test() { return 1; } " * 10, "0x1000", idb, RelationBB(), "s1")
    obj._get_bb_by_related_addresses = real_rel

    # 3. _enrich_address_list exception (lines 1056-1057)
    monkeypatch.setattr(idx, "_conn", lambda: (_ for _ in ()).throw(RuntimeError("conn fail")))
    assert obj._enrich_address_list(["0x1000"], idb) == []

    # 4. suggest_next_targets: ea in analyzed / seen (line 1087) and exception (lines 1099-1100)
    monkeypatch.setattr(idx, "cache_keys", lambda: {"0x1000"})
    monkeypatch.setattr(idx, "search_structured", lambda *a, **k: [
        {"ea": "0x1000", "name": "sub_1000", "func_size": 100, "bb_count": 5, "api_count": 3, "has_loops": 1},
        {"ea": "0x2000", "name": "sub_2000", "func_size": 100, "bb_count": 5, "api_count": 3, "has_loops": 1},
        {"ea": "0x2000", "name": "sub_2000_dup", "func_size": 100, "bb_count": 5, "api_count": 3, "has_loops": 1},
    ])
    sugg = obj.suggest_next_targets(idb)
    assert len(sugg) == 1
    assert sugg[0]["ea"] == "0x2000"

    monkeypatch.setattr(idx, "search_structured", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("search fail")))
    assert obj.suggest_next_targets(idb) == []

    # 5. _shutdown_intelligence_singleton with active assembler (lines 1144-1146)
    context_mod._assembler = types.SimpleNamespace(stop=lambda: (_ for _ in ()).throw(RuntimeError("stop fail")))
    context_mod._shutdown_intelligence_singleton()
