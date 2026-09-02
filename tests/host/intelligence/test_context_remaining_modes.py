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
