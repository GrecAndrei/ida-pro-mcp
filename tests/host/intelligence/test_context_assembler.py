"""Behavioral tests for ContextAssembler's adaptive control plane.

The assembler's retrieval-ranking, semantic-tuning, stuck-detection, and
relation-graph logic is pure in-memory Python.  These tests drive those
methods through their public inputs/outputs with a minimal instance (the
heavy embedder/classifier constructor is skipped via ``object.__new__``),
so no IDA or embedding model is needed.
"""
from __future__ import annotations

import collections
import threading
import time

from ida_pro_mcp.host.intelligence.context import ContextAssembler


def _assembler(**attrs) -> ContextAssembler:
    obj = object.__new__(ContextAssembler)
    obj._retrieval_metrics = collections.defaultdict(dict)
    obj._retrieval_metrics_lock = threading.Lock()
    obj._session_semantic_threshold = {}
    obj._semantic_threshold_lock = threading.Lock()
    obj._last_housekeeping_ts = 0.0
    obj._housekeeping_lock = threading.Lock()
    obj._related_graph_max_edges = 1200
    obj._related_addr_graph = collections.defaultdict(lambda: collections.defaultdict(set))
    obj._related_addr_lock = threading.Lock()
    obj._semantic_circuit_breaker_until = {}
    obj._circuit_breaker_lock = threading.Lock()
    obj._session_stats_cache = {}
    obj._stats_cache_lock = threading.Lock()
    obj._stats_cache_ttl_sec = 1.5
    obj._perf_buckets = collections.defaultdict(dict)
    obj._perf_lock = threading.Lock()
    obj._semantic_budget_cache = {}
    obj._semantic_budget_lock = threading.Lock()
    obj._activity = collections.defaultdict(list)
    obj._activity_lock = threading.Lock()
    for key, value in attrs.items():
        # Kwargs mirror the private attribute names (e.g.
        # _related_graph_max_edges), matching the defaults set above.
        setattr(obj, key if key.startswith("_") else f"_{key}", value)
    return obj


def _seed_metrics(obj: ContextAssembler, session_id: str, totals: dict[str, int], hits: dict[str, int]) -> None:
    metrics = obj._retrieval_metrics[session_id]
    for src in ("address_linked", "relation_linked", "api_linked", "semantic_linked"):
        metrics[f"{src}.total"] = totals.get(src, 0)
        metrics[f"{src}.accepted"] = totals.get(src, 0)
        metrics[f"{src}.kept"] = hits.get(src, 0)


class TestMergeRelatedFindings:
    def test_ranks_by_source_then_confidence(self):
        obj = _assembler()
        pack: dict = {}
        entries = [
            {"id": "a1", "confidence": 0.9, "priority": 0.8, "updated_at": 3},
            {"id": "a2", "confidence": 0.9, "priority": 0.8, "updated_at": 3},
            {"id": "a3", "confidence": 0.9, "priority": 0.8, "updated_at": 3},
            {"id": "a4", "confidence": 0.9, "priority": 0.8, "updated_at": 3},
        ]
        obj._merge_related_findings(pack, entries, "address_linked", "s1")
        obj._merge_related_findings(pack, [{"id": "b1", "confidence": 0.9, "priority": 0.8, "updated_at": 3}], "semantic_linked", "s1")
        assert len(pack["related_findings"]) == 5
        assert pack["related_findings"][0]["retrieval_source"] == "address_linked"
        # semantic_linked ranks last
        assert pack["related_findings"][-1]["id"] == "b1"

    def test_dedup_keeps_higher_source_rank(self):
        obj = _assembler()
        pack: dict = {}
        obj._merge_related_findings(
            pack,
            [{"id": "x", "confidence": 0.9, "priority": 0.5, "updated_at": 1}],
            "semantic_linked",
            "s1",
        )
        obj._merge_related_findings(
            pack,
            [{"id": "x", "confidence": 0.9, "priority": 0.5, "updated_at": 1}],
            "address_linked",
            "s1",
        )
        assert len(pack["related_findings"]) == 1
        assert pack["related_findings"][0]["retrieval_source"] == "address_linked"

    def test_empty_entries_leave_pack_unchanged(self):
        obj = _assembler()
        pack: dict = {"related_findings": [{"id": "keep", "confidence": 0.5}]}
        obj._merge_related_findings(pack, [], "address_linked", "s1")
        assert pack["related_findings"] == [{"id": "keep", "confidence": 0.5}]

    def test_metrics_recorded(self):
        obj = _assembler()
        pack: dict = {}
        entries = [{"id": f"e{i}", "confidence": 0.9, "priority": 0.5, "updated_at": 1} for i in range(10)]
        obj._merge_related_findings(pack, entries, "api_linked", "s1")
        metrics = obj._retrieval_metrics["s1"]
        assert metrics["api_linked.total"] == 10
        assert metrics["api_linked.accepted"] == 8  # capped at max_take=8
        assert metrics["api_linked.kept"] == 8  # capped at 8


class TestRetrievalStats:
    def test_rates_and_caching(self):
        obj = _assembler()
        _seed_metrics(obj, "s1", totals={"address_linked": 10, "semantic_linked": 5}, hits={"address_linked": 8, "semantic_linked": 1})
        stats = obj._session_retrieval_stats("s1")
        assert stats["address_linked"]["accept_rate"] == 1.0
        assert stats["address_linked"]["hit_rate"] == 0.8
        assert stats["semantic_linked"]["hit_rate"] == 0.2
        assert stats["semantic_threshold"] == 0.5
        # Second call is served from cache
        stats["address_linked"]["hit_rate"] = 0.0
        cached = obj._session_retrieval_stats("s1")
        assert cached["address_linked"]["hit_rate"] == 0.8

    def test_no_metrics_returns_empty(self):
        obj = _assembler()
        assert obj._session_retrieval_stats("s1") == {}
        assert obj._session_retrieval_stats("") == {}

    def test_quality_profile_from_rates(self):
        obj = _assembler()
        _seed_metrics(
            obj, "s1",
            totals={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 10},
            hits={"address_linked": 9, "relation_linked": 7, "api_linked": 5, "semantic_linked": 3},
        )
        profile = obj._semantic_quality_profile("s1")
        assert profile["hit_q25"] <= profile["hit_q50"] <= profile["hit_q75"]
        assert profile["min_total"] >= 4

    def test_quality_profile_defaults_without_data(self):
        obj = _assembler()
        profile = obj._semantic_quality_profile("s1")
        assert profile["hit_q50"] == 0.5  # default
        assert profile["perf_q50"] == 45.0  # default
        assert profile["min_total"] >= 4


class TestSemanticTuning:
    def test_threshold_rises_when_hit_rate_is_low(self):
        obj = _assembler()
        _seed_metrics(
            obj, "s1",
            totals={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 12},
            hits={"address_linked": 10, "relation_linked": 9, "api_linked": 8, "semantic_linked": 0},
        )
        obj._tune_semantic_threshold("s1")
        assert obj._get_semantic_threshold("s1") > 0.5

    def test_threshold_falls_when_hit_rate_is_high(self):
        obj = _assembler()
        obj._session_semantic_threshold["s1"] = 0.9
        _seed_metrics(
            obj, "s1",
            totals={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 12},
            hits={"address_linked": 0, "relation_linked": 1, "api_linked": 2, "semantic_linked": 12},
        )
        obj._tune_semantic_threshold("s1")
        assert obj._get_semantic_threshold("s1") < 0.9

    def test_threshold_untouched_below_min_total(self):
        obj = _assembler()
        obj._retrieval_metrics["s1"].update(
            {"semantic_linked.total": 2, "semantic_linked.accepted": 2, "semantic_linked.kept": 0}
        )
        obj._tune_semantic_threshold("s1")
        assert obj._get_semantic_threshold("s1") == 0.5

    def test_tune_does_not_raise_without_persistence_hook(self):
        # Regression: _schedule_policy_save was removed with the policy
        # mixin; tuning must still update the in-memory threshold.
        obj = _assembler()
        _seed_metrics(
            obj, "s1",
            totals={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 12},
            hits={"address_linked": 10, "relation_linked": 9, "api_linked": 8, "semantic_linked": 0},
        )
        obj._tune_semantic_threshold("s1")  # must not raise
        assert obj._get_semantic_threshold("s1") > 0.5

    def test_circuit_breaker_opens_on_persistent_weak_quality(self):
        obj = _assembler()
        _seed_metrics(
            obj, "s1",
            totals={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 10},
            hits={"address_linked": 10, "relation_linked": 10, "api_linked": 10, "semantic_linked": 0},
        )
        obj._update_semantic_circuit_breaker("s1")
        assert obj._semantic_circuit_open("s1") is True


class TestAdaptiveBudget:
    def test_bounds_and_cache(self):
        obj = _assembler()
        budget = obj._adaptive_semantic_budget("s1", default_max=24)
        assert 6 <= budget <= 48
        assert obj._adaptive_semantic_budget("s1", default_max=24) == budget  # cached

    def test_circuit_open_halves_budget(self):
        obj = _assembler()
        obj._semantic_circuit_breaker_until["s1"] = int(time.time()) + 1000
        budget = obj._adaptive_semantic_budget("s1", default_max=24)
        assert budget < 24


class TestStuckDetection:
    def test_repeated_address(self):
        obj = _assembler()
        for _i in range(4):
            obj.record_call("s1", "code", "decompile", "0x1000")
        result = obj.check_stuck("s1", "0x1000", "code", "decompile")
        assert result is not None
        assert result["type"] == "repeated_address"
        assert result["count"] == 4
        assert any("callers" in p for p in result["pivot_suggestions"])

    def test_repeated_tool_with_pivots(self):
        obj = _assembler()
        for _i in range(6):
            obj.record_call("s1", "code", "decompile", "0x1000")
        result = obj.check_stuck("s1", "0x2000", "code", "decompile")
        assert result["type"] == "repeated_tool"
        assert result["tool_action"] == "code:decompile"
        assert result["pivot_suggestions"] == ["code:callers", "code:callees", "search:semantic"]

    def test_below_threshold_returns_none(self):
        obj = _assembler()
        for _i in range(3):
            obj.record_call("s1", "code", "decompile", "0x1000")
        assert obj.check_stuck("s1", "0x1000", "code", "decompile") is None


class TestRelationGraph:
    def test_edges_are_undirected_and_self_excluded(self):
        obj = _assembler()
        obj._record_related_addresses("s1", "0x1000", ["0x2000", "0x2000", "0x1000"])
        graph = obj._related_addr_graph["s1"]
        assert "0x2000" in graph["0x1000"]
        assert "0x1000" in graph["0x2000"]
        assert "0x1000" not in graph["0x1000"]

    def test_housekeeping_prunes_oversized_graph(self):
        obj = _assembler(_related_graph_max_edges=4)
        graph = obj._related_addr_graph["s1"]
        for i in range(6):
            anchor = f"0x{i:04x}"
            for j in range(6):
                if j != i:
                    graph[anchor].add(f"0x{j:04x}")
        obj._run_housekeeping("s1")
        total = sum(len(v) for v in obj._related_addr_graph["s1"].values())
        assert total <= 4
