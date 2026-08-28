"""Pipeline-level tests for ContextAssembler.assemble() and enrichment helpers.

These drive the decompile/search enrichment paths with fake embedder,
classifier, and blackboard-store doubles so the whole control plane runs in
memory (no IDA, no model, no subprocess).
"""

from __future__ import annotations

import collections
import threading
import time

import pytest

from ida_pro_mcp.host.intelligence import context as context_mod, core as core_mod
from ida_pro_mcp.host.intelligence.context import ContextAssembler


def _make_assembler(**attrs) -> ContextAssembler:
    """Minimal ContextAssembler without the heavy embedder/classifier ctor."""
    obj = object.__new__(ContextAssembler)
    obj._embedder = None
    obj._classifier = None
    obj._indexes = {}
    obj._idx_lock = threading.Lock()
    obj._activity = collections.defaultdict(list)
    obj._activity_lock = threading.Lock()
    obj._related_addr_graph = collections.defaultdict(lambda: collections.defaultdict(set))
    obj._related_addr_lock = threading.Lock()
    obj._retrieval_metrics = collections.defaultdict(dict)
    obj._retrieval_metrics_lock = threading.Lock()
    obj._session_semantic_threshold = {}
    obj._semantic_threshold_lock = threading.Lock()
    obj._last_housekeeping_ts = 0.0
    obj._housekeeping_lock = threading.Lock()
    obj._related_graph_max_edges = 1200
    obj._semantic_circuit_breaker_until = {}
    obj._circuit_breaker_lock = threading.Lock()
    obj._session_stats_cache = {}
    obj._stats_cache_lock = threading.Lock()
    obj._stats_cache_ttl_sec = 1.5
    obj._perf_buckets = collections.defaultdict(dict)
    obj._perf_lock = threading.Lock()
    obj._semantic_budget_cache = {}
    obj._semantic_budget_lock = threading.Lock()
    obj._persist_gate = threading.Semaphore(4)
    obj._max_indexes = 4
    obj._idx_last_access = {}
    obj._session_last_seen = {}
    obj._session_last_seen_lock = threading.Lock()
    for key, value in attrs.items():
        setattr(obj, key if key.startswith("_") else f"_{key}", value)
    return obj


class _FakeEmbedder:
    backend = "fake"
    dim = 4
    embedding_format = "fake-format"
    _model_path = ""
    _server_bin = ""
    _ready = True
    _batch_size = 2

    def __init__(self):
        self.stopped = False
        self.ensure_calls = 0

    def embed_vector(self, text):
        return [0.9, 0.1, 0.0, 0.0]

    def stop(self):
        self.stopped = True

    def ensure_ready(self):
        self.ensure_calls += 1
        return True


class _FakeClassifier:
    def __init__(self, hits=None):
        self.hits = hits or [{"behavior": "network", "confidence": 0.91}]
        self.calls: list[str] = []

    def classify(self, text, threshold=0.25, top_k=4, block=True):
        self.calls.append(str(text))
        return self.hits


class _FakeBBStore:
    def __init__(self, addr_entries=None, by_addr=None, sem_entries=None):
        self._addr = addr_entries or []
        self._by_addr = by_addr or {}
        self._sem = sem_entries or []

    def list(self, addr=None, limit=5, include_resolved=False):
        if addr is None:
            return []
        entries = self._by_addr.get(addr, self._addr)
        return entries[:limit]

    def semantic_search(self, query=None, top_k=5, threshold=0.5):
        return self._sem[:top_k]


def _entry(eid: str, addr: str, confidence: float = 0.9) -> dict:
    return {"id": eid, "addr": addr, "confidence": confidence,
            "priority": 0.5, "updated_at": 1}


# ---------------------------------------------------------------------------
# assemble() pipeline
# ---------------------------------------------------------------------------

class TestAssemble:
    def test_compact_mode_touches_no_heavy_backends(self):
        obj = _make_assembler()  # no embedder/classifier at all
        pack = obj.assemble(
            "code", "decompile", {"code": "void f(void) { api(); }" * 20},
            "0x1000", "s1", "", mode="compact",
        )
        assert pack == {}

    def test_full_decompile_pipeline_with_fakes(self, tmp_path):
        idb = str(tmp_path / "fake.idb")
        emb = _FakeEmbedder()
        cls = _FakeClassifier()
        obj = _make_assembler(embedder=emb, classifier=cls)
        bb = _FakeBBStore(
            addr_entries=[_entry("a1", "0x1000")],
            sem_entries=[_entry("s1", "0x9000", 0.7)],
        )
        idx = obj._get_index(idb)
        idx.cache_store("0x402000", [1.0, 0.0, 0.0, 0.0])
        with idx._conn() as conn:
            conn.execute(
                """INSERT INTO func_embeddings
                   (ea, name, dim, vec_blob, pseudo_hash, indexed_at)
                   VALUES (?,?,?,?,?,?)""",
                ("0x402000", "similar_fn", 4, idx._pack([1.0, 0.0, 0.0, 0.0]),
                 "h", time.time()),
            )
            conn.commit()

        pack = obj.assemble(
            "code", "decompile",
            {"code": "void target(void) { connect(); }" * 20, "name": "sub_1000"},
            "0x1000", "s1", idb, bb_store=bb,
        )
        assert pack["related_findings"][0]["retrieval_source"] == "address_linked"
        assert pack["behavior_tags"] == ["network"]
        assert pack["suggested_next_actions"][0]["action"] == "callers"
        assert pack["similar_functions"][0]["ea"] == "0x402000"
        assert pack["retrieval_stats"]["address_linked"]["total"] == 1
        assert pack["retrieval_stats"]["semantic_linked"]["total"] == 1
        assert "stuck" not in pack
        # The embedder and classifier were actually exercised.
        assert cls.calls
        # The indexing side effect landed in the DB (async persist).
        row = None
        for _ in range(50):
            with idx._conn() as conn:
                row = conn.execute(
                    "SELECT name, document_text FROM func_embeddings WHERE ea=?", ("0x1000",)
                ).fetchone()
            if row is not None:
                break
            time.sleep(0.02)
        assert row is not None and row[0] == "sub_1000"
        assert row[1].startswith("void target(void)")

    def test_request_persist_restamps_freshness_after_own_commit(self, tmp_path):
        obj = _make_assembler(embedder=_FakeEmbedder())
        idx = obj._get_index(str(tmp_path / "fresh.idb"))
        assert obj._schedule_embedding_persist(
            idx, "0x1000", "target", [1.0, 0.0, 0.0, 0.0],
            "hash", "void target(void)", "sig-hash", "void target(void) { return; }",
        ) is True

        for _ in range(50):
            with idx._conn() as conn:
                row = conn.execute(
                    "SELECT document_text FROM func_embeddings WHERE ea=?", ("0x1000",)
                ).fetchone()
            if row is not None and not idx.db_changed_since_load():
                break
            time.sleep(0.02)
        assert row is not None
        assert idx.db_changed_since_load() is False

    def test_request_persist_skips_when_gate_is_saturated(self, tmp_path, monkeypatch):
        obj = _make_assembler(
            embedder=_FakeEmbedder(),
            _persist_gate=threading.Semaphore(0),
        )
        idx = obj._get_index(str(tmp_path / "fake.idb"))

        class _UnexpectedThread:
            def __init__(self, *args, **kwargs):
                raise AssertionError("saturated persistence must not spawn a thread")

        monkeypatch.setattr(context_mod.threading, "Thread", _UnexpectedThread)
        assert obj._schedule_embedding_persist(
            idx, "0x1000", "target", [1.0, 0.0, 0.0, 0.0],
            "hash", "void target(void)", "sig-hash", "void target(void) { return; }",
        ) is False
        with idx._conn() as conn:
            assert conn.execute(
                "SELECT 1 FROM func_embeddings WHERE ea=?", ("0x1000",)
            ).fetchone() is None

    def test_search_enrichment_and_next_targets(self, tmp_path):
        idb = str(tmp_path / "fake.idb")
        obj = _make_assembler(embedder=_FakeEmbedder())
        idx = obj._get_index(idb)
        idx.cache_store("0x401000", [0.5, 0.5, 0.5, 0.5])  # already analyzed
        with idx._conn() as conn:
            conn.execute(
                """INSERT INTO func_embeddings
                   (ea, name, dim, vec_blob, pseudo_hash, indexed_at,
                    func_size, bb_count, has_loops, api_count, string_count,
                    segment, cyclomatic)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("0x402000", "candidate_fn", 4, idx._pack([0.5, 0.5, 0.5, 0.5]),
                 "h", time.time(), 100, 5, 1, 2, 3, ".text", 4),
            )
            conn.commit()
        for i in range(4):  # 5th call triggers next-target suggestion
            obj.record_call("s1", "search", "find", f"0x1{i:03x}")

        pack = obj.assemble(
            "search", "find", {"matches": ["0x402000"]},
            "0x1000", "s1", idb,
        )
        assert pack["hit_details"][0]["ea"] == "0x402000"
        assert pack["hit_details"][0]["size"] == 100
        assert pack["suggested_targets"][0]["ea"] == "0x402000"
        assert pack["suggested_targets"][0]["name"] == "candidate_fn"
        assert pack["stuck"]["type"] == "repeated_tool"
        # Related-address graph recorded the hit for future cross-address recall.
        assert "0x402000" in obj._related_addr_graph["s1"]["0x1000"]

    def test_stuck_reported_in_full_mode(self):
        obj = _make_assembler()
        for _i in range(3):
            obj.record_call("s1", "code", "decompile", "0x1000")
        pack = obj.assemble("code", "decompile", {}, "0x1000", "s1", "")
        assert pack["stuck"]["type"] == "repeated_address"


# ---------------------------------------------------------------------------
# enrichment helpers
# ---------------------------------------------------------------------------

class TestBehaviorClassifier:
    def test_rebinds_when_embedder_changed(self, monkeypatch):
        created: list = []

        class _StubBC:
            def __init__(self, embedder):
                self._embedder = embedder

            def classify(self, *a, **k):
                return []

        class _StubBehaviorClassifier:
            @classmethod
            def instance(cls, embedder):
                created.append(embedder)
                return _StubBC(embedder)

        monkeypatch.setattr(context_mod, "BehaviorClassifier", _StubBehaviorClassifier)
        obj = _make_assembler(embedder="embA")
        obj._classifier = _StubBC("embB")  # stale embedder -> rebind
        assert obj._behavior_classifier()._embedder == "embA"
        assert created == ["embA"]

    def test_creates_when_missing(self, monkeypatch):
        created: list = []

        class _StubBC:
            def __init__(self, embedder):
                self._embedder = embedder

            def classify(self, *a, **k):
                return []

        monkeypatch.setattr(
            context_mod, "BehaviorClassifier",
            type("BC", (), {"instance": classmethod(lambda cls, e: created.append(e) or _StubBC(e))}),
        )
        obj = _make_assembler(embedder="embA")
        assert obj._behavior_classifier()._embedder == "embA"
        assert created == ["embA"]

    def test_keeps_matching_embedder(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            context_mod, "BehaviorClassifier",
            type("BC", (), {"instance": classmethod(lambda cls, e: calls.append(e))}),
        )
        obj = _make_assembler(embedder="embA")
        obj._classifier = _FakeClassifier()
        obj._classifier._embedder = "embA"
        assert obj._behavior_classifier() is obj._classifier
        assert calls == []


class TestIndexAndBlackboard:
    def test_get_index_creates_and_caches(self, tmp_path):
        obj = _make_assembler(embedder=_FakeEmbedder())
        i1 = obj._get_index(str(tmp_path / "a.idb"))
        i2 = obj._get_index(str(tmp_path / "a.idb"))
        assert i1 is i2
        assert i1._db_path == str(tmp_path / "a.idb.embeddings.db")

    def test_get_bb_entries_paths(self):
        obj = _make_assembler()
        assert obj._get_bb_entries("0x1000", None) == []
        assert obj._get_bb_entries("", _FakeBBStore(addr_entries=[_entry("a", "0x1")])) == []
        bb = _FakeBBStore(addr_entries=[_entry("a", "0x1000"), _entry("b", "0x1000")])
        assert [e["id"] for e in obj._get_bb_entries("0x1000", bb)] == ["a", "b"]

        class _BrokenBB:
            def list(self, **kwargs):
                raise RuntimeError("boom")

        assert obj._get_bb_entries("0x1000", _BrokenBB()) == []

    def test_get_bb_by_related_addresses_dedup_and_cap(self):
        obj = _make_assembler()
        obj._related_addr_graph["s1"]["0x1000"] = {"0x2000", "0x3000"}
        e1, e2, e3 = _entry("e1", "0x2000"), _entry("e2", "0x2000"), _entry("e3", "0x2000")
        bb = _FakeBBStore(by_addr={"0x2000": [e1, e2, e3], "0x3000": [dict(e3), _entry("e4", "0x3000")]})
        out = obj._get_bb_by_related_addresses("s1", "0x1000", bb, top_k=4)
        assert {e["id"] for e in out} == {"e1", "e2", "e3", "e4"}
        assert len(out) == 4  # duplicate e3 from the second neighbor skipped
        # top_k caps early
        out2 = obj._get_bb_by_related_addresses("s1", "0x1000", bb, top_k=2)
        assert len(out2) == 2
        # no neighbors / no session / no store
        assert obj._get_bb_by_related_addresses("s2", "0x1000", bb) == []
        assert obj._get_bb_by_related_addresses("s1", "0x1000", None) == []
        assert obj._get_bb_by_related_addresses("", "0x1000", bb) == []
        assert obj._get_bb_by_related_addresses("s1", "", bb) == []


class TestEnrichAddressList:
    def _seeded(self, tmp_path) -> tuple[ContextAssembler, str]:
        idb = str(tmp_path / "fake.idb")
        obj = _make_assembler(embedder=_FakeEmbedder())
        idx = obj._get_index(idb)
        idx.cache_store("0x401000", [0.5, 0.5, 0.5, 0.5])
        with idx._conn() as conn:
            conn.execute(
                """INSERT INTO func_embeddings
                   (ea, name, dim, vec_blob, pseudo_hash, indexed_at,
                    func_size, bb_count, has_loops, api_count, string_count,
                    segment, cyclomatic)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("0x402000", "candidate_fn", 4, idx._pack([0.5, 0.5, 0.5, 0.5]),
                 "h", time.time(), 100, 5, 1, 2, 3, ".text", 4),
            )
            conn.commit()
        return obj, idb

    def test_returns_structural_metadata(self, tmp_path):
        obj, idb = self._seeded(tmp_path)
        out = obj._enrich_address_list(["0x402000"], idb)
        assert out[0]["ea"] == "0x402000"
        assert out[0]["name"] == "candidate_fn"
        assert out[0]["size"] == 100
        assert out[0]["bb_count"] == 5
        assert out[0]["has_loops"] is True
        assert out[0]["api_count"] == 2
        assert out[0]["segment"] == ".text"
        assert out[0]["cyclomatic"] == 4

    def test_empty_and_invalid_inputs(self, tmp_path):
        obj, idb = self._seeded(tmp_path)
        assert obj._enrich_address_list([], idb) == []
        assert obj._enrich_address_list(["0x402000"], "") == []
        assert obj._enrich_address_list(["not-an-address"], idb) == []
        assert obj._enrich_address_list(["0x999999"], idb) == []

    def test_empty_index_returns_empty(self, tmp_path):
        idb = str(tmp_path / "fresh.idb")
        obj = _make_assembler(embedder=_FakeEmbedder())
        assert obj._enrich_address_list(["0x402000"], idb) == []


class TestSuggestNextTargets:
    def test_empty_paths(self, tmp_path):
        obj = _make_assembler(embedder=_FakeEmbedder())
        assert obj.suggest_next_targets("") == []
        assert obj.suggest_next_targets(str(tmp_path / "fresh.idb")) == []

    def test_excludes_analyzed_and_returns_limited(self, tmp_path):
        idb = str(tmp_path / "fake.idb")
        obj = _make_assembler(embedder=_FakeEmbedder())
        idx = obj._get_index(idb)
        idx.cache_store("0x401000", [0.5, 0.5, 0.5, 0.5])
        with idx._conn() as conn:
            for i in range(3):
                ea = f"0x40{i+2}000"
                conn.execute(
                    """INSERT INTO func_embeddings
                       (ea, name, dim, vec_blob, pseudo_hash, indexed_at,
                        func_size, bb_count, has_loops, api_count)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (ea, f"fn_{i}", 4, idx._pack([0.5, 0.5, 0.5, 0.5]),
                     "h", time.time(), 100, 5, 1, 2),
                )
            conn.commit()
        out = obj.suggest_next_targets(idb, limit=2)
        assert len(out) == 2
        assert {r["ea"] for r in out} == {"0x402000", "0x403000"}
        assert out[0]["interest_score"] == 0.5
        assert "size=100" in out[0]["reason"]


class TestActivityAndHousekeeping:
    def test_record_call_trims_to_50(self):
        obj = _make_assembler()
        for i in range(55):
            obj.record_call("s1", "code", "decompile", f"0x{i:04x}")
        log = obj._activity["s1"]
        assert len(log) == 50
        assert log[-1]["addr"] == "0x0036"

    def test_check_stuck_default_pivots(self):
        obj = _make_assembler()
        for i in range(5):
            obj.record_call("s1", "code", "blocks", f"0x{i:04x}")
        result = obj.check_stuck("s1", "0x9999", "code", "blocks")
        assert result["type"] == "repeated_tool"
        assert result["pivot_suggestions"] == [
            "blackboard(action='list') — review what you've found so far",
            "predictor(action='suggest_focus') — get focus suggestions",
        ]

    def test_housekeeping_throttle_lock_and_prune(self):
        obj = _make_assembler(_related_graph_max_edges=4)
        graph = obj._related_addr_graph["s1"]
        graph["0x1"].add("0x2")
        graph["0x2"].add("0x1")
        graph["0x3"].add("0x4")
        graph["0x4"].add("0x3")

        # Throttled: last run within 30s.
        obj._last_housekeeping_ts = time.time()
        obj._run_housekeeping("s1")
        assert sum(len(v) for v in graph.values()) == 4

        # Lock held elsewhere: skips.
        obj._last_housekeeping_ts = 0.0
        obj._housekeeping_lock.acquire()
        try:
            obj._run_housekeeping("s1")
        finally:
            obj._housekeeping_lock.release()
        assert sum(len(v) for v in graph.values()) == 4

        # Now it prunes down to the bound.
        obj._run_housekeeping("s1")
        assert sum(len(v) for v in obj._related_addr_graph["s1"].values()) <= 4


class TestQuantileAndPerf:
    def test_quantile_falls_back_when_helper_raises(self, monkeypatch):
        monkeypatch.setattr(
            context_mod._helpers, "quantile",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        obj = _make_assembler()
        assert obj._quantile([1.0], 0.5, default=2.5) == 2.5

    def test_perf_buckets_respect_profile_flag(self, monkeypatch):
        obj = _make_assembler()
        t0 = obj._perf_start()
        monkeypatch.setattr(core_mod, "INTEL_PROFILE", True)
        obj._perf_end("s1", "assemble", t0)
        obj._perf_end("s1", "assemble", t0)
        assert obj._perf_buckets["s1"]["assemble.count"] == 2
        assert obj._perf_buckets["s1"]["assemble.max_ms"] >= 0.0
        monkeypatch.setattr(core_mod, "INTEL_PROFILE", False)
        obj._perf_end("s1", "assemble", t0)
        assert obj._perf_buckets["s1"]["assemble.count"] == 2


class TestLifecycleSurface:
    def test_status_stop_and_ensure(self, tmp_path):
        emb = _FakeEmbedder()
        obj = _make_assembler(embedder=emb)
        obj._get_index(str(tmp_path / "x.idb"))
        st = obj.status
        assert st["backend"] == "fake"
        assert st["model_ready"] is True
        assert st["embed_dim"] == 4
        assert str(tmp_path / "x.idb") in st["indexes"]
        assert st["embed_batch_size"] == 2
        assert obj.ensure_embedding_server() is True
        assert emb.ensure_calls == 1
        obj.stop()
        assert emb.stopped is True
