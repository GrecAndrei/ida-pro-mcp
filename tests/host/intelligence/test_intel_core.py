"""Regression tests for the f11_intel_core session-lifecycle fixes.

Covers, for host/intelligence/context.py:

  * drop_session teardown hook (state must not leak past session death and
    must not contaminate a reused session id)
  * malformed blackboard entries must not abort the whole context pack
  * the every-5-calls target-suggestion gate must stay every-5 past the
    50-entry activity cap (it previously degraded to every call)
  * housekeeping pruning must hold the last-seen lock and keep active sessions
  * removal of the dead ``seen_act`` guard (next-action suggestion is now a
    single deterministic entry)
  * empty/whitespace session ids must not accumulate shared per-session state
  * cross-session isolation, asserted through public observable outputs
    (relation_linked findings in the context pack) rather than private
    attributes

All tests drive the in-memory control plane with fake embedder/classifier/
blackboard doubles — no IDA, no model, no subprocess.
"""

from __future__ import annotations

import collections
import threading
import time

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

    def classify(self, text, threshold=0.25, top_k=4, block=True):
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


def _seed_candidate(obj: ContextAssembler, idb: str) -> None:
    """Seed one un-analyzed candidate function in the embedding index."""
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


# ── finding 1 (medium): session teardown hook ──────────────────────────────

class TestDropSession:
    def test_drop_session_clears_all_per_session_state(self):
        obj = _make_assembler()
        obj.record_call("s1", "code", "decompile", "0x1000")
        obj._related_addr_graph["s1"]["0x1000"].add("0x2000")
        obj._retrieval_metrics["s1"]["address_linked.total"] = 5
        obj._session_semantic_threshold["s1"] = 0.7
        obj._semantic_circuit_breaker_until["s1"] = int(time.time()) + 100
        obj._semantic_budget_cache["s1"] = (time.time(), 20)
        obj._perf_buckets["s1"]["assemble.count"] = 3.0
        obj._session_stats_cache["s1"] = (time.time(), {"x": 1})
        obj._session_last_seen["s1"] = time.time()

        obj.drop_session("s1")

        assert "s1" not in obj._activity
        assert "s1" not in obj._related_addr_graph
        assert "s1" not in obj._retrieval_metrics
        assert "s1" not in obj._session_semantic_threshold
        assert "s1" not in obj._semantic_circuit_breaker_until
        assert "s1" not in obj._semantic_budget_cache
        assert "s1" not in obj._perf_buckets
        assert "s1" not in obj._session_stats_cache
        assert "s1" not in obj._session_last_seen

    def test_drop_session_leaves_other_sessions_untouched(self):
        obj = _make_assembler()
        obj.record_call("s1", "code", "decompile", "0x1000")
        obj.record_call("s2", "code", "decompile", "0x2000")
        obj._session_semantic_threshold["s2"] = 0.6

        obj.drop_session("s1")

        assert "s1" not in obj._activity
        assert "s2" in obj._activity
        assert obj._session_semantic_threshold["s2"] == 0.6
        assert obj.check_stuck("s2", "0x2000", "code", "decompile") is None

    def test_drop_session_prevents_reused_id_contamination(self):
        obj = _make_assembler()
        # First life of session "s1": saturated activity + an adapted threshold.
        for _i in range(4):
            obj.record_call("s1", "code", "decompile", "0x1000")
        obj._session_semantic_threshold["s1"] = 0.85

        obj.drop_session("s1")

        # A fresh session reusing the id starts clean.
        assert obj.check_stuck("s1", "0x1000", "code", "decompile") is None
        assert obj._get_semantic_threshold("s1") == 0.5

    def test_drop_session_is_idempotent(self):
        obj = _make_assembler()
        obj.record_call("s1", "code", "decompile", "0x1000")
        obj.drop_session("s1")
        obj.drop_session("s1")  # must not raise
        obj.drop_session("never-existed")
        assert "s1" not in obj._activity


# ── finding 2 (medium): malformed blackboard entries ───────────────────────

class TestMalformedBlackboardEntries:
    def test_merge_failure_does_not_drop_context_pack(self):
        obj = _make_assembler(embedder=_FakeEmbedder(), classifier=_FakeClassifier())
        bb = _FakeBBStore(addr_entries=[
            {"id": "bad", "addr": "0x1000", "confidence": 0.9,
             "priority": 0.5, "updated_at": "not-a-number"},
            {"id": "ok", "addr": "0x1000", "confidence": 0.9,
             "priority": 0.5, "updated_at": 1},
        ])
        pack = obj.assemble(
            "code", "decompile", {"code": "void f(void) { api(); }" * 20},
            "0x1000", "s1", "", bb_store=bb,
        )
        # The merge step fails on the malformed entry, but the rest of the
        # context pack is still assembled (previously the exception aborted
        # assemble() entirely and the caller swallowed it).
        assert pack["behavior_tags"] == ["network"]
        assert pack["suggested_next_actions"][0]["action"] == "callers"
        assert "related_findings" not in pack


# ── finding 3 (medium): every-5-calls gate past the activity cap ───────────

class TestTargetSuggestionGate:
    def test_gate_fires_every_5_not_every_call_after_activity_cap(self, tmp_path):
        idb = str(tmp_path / "fake.idb")
        obj = _make_assembler(embedder=_FakeEmbedder())
        _seed_candidate(obj, idb)
        # Saturate the per-session activity log past its 50-entry cap.
        for i in range(55):
            obj.record_call("s1", "search", "find", f"0x{i:04x}")

        # Call 56: 56 % 5 != 0 -> no suggestion.  Regression: pre-fix every
        # call after the cap fired because len(log) was pinned at 50.
        pack = obj.assemble(
            "search", "find", {"matches": ["0x402000"]},
            "0x1000", "s1", idb,
        )
        assert "suggested_targets" not in pack

        # Calls 57-59, then call 60 fires (60 % 5 == 0) even past the cap.
        for i in range(3):
            obj.record_call("s1", "search", "find", f"0x{i + 100:04x}")
        pack = obj.assemble(
            "search", "find", {"matches": ["0x402000"]},
            "0x1000", "s1", idb,
        )
        assert pack["suggested_targets"][0]["ea"] == "0x402000"
        assert pack["suggested_targets"][0]["name"] == "candidate_fn"


# ── finding 4 (low): housekeeping lock / stale-prune discipline ────────────

class TestHousekeeping:
    def test_prunes_stale_sessions_and_keeps_active(self):
        obj = _make_assembler()
        now = time.time()
        # "stale" idled more than 10 minutes ago.
        obj.record_call("stale", "code", "decompile", "0x1000")
        obj._session_last_seen["stale"] = now - 1000.0
        obj._related_addr_graph["stale"]["0x1"].add("0x2")
        obj._session_semantic_threshold["stale"] = 0.7
        # "active" was seen recently.
        obj.record_call("active", "code", "decompile", "0x2000")
        obj._session_last_seen["active"] = now - 5.0

        obj._last_housekeeping_ts = 0.0
        obj._run_housekeeping("s1")

        assert "stale" not in obj._session_last_seen
        assert "stale" not in obj._activity
        assert "stale" not in obj._related_addr_graph
        assert "stale" not in obj._session_semantic_threshold
        assert "active" in obj._session_last_seen
        assert "active" in obj._activity

    def test_prune_does_not_crash_when_no_stale_sessions(self):
        obj = _make_assembler()
        obj.record_call("s1", "code", "decompile", "0x1000")
        obj._last_housekeeping_ts = 0.0
        obj._run_housekeeping("s1")  # must not raise
        assert "s1" in obj._session_last_seen
        assert "s1" in obj._activity


# ── finding 5 (low): dead seen_act guard removed ───────────────────────────

class TestSuggestedNextActions:
    def test_single_deterministic_callers_entry(self):
        obj = _make_assembler(embedder=_FakeEmbedder(), classifier=_FakeClassifier())
        pack = obj.assemble(
            "code", "decompile", {"code": "void f(void) { api(); }" * 20},
            "0x1000", "s1", "",
        )
        assert pack["suggested_next_actions"] == [
            {"tool": "code", "action": "callers", "addr": "0x1000",
             "reason": "See what calls this function"},
        ]

    def test_absent_without_addr(self):
        obj = _make_assembler(embedder=_FakeEmbedder(), classifier=_FakeClassifier())
        pack = obj.assemble(
            "code", "decompile", {"code": "void f(void) { api(); }" * 20},
            "", "s1", "",
        )
        assert "suggested_next_actions" not in pack


# ── finding 6 (low): empty session id must not be tracked ──────────────────

class TestEmptySessionId:
    def test_record_call_ignores_empty_and_whitespace_ids(self):
        obj = _make_assembler()
        obj.record_call("", "code", "decompile", "0x1000")
        obj.record_call("   ", "code", "decompile", "0x1000")
        assert "" not in obj._activity
        assert "" not in obj._session_last_seen
        assert obj.check_stuck("", "0x1000", "code", "decompile") is None


# ── finding 7 (test_gap): isolation via public observables ─────────────────

class TestSessionIsolation:
    def test_sessions_are_isolated_for_stuck_detection(self):
        obj = _make_assembler()
        for _i in range(4):
            obj.record_call("s1", "code", "decompile", "0x1000")
        obj.record_call("s2", "code", "decompile", "0x2000")
        assert obj.check_stuck("s1", "0x1000", "code", "decompile")["type"] == "repeated_address"
        assert obj.check_stuck("s2", "0x2000", "code", "decompile") is None

    def test_related_address_recall_is_observable_via_public_pack(self, tmp_path):
        idb = str(tmp_path / "fake.idb")
        obj = _make_assembler(embedder=_FakeEmbedder(), classifier=_FakeClassifier())
        bb = _FakeBBStore(by_addr={"0x2000": [_entry("r1", "0x2000")]})
        # A search surfaces 0x2000 as related to the anchor 0x1000.
        obj.assemble(
            "search", "find", {"matches": ["0x2000"]},
            "0x1000", "s1", idb, bb_store=bb,
        )
        # A later decompile at the anchor recalls the relation-linked finding
        # through the public context pack (the behavior previously asserted via
        # the private _related_addr_graph attribute).
        pack = obj.assemble(
            "code", "decompile", {"code": "void f(void) { api(); }" * 20},
            "0x1000", "s1", idb, bb_store=bb,
        )
        sources = [r.get("retrieval_source") for r in pack.get("related_findings", [])]
        assert "relation_linked" in sources
        assert any(r.get("id") == "r1" for r in pack.get("related_findings", []))
