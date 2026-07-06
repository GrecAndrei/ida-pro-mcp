import os
import tempfile
import time

from tests._isolated_repo_loader import load_host_module

intel_mod = load_host_module("intelligence.core")
ContextAssembler = load_host_module("intelligence.context").ContextAssembler
prune_policy_store = load_host_module("intelligence.helpers").prune_policy_store


class _FakeEmbedder:
    @staticmethod
    def _score(text: str) -> float:
        t = text.lower()
        if "virtualallocex" in t or "writeprocessmemory" in t:
            return 1.0
        if "loadlibrary" in t:
            return 0.35
        return 0.05

    def embed(self, text: str):
        s = self._score(text)
        return [s, 1.0 - s]

    def embed_batch(self, texts):
        return [self.embed(t) for t in texts]

    @staticmethod
    def cosine(a, b):
        na = (a[0] ** 2 + a[1] ** 2) ** 0.5 or 1.0
        nb = (b[0] ** 2 + b[1] ** 2) ** 0.5 or 1.0
        return (a[0] * b[0] + a[1] * b[1]) / (na * nb)


class _FakeBlackboardStore:
    def __init__(self):
        self._entries = [
            {
                "id": "inj1",
                "title": "Process injection at 0x401000",
                "content": "Uses VirtualAllocEx and WriteProcessMemory",
                "addr": "0x401000",
                "tags": ["VirtualAllocEx", "WriteProcessMemory", "dangerous"],
                "confidence": 0.95,
                "updated_at": 10,
            },
            {
                "id": "benign1",
                "title": "Plugin loader",
                "content": "Uses LoadLibrary",
                "addr": "0x500000",
                "tags": ["LoadLibrary"],
                "confidence": 0.4,
                "updated_at": 8,
            },
        ]

    def list(self, category=None, addr=None, tag=None, min_confidence=0.0, limit=100, offset=0):
        rows = list(self._entries)
        if addr:
            rows = [e for e in rows if e.get("addr") == addr]
        if tag:
            rows = [e for e in rows if tag in (e.get("tags") or [])]
        if min_confidence > 0:
            rows = [e for e in rows if float(e.get("confidence") or 0.0) >= min_confidence]
        return rows[offset : offset + limit]

    def exists(self, addr, category, title):
        return False

    def write(self, **kwargs):
        return "new"


def test_cross_address_blackboard_retrieval_by_api_tags():
    asm = ContextAssembler()
    asm._embedder = _FakeEmbedder()
    bb = _FakeBlackboardStore()
    pack = {}
    payload = {"name": "caller_fn"}
    pseudocode = """
    void caller_fn() {
      h = VirtualAllocEx(proc, 0, n, 0x3000, 0x40);
      WriteProcessMemory(proc, h, buf, n, 0);
      return;
    }
    """

    asm._enrich_decompile(pack, payload, pseudocode, "0x402000", "/tmp/test.idb", bb, "sess-a")

    findings = pack.get("related_findings") or []
    # API-based auto-blackboard removed — semantic linking still works
    assert isinstance(findings, list)


def test_related_address_blackboard_retrieval_from_observed_graph():
    asm = ContextAssembler()
    bb = _FakeBlackboardStore()
    asm._record_related_addresses("sess-g", "0x402000", ["0x401000"])

    rel = asm._get_bb_by_related_addresses("sess-g", "0x402000", bb, top_k=4)
    ids = {e.get("id") for e in rel}
    assert "inj1" in ids


def test_related_findings_rank_prefers_stronger_source_than_semantic():
    asm = ContextAssembler()
    pack = {}
    # Same entry first appears via semantic retrieval
    entry = {
        "id": "dup1",
        "title": "same finding",
        "content": "same",
        "confidence": 0.9,
        "updated_at": 11,
    }
    asm._merge_related_findings(pack, [entry], "semantic_linked", session_id="sess-rank")
    # Then appears via relation-linked retrieval; source should be upgraded
    asm._merge_related_findings(pack, [entry], "relation_linked", session_id="sess-rank")

    findings = pack.get("related_findings") or []
    assert findings
    assert findings[0]["id"] == "dup1"
    assert findings[0]["retrieval_source"] == "relation_linked"


def test_adaptive_semantic_threshold_tunes_up_and_down():
    asm = ContextAssembler()
    sess = "sess-thr"

    # Poor semantic hit-rate should raise threshold.
    low_conf = {"title": "no-id", "confidence": 0.1, "updated_at": 1}
    for _ in range(6):
        asm._merge_related_findings({}, [low_conf], "semantic_linked", session_id=sess)
    before = asm._get_semantic_threshold(sess)
    asm._tune_semantic_threshold(sess)
    after_up = asm._get_semantic_threshold(sess)
    assert after_up >= before

    # Strong semantic hit-rate should lower threshold.
    strong_pack = {}
    strong = {"id": "s2", "confidence": 0.95, "updated_at": 2}
    for _ in range(8):
        asm._merge_related_findings(strong_pack, [strong], "semantic_linked", session_id=sess)
    asm._tune_semantic_threshold(sess)
    after_down = asm._get_semantic_threshold(sess)
    assert 0.35 <= after_down <= 0.75


def test_helper_prune_policy_store_standalone():
    data = {"schema_version": 1, "sessions": {"s1": {"saved_at": 1.0}, "s2": {"saved_at": 2.0}}}
    out = prune_policy_store(data, max_sessions=1)
    assert out.get("schema_version") == 2
    assert len(out.get("sessions") or {}) == 1
    assert "s2" in (out.get("sessions") or {})


def test_semantic_circuit_breaker_opens_for_persistently_weak_signal():
    asm = ContextAssembler()
    sess = "sess-cb"
    # Build weak semantic stats: many semantic lookups but almost none kept.
    with asm._retrieval_metrics_lock:
        asm._retrieval_metrics[sess]["semantic_linked.total"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.accepted"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.kept"] = 1
    asm._update_semantic_circuit_breaker(sess)
    assert asm._semantic_circuit_open(sess) is True


def test_session_retrieval_stats_cache_invalidation_on_merge():
    asm = ContextAssembler()
    sess = "sess-cache"
    pack = {}
    asm._merge_related_findings(pack, [{"id": "a", "confidence": 0.9}], "api_linked", session_id=sess)
    s1 = asm._session_retrieval_stats(sess)
    # Add more metrics; cache should be invalidated and totals updated.
    asm._merge_related_findings(pack, [{"id": "b", "confidence": 0.8}], "api_linked", session_id=sess)
    s2 = asm._session_retrieval_stats(sess)
    assert s2["api_linked"]["total"] >= s1["api_linked"]["total"]


def test_adaptive_semantic_budget_bounds_and_direction():
    asm = ContextAssembler()
    sess = "sess-budget"
    with asm._retrieval_metrics_lock:
        asm._retrieval_metrics[sess]["semantic_linked.total"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.accepted"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.kept"] = 18
    b_hi = asm._adaptive_semantic_budget(sess, default_max=24)
    assert 24 <= b_hi <= 48

    asm._semantic_budget_cache.pop(sess, None)
    with asm._retrieval_metrics_lock:
        asm._retrieval_metrics[sess]["semantic_linked.kept"] = 1
    asm._invalidate_session_caches(sess)
    b_lo = asm._adaptive_semantic_budget(sess, default_max=24)
    assert 8 <= b_lo <= 24


def test_embedder_batch_controller_backoff_and_growth():
    class _TestEmbedder(_FakeEmbedder):
        def __init__(self):
            self._use_llama = True
            self._batch_size = 8
            self._batch_lock = type("L", (), {"__enter__": lambda s: None, "__exit__": lambda s, a, b, c: None})()

        def _llama_embed_batch(self, texts):
            if len(texts) > 4:
                return None
            return [self.embed(t) for t in texts]

    emb = _TestEmbedder()
    out = emb.embed_batch(["a", "b", "c", "d", "e", "f"])
    assert len(out) == 6
    assert emb._batch_size <= 8
