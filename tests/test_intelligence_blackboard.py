import os
import sys
import tempfile
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ida_pro_mcp.host.intelligence as intel_mod
from ida_pro_mcp.host.intelligence import ContextAssembler
from ida_pro_mcp.host.intelligence_helpers import prune_policy_store


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
    ids = {f.get("id") for f in findings}
    assert "inj1" in ids
    assert any(f.get("retrieval_source") in ("api_linked", "semantic_linked", "address_linked", "relation_linked") for f in findings)
    assert "retrieval_stats" in pack


def test_semantic_blackboard_vectors_are_cached():
    asm = ContextAssembler()
    embedder = _FakeEmbedder()
    asm._embedder = embedder
    bb = _FakeBlackboardStore()
    q = embedder.embed("VirtualAllocEx WriteProcessMemory")

    out1 = asm._get_bb_semantic_vec(q, bb, top_k=3, threshold=0.1, max_entries=10)
    cache_after_first = len(asm._bb_entry_vec_cache)
    out2 = asm._get_bb_semantic_vec(q, bb, top_k=3, threshold=0.1, max_entries=10)
    cache_after_second = len(asm._bb_entry_vec_cache)

    assert out1
    assert out2
    assert cache_after_first > 0
    assert cache_after_second == cache_after_first


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


def test_retrieval_stats_hit_rate_shape():
    asm = ContextAssembler()
    pack = {}
    e1 = {"id": "a", "confidence": 0.9, "updated_at": 1}
    e2 = {"id": "b", "confidence": 0.2, "updated_at": 1}
    asm._merge_related_findings(pack, [e1, e2], "api_linked", session_id="sess-m")
    stats = asm._session_retrieval_stats("sess-m")
    assert "api_linked" in stats
    assert stats["api_linked"]["total"] == 2
    assert stats["api_linked"]["accepted"] >= 1
    assert stats["api_linked"]["kept"] >= 1
    assert 0.0 <= stats["api_linked"]["accept_rate"] <= 1.0
    assert 0.0 <= stats["api_linked"]["hit_rate"] <= 1.0
    assert "semantic_threshold" in stats
    assert "source_policy" in stats
    assert "api_linked" in stats["source_policy"]


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


def test_source_policy_hardens_low_hit_source():
    asm = ContextAssembler()
    sess = "sess-pol"
    # Repeated low-confidence semantic entries should trigger stricter policy.
    weak = {"title": "weak", "confidence": 0.1, "updated_at": 1}
    for _ in range(8):
        asm._merge_related_findings({}, [weak], "semantic_linked", session_id=sess)
    policy = asm._session_source_policy(sess)
    sem = policy["semantic_linked"]
    assert sem["min_confidence"] >= 0.45
    assert sem["max_take"] <= 4


def test_analysis_focus_prefers_relation_pivot_when_relation_signal_is_strong():
    asm = ContextAssembler()
    sess = "sess-focus"
    # Create enough relation-linked signal to raise hit-rate.
    entry = {"id": "r1", "confidence": 0.9, "updated_at": 10}
    pack = {"related_findings": [entry], "structural": {}}
    for _ in range(8):
        asm._merge_related_findings(pack, [entry], "relation_linked", session_id=sess)

    focus = asm._derive_analysis_focus(pack, "0x401000", sess)
    assert focus is not None
    assert focus["tool"] == "code"
    assert focus["action"] == "callers"


def test_analysis_focus_falls_back_to_structural_blocks_on_high_entropy():
    asm = ContextAssembler()
    pack = {
        "related_findings": [],
        "structural": {"entropy": 6.8, "xor_count": 1, "cyclomatic_complexity": 6},
        "api_calls": [],
    }
    focus = asm._derive_analysis_focus(pack, "0x402000", "sess-struct")
    assert focus is not None
    assert focus["tool"] == "code"
    assert focus["action"] == "blocks"


def test_focus_feedback_closed_loop_updates_stats():
    asm = ContextAssembler()
    sess = "sess-loop"
    focus = {"tool": "code", "action": "callers", "addr": "0x401000", "score": 1.2}
    asm._record_focus_suggestion(sess, focus)

    followed = asm._consume_focus_follow(sess, "code", "callers")
    assert followed is True
    asm._record_focus_outcome(sess, "code", "callers", success=True)

    fb = asm._focus_feedback_stats(sess)
    assert fb["suggested"] == 1
    assert fb["followed"] == 1
    assert fb["successful"] == 1
    assert fb["success_rate"] == 1.0
    assert "per_action" in fb
    assert "code:callers" in fb["per_action"]


def test_focus_action_bias_reflects_per_action_success_history():
    asm = ContextAssembler()
    sess = "sess-bias"

    # Build enough samples to move bias above neutral for callers.
    for _ in range(4):
        asm._record_focus_outcome(sess, "code", "callers", success=True)
    for _ in range(1):
        asm._record_focus_outcome(sess, "code", "callers", success=False)

    bias = asm._focus_action_bias(sess, "code", "callers")
    assert bias > 1.0


def test_policy_persistence_roundtrip_across_instances():
    with tempfile.TemporaryDirectory() as td:
        idb_path = os.path.join(td, "sample.idb")
        sess = "sess-persist"

        asm1 = ContextAssembler()
        asm1._load_session_policy(sess, idb_path)
        asm1._merge_related_findings({}, [{"id": "x1", "confidence": 0.8}], "api_linked", session_id=sess)
        asm1._record_focus_suggestion(sess, {"tool": "code", "action": "callers"})
        asm1._consume_focus_follow(sess, "code", "callers")
        asm1._record_focus_outcome(sess, "code", "callers", success=True)
        asm1._save_session_policy(sess)

        asm2 = ContextAssembler()
        asm2._load_session_policy(sess, idb_path)
        stats = asm2._session_retrieval_stats(sess)
        fb = asm2._focus_feedback_stats(sess)

        assert "api_linked" in stats
        assert stats["api_linked"]["total"] >= 1
        assert fb["suggested"] >= 1
        assert fb["successful"] >= 1


def test_policy_compaction_keeps_top_action_stats_and_caps_sessions():
    asm = ContextAssembler()
    # Build oversized fake store
    data = {"schema_version": 1, "sessions": {}}
    for i in range(40):
        sid = f"s{i}"
        ff = {"suggested": i + 1, "followed": i, "successful": i // 2, "failed": i // 3}
        # Add many action counters; compaction should cap them.
        for j in range(60):
            ff[f"action.tool{j}:act.ok"] = j + 1
            ff[f"action.tool{j}:act.fail"] = j
        data["sessions"][sid] = {
            "retrieval_metrics": {
                "api_linked.total": 10,
                "api_linked.accepted": 8,
                "api_linked.kept": 5,
                "junk.metric": 999,
            },
            "focus_feedback": ff,
            "semantic_threshold": 0.9,
            "saved_at": float(i),
        }

    pruned = asm._prune_policy_store(data, max_sessions=24)
    assert pruned.get("schema_version") == 2
    sessions = pruned.get("sessions") or {}
    assert len(sessions) <= 24
    # Most recent session should be preserved and compacted.
    assert "s39" in sessions
    blob = sessions["s39"]
    assert blob.get("semantic_threshold") <= 0.75
    assert "junk.metric" not in (blob.get("retrieval_metrics") or {})
    ff2 = blob.get("focus_feedback") or {}
    action_keys = [k for k in ff2 if k.startswith("action.")]
    assert len(action_keys) <= 48


def test_helper_prune_policy_store_standalone():
    data = {"schema_version": 1, "sessions": {"s1": {"saved_at": 1.0}, "s2": {"saved_at": 2.0}}}
    out = prune_policy_store(data, max_sessions=1)
    assert out.get("schema_version") == 2
    assert len(out.get("sessions") or {}) == 1
    assert "s2" in (out.get("sessions") or {})


def test_housekeeping_expires_stale_pending_focus():
    asm = ContextAssembler()
    sess = "sess-hk"
    asm._pending_focus_ttl_sec = 0.01
    asm._record_focus_suggestion(sess, {"tool": "code", "action": "callers"})
    # Force stale timestamp and housekeeping run.
    asm._pending_focus[sess]["ts"] = asm._pending_focus[sess]["ts"] - 1.0
    asm._last_housekeeping_ts = 0.0
    asm._run_housekeeping(sess)
    assert sess not in asm._pending_focus


def test_intelligence_health_exposes_cache_and_threshold():
    asm = ContextAssembler()
    sess = "sess-health"
    asm._session_semantic_threshold[sess] = 0.55
    health = asm._collect_intelligence_health(sess)
    assert "bb_cache" in health
    assert "relation_graph" in health
    assert health.get("semantic_threshold") == 0.55


def test_analysis_focus_alternatives_are_ranked():
    asm = ContextAssembler()
    pack = {
        "related_findings": [{"id": "r1", "confidence": 0.9}],
        "structural": {"entropy": 6.9, "xor_count": 5, "cyclomatic_complexity": 20},
        "api_calls": ["VirtualAllocEx"],
    }
    cands = asm._derive_focus_candidates(pack, "0x401000", "sess-alt")
    assert cands
    assert len(cands) >= 2
    assert float(cands[0]["score"]) >= float(cands[1]["score"])


def test_focus_explainability_has_margin_with_runner_up():
    asm = ContextAssembler()
    cands = [
        {"tool": "code", "action": "callers", "score": 1.4, "reason": "r1"},
        {"tool": "search", "action": "api", "score": 1.1, "reason": "r2"},
    ]
    ex = asm._focus_explainability(cands)
    assert ex.get("selected") == "code:callers"
    assert ex.get("runner_up") == "search:api"
    assert float(ex.get("score_margin") or 0.0) > 0


def test_semantic_circuit_breaker_opens_for_persistently_weak_signal():
    asm = ContextAssembler()
    sess = "sess-cb"
    # Build weak semantic stats and low cache hit rate.
    with asm._retrieval_metrics_lock:
        asm._retrieval_metrics[sess]["semantic_linked.total"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.accepted"] = 20
        asm._retrieval_metrics[sess]["semantic_linked.kept"] = 1
    with asm._bb_cache_stats_lock:
        asm._bb_cache_hits = 0
        asm._bb_cache_misses = 30
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


def test_intelligence_health_perf_block_when_profile_enabled():
    old = intel_mod.INTEL_PROFILE
    intel_mod.INTEL_PROFILE = True
    try:
        asm = ContextAssembler()
        sess = "sess-perf"
        t0 = asm._perf_start()
        asm._perf_end(sess, "assemble", t0)
        health = asm._collect_intelligence_health(sess)
        assert "perf" in health
        assert "assemble" in health["perf"]
    finally:
        intel_mod.INTEL_PROFILE = old


def test_debounced_policy_save_and_flush_persists_file():
    with tempfile.TemporaryDirectory() as td:
        idb_path = os.path.join(td, "debounce.idb")
        sess = "sess-debounce"
        asm = ContextAssembler()
        asm._policy_save_debounce_sec = 0.05
        asm._load_session_policy(sess, idb_path)
        asm._merge_related_findings({}, [{"id": "d1", "confidence": 0.9}], "api_linked", session_id=sess)
        asm.flush_policy_saves(sess)
        time.sleep(0.08)
        p = idb_path + ".focus_policy.json"
        assert os.path.exists(p)
