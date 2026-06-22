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


def test_llm_payload_builders_produce_action_uncertainty_and_evidence():
    asm = ContextAssembler()
    pack = {
        "api_calls": ["VirtualAllocEx", "WriteProcessMemory"],
        "structural": {"entropy": 6.7, "xor_count": 5},
        "related_findings": [{"title": "Process injection", "retrieval_source": "api_linked"}],
        "analysis_focus": {"tool": "code", "action": "callers", "addr": "0x401000", "reason": "expand"},
        "analysis_focus_alternatives": [{"tool": "search", "action": "api", "pattern": "VirtualAllocEx", "reason": "pivot"}],
        "retrieval_stats": {"semantic_threshold": 0.7},
    }
    card = asm._build_llm_action_card(pack, "0x401000")
    unc = asm._build_llm_uncertainty(pack)
    evid = asm._build_llm_evidence_snippets(pack)

    assert card["primary"]["call"]["tool"] == "code"
    assert unc["risk"] in ("medium", "high")
    assert evid and len(evid) >= 3


def test_llm_contract_failover_and_style_guard_shapes():
    asm = ContextAssembler()
    pack = {
        "analysis_focus": {"tool": "code", "action": "callers", "addr": "0x401000", "reason": "expand"},
        "analysis_focus_alternatives": [
            {"tool": "search", "action": "api", "pattern": "VirtualAllocEx", "reason": "pivot"}
        ],
        "llm_evidence": [{"fact": "API observed: VirtualAllocEx", "source": "decompile/api_extract"}],
        "llm_uncertainty": {"risk": "high", "checks": ["semantic_circuit_open"]},
    }
    contract = asm._build_llm_tool_call_contract(pack, "0x401000")
    failover = asm._build_llm_failover_route(pack, "0x401000")
    style = asm._build_llm_response_style_guard(pack)

    assert contract["format"] == "json"
    assert contract["primary"]["tool"] == "code"
    assert failover and failover[0]["call"]["tool"] == "search"
    assert style["mode"] == "cautious"


def test_compiled_plan_budget_and_mode_profiles_are_emitted():
    asm = ContextAssembler()
    pack = {
        "api_calls": ["VirtualAllocEx", "WriteProcessMemory"],
        "structural": {"entropy": 6.9},
        "llm_evidence": [{"fact": "API observed", "source": "x"}],
        "llm_uncertainty": {"risk": "high", "checks": ["semantic_circuit_open"]},
    }
    plan = asm._compile_question_tool_plan(pack, "0x401000")
    budget = asm._evidence_budget_gate(pack, "0x401000")
    mode = asm._mode_profile(pack)
    esc = asm._dead_end_escalation("sess-z", "0x401000", pack)

    assert plan["intent"] == "malware_triage"
    assert budget["claim_blocked"] is True
    assert mode["mode"] in ("triage_mode", "firmware_mode", "analysis_mode")
    assert "loop_detected" in esc


def test_record_call_outcome_updates_mcp_value_score():
    asm = ContextAssembler()
    sess = "sess-score"
    asm._record_call_outcome(sess, {"related_findings": []})
    s1 = asm._mcp_value_score(sess, {})
    asm._record_call_outcome(sess, {"related_findings": [{"id": "x"}]})
    s2 = asm._mcp_value_score(sess, {"related_findings": [{"id": "x"}]})
    assert s2 >= s1


def test_ten_llm_feature_payload_builders_shapes():
    asm = ContextAssembler()
    pack = {
        "api_calls": ["VirtualAllocEx", "WriteProcessMemory"],
        "related_findings": [{"title": "Process injection"}],
        "structural": {"entropy": 6.6},
        "llm_action_card": {"primary": {"call": {"tool": "code", "action": "callers", "addr": "0x401000"}}},
        "llm_failover_route": [{"call": {"tool": "search", "action": "api", "pattern": "VirtualAllocEx"}}],
        "evidence_budget": {"claim_blocked": True},
    }
    addr = "0x401000"
    assert asm._llm_query_intent(pack)["intent"]
    assert "required_min" in asm._llm_required_evidence_sources(pack)
    assert "safe_claim" in asm._llm_claim_templates()
    assert asm._llm_call_sequence(pack, addr)
    assert "must_refuse_definitive_claim" in asm._llm_refusal_policy(pack)
    assert "avoid_repeating" in asm._llm_tool_cooldowns("sess-any")
    assert asm._llm_context_capsule(pack, addr)["addr"] == addr
    assert asm._llm_verification_checklist(pack, addr)
    assert isinstance(asm._llm_next_best_question(pack), str)
    assert asm._llm_auto_notes(pack)


def test_llm_nudge_requires_call_when_gate_is_active():
    asm = ContextAssembler()
    pack = {
        "must_call_before_answer": True,
        "required_followup_call": {"tool": "code", "action": "callers", "addr": "0x401000"},
    }
    n = asm._build_llm_nudge(pack, "0x401000")
    assert n["must_call"] is True
    assert n["required_call"]["tool"] == "code"
    assert "Run required MCP call now" in " ".join(n["protocol"])


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
    import sys
    import types
    active_core = sys.modules.get("ida_pro_mcp.host.intelligence.core", intel_mod)
    
    # Scan for all core module objects in memory
    core_modules = set()
    for mod in list(sys.modules.values()):
        if isinstance(mod, types.ModuleType):
            file_path = getattr(mod, "__file__", "") or ""
            name = getattr(mod, "__name__", "") or ""
            if "intelligence/core.py" in file_path or name.endswith("intelligence.core") or name == "ida_pro_mcp.host.intelligence_core":
                core_modules.add(mod)
            for attr_val in list(mod.__dict__.values()):
                if isinstance(attr_val, types.ModuleType):
                    f = getattr(attr_val, "__file__", "") or ""
                    n = getattr(attr_val, "__name__", "") or ""
                    if "intelligence/core.py" in f or n.endswith("intelligence.core") or n == "ida_pro_mcp.host.intelligence_core":
                        core_modules.add(attr_val)
                        
    core_modules.add(active_core)
    core_modules.add(intel_mod)
    
    old_values = {}
    for m in core_modules:
        old_values[m] = getattr(m, "INTEL_PROFILE", False)
        m.INTEL_PROFILE = True

    try:
        asm = ContextAssembler()
        sess = "sess-perf"
        t0 = asm._perf_start()
        asm._perf_end(sess, "assemble", t0)
        health = asm._collect_intelligence_health(sess)
        assert "perf" in health
        assert "assemble" in health["perf"]
    finally:
        for m, val in old_values.items():
            m.INTEL_PROFILE = val


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


def test_semantic_candidates_prioritize_api_overlap_and_confidence():
    asm = ContextAssembler()
    entries = [
        {"id": "e1", "confidence": 0.4, "updated_at": 10, "tags": ["foo"]},
        {"id": "e2", "confidence": 0.3, "updated_at": 10, "tags": ["VirtualAllocEx"]},
        {"id": "e3", "confidence": 0.9, "updated_at": 1, "tags": []},
    ]
    out = asm._semantic_candidates(entries, ["VirtualAllocEx"], max_entries=2)
    ids = [e.get("id") for e in out]
    assert "e2" in ids
    assert "e3" in ids


def test_semantic_result_cache_avoids_repeated_scoring_pass():
    asm = ContextAssembler()
    asm._embedder = _FakeEmbedder()
    bb = _FakeBlackboardStore()
    q = [1.0, 0.0]
    sess = "sess-sem-cache"

    _ = asm._get_bb_semantic_vec(q, bb, top_k=2, threshold=0.1, max_entries=6, api_calls=["VirtualAllocEx"], session_id=sess)
    with asm._bb_cache_stats_lock:
        miss1 = asm._bb_cache_misses
        hit1 = asm._bb_cache_hits
    _ = asm._get_bb_semantic_vec(q, bb, top_k=2, threshold=0.1, max_entries=6, api_calls=["VirtualAllocEx"], session_id=sess)
    with asm._bb_cache_stats_lock:
        miss2 = asm._bb_cache_misses
        hit2 = asm._bb_cache_hits

    # second request should be served from semantic result cache path
    assert miss2 == miss1
    assert hit2 == hit1


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
