"""
Context assembly layer for IDA Pro MCP.

Extracted from intelligence.py so the core embedding / classifier / memory
backends can live in a smaller dedicated module.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    BgeCodeEmbedder,
    BehaviorClassifier,
    EMBED_DIM,
    FunctionEmbeddingIndex,
    _extract_signature,
)
from .context_policy import ContextAssemblerPolicyMixin
from .context_semantic import ContextAssemblerSemanticMixin
from .structural_index import get_db_path
from . import helpers as _helpers
from .api_patterns import (
    ALL_INTERESTING_APIS,
    actions_from_apis,
    actions_from_schemaboot,
    detect_crypto_constants,
    extract_api_calls,
    extract_string_refs,
)


def _intel_profile_enabled() -> bool:
    """Look up the canonical symbol at call time so tests/runtime can toggle
    the profile flag by mutating the module attribute on intelligence_core."""
    from . import core as intelligence_core
    return bool(intelligence_core.INTEL_PROFILE)


class ContextAssembler(
    ContextAssemblerSemanticMixin,
    ContextAssemblerPolicyMixin,
):
    """
    Per-call context assembly.  Replaces cognitive_layer, cartographer_mu,
    and attention_kernel with a clean, honest pipeline:

      1. Blackboard: addr-matched past findings
      2. Embedding similarity: similar functions in this binary
      3. Zero-shot behavior classification: what does this function do?
      4. Rule-based next actions: what should the LLM do next?
      5. Stuck detection: has the LLM been spinning here?

    Produces a compact `context_pack` injected into every relevant response.
    """

    def __init__(self):
        self._embedder   = BgeCodeEmbedder()
        # Shared singleton classifier — anchors loaded once across all instances
        self._classifier = BehaviorClassifier.instance(self._embedder)
        # Per-binary embedding indexes keyed by idb_path
        self._indexes: Dict[str, FunctionEmbeddingIndex] = {}
        self._idx_lock   = threading.Lock()
        # Activity tracking for stuck detection (in-memory, per session)
        self._activity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._activity_lock = threading.Lock()
        self._related_addr_graph: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._related_addr_lock = threading.Lock()
        self._retrieval_metrics: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._retrieval_metrics_lock = threading.Lock()
        self._session_semantic_threshold: Dict[str, float] = {}
        self._semantic_threshold_lock = threading.Lock()
        self._focus_feedback: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._focus_feedback_lock = threading.Lock()
        self._pending_focus: Dict[str, Dict[str, Any]] = {}
        self._pending_focus_lock = threading.Lock()
        self._session_call_outcomes: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._session_call_outcomes_lock = threading.Lock()
        self._session_store_binding: Dict[str, str] = {}
        self._store_binding_lock = threading.Lock()
        # Cache blackboard entry embeddings by stable key to avoid repeated
        # re-embedding the same rows on every decompile call.
        self._bb_entry_vec_cache: Dict[str, Tuple[List[float], float]] = {}
        self._bb_entry_vec_cache_lock = threading.Lock()
        self._bb_entry_cache_ttl_sec = 900.0
        self._bb_entry_cache_max = 4000
        self._bb_cache_hits = 0
        self._bb_cache_misses = 0
        self._bb_cache_stats_lock = threading.Lock()
        self._last_housekeeping_ts = 0.0
        self._housekeeping_lock = threading.Lock()
        self._pending_focus_ttl_sec = 420.0
        self._related_graph_max_edges = 1200
        self._semantic_circuit_breaker_until: Dict[str, int] = {}
        self._circuit_breaker_lock = threading.Lock()
        self._session_stats_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._stats_cache_lock = threading.Lock()
        self._stats_cache_ttl_sec = 1.5
        self._source_policy_cache: Dict[str, Tuple[Tuple[int, int, int, int], Dict[str, Dict[str, Any]]]] = {}
        self._policy_cache_lock = threading.Lock()
        self._perf_buckets: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._perf_lock = threading.Lock()
        self._policy_save_due_at: Dict[str, float] = {}
        self._policy_save_inflight: set = set()
        self._policy_save_lock = threading.Lock()
        self._policy_save_debounce_sec = 0.35
        self._semantic_result_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._semantic_result_cache_lock = threading.Lock()
        self._semantic_result_cache_ttl_sec = 3.0
        self._semantic_budget_cache: Dict[str, Tuple[float, int]] = {}
        self._semantic_budget_lock = threading.Lock()

    # ── helpers ─────────────────────────────────────────────────────────

    def _behavior_classifier(self) -> BehaviorClassifier:
        """Return the shared classifier, re-binding it if the embedder changed.

        Test doubles can inject a classifier without an `_embedder` attribute;
        those are left untouched so unit tests can isolate the enrichment path.
        """
        classifier = getattr(self, "_classifier", None)
        if classifier is None:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
            return classifier
        classifier_embedder = getattr(classifier, "_embedder", None)
        if classifier_embedder is not None and classifier_embedder is not self._embedder:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
        return classifier

    def _get_index(self, idb_path: str) -> FunctionEmbeddingIndex:
        with self._idx_lock:
            if idb_path not in self._indexes:
                db = idb_path + ".embeddings.db"
                self._indexes[idb_path] = FunctionEmbeddingIndex(db, self._embedder)
        return self._indexes[idb_path]

    # ── blackboard retrieval ──────────────────────────────────────────────

    def _get_bb_entries(self, addr: str, bb_store) -> List[Dict[str, Any]]:
        """Fetch blackboard entries relevant to this address."""
        if bb_store is None or not addr:
            return []
        try:
            entries = bb_store.list(addr=addr, limit=5)
            return entries or []
        except Exception:
            return []

    def _merge_related_findings(
        self,
        pack: Dict[str, Any],
        entries: List[Dict[str, Any]],
        source: str,
        session_id: str = "",
    ) -> None:
        """
        Merge findings into pack['related_findings'] with deterministic ranking.

        Ranking priority:
          1) evidence source: address_linked > relation_linked > api_linked > semantic_linked
          2) confidence
          3) updated_at recency
        """
        if not entries:
            return
        policy = self._session_source_policy(session_id) if session_id else {}
        p_src = policy.get(source, {}) if isinstance(policy, dict) else {}
        min_conf = float(p_src.get("min_confidence", 0.0) or 0.0)
        max_take = int(p_src.get("max_take", 8) or 8)
        weight = float(p_src.get("weight", 1.0) or 1.0)
        filtered_entries = [
            e for e in entries
            if float(e.get("confidence") or 0.0) >= min_conf
        ]
        if max_take > 0:
            filtered_entries = sorted(
                filtered_entries,
                key=lambda e: (
                    float(e.get("confidence") or 0.0),
                    float(e.get("updated_at") or 0.0),
                ),
                reverse=True,
            )[:max_take]
        if not filtered_entries:
            return
        src_rank = {
            "address_linked": 4,
            "relation_linked": 3,
            "api_linked": 2,
            "semantic_linked": 1,
        }
        merged: Dict[str, Dict[str, Any]] = {}
        for existing in pack.get("related_findings", []):
            e = dict(existing)
            e.setdefault("retrieval_source", "address_linked")
            merged[str(e.get("id") or hashlib.md5(json.dumps(e, sort_keys=True).encode()).hexdigest())] = e
        for entry in filtered_entries:
            e = dict(entry)
            e["retrieval_source"] = source
            e["retrieval_weight"] = round(weight, 3)
            key = str(e.get("id") or hashlib.md5(json.dumps(e, sort_keys=True).encode()).hexdigest())
            prev = merged.get(key)
            if prev is None:
                merged[key] = e
                continue
            prev_rank = src_rank.get(str(prev.get("retrieval_source") or "semantic_linked"), 0)
            new_rank = src_rank.get(source, 0)
            if new_rank > prev_rank:
                merged[key] = e
                continue
            if new_rank == prev_rank:
                if float(e.get("confidence") or 0.0) > float(prev.get("confidence") or 0.0):
                    merged[key] = e

        ranked = sorted(
            merged.values(),
            key=lambda x: (
                src_rank.get(str(x.get("retrieval_source") or "semantic_linked"), 0),
                float(x.get("retrieval_weight") or 1.0),
                float(x.get("confidence") or 0.0),
                float(x.get("updated_at") or 0.0),
            ),
            reverse=True,
        )
        pack["related_findings"] = ranked[:8]
        if session_id:
            try:
                with self._retrieval_metrics_lock:
                    metrics = self._retrieval_metrics[session_id]
                    key_total = f"{source}.total"
                    key_accepted = f"{source}.accepted"
                    key_kept = f"{source}.kept"
                    metrics[key_total] = int(metrics.get(key_total, 0)) + len(entries)
                    metrics[key_accepted] = int(metrics.get(key_accepted, 0)) + len(filtered_entries)
                    kept = sum(1 for e in filtered_entries if any(
                        (r.get("id") and r.get("id") == e.get("id"))
                        for r in pack.get("related_findings", [])
                    ))
                    metrics[key_kept] = int(metrics.get(key_kept, 0)) + kept
                self._invalidate_session_caches(session_id)
                self._schedule_policy_save(session_id)
            except Exception:
                pass

    def _invalidate_session_caches(self, session_id: str) -> None:
        if not session_id:
            return
        with self._stats_cache_lock:
            self._session_stats_cache.pop(session_id, None)
        with self._policy_cache_lock:
            self._source_policy_cache.pop(session_id, None)
        with self._semantic_result_cache_lock:
            if session_id:
                stale = [k for k in self._semantic_result_cache.keys() if k.startswith(f"{session_id}:")]
                for k in stale[:128]:
                    self._semantic_result_cache.pop(k, None)

    def _perf_start(self) -> float:
        return time.perf_counter()

    def _perf_end(self, session_id: str, bucket: str, t0: float) -> None:
        if not _intel_profile_enabled() or not session_id:
            return
        dt_ms = (time.perf_counter() - t0) * 1000.0
        with self._perf_lock:
            b = self._perf_buckets[session_id]
            b[f"{bucket}.count"] = float(b.get(f"{bucket}.count", 0.0) + 1.0)
            b[f"{bucket}.sum_ms"] = float(b.get(f"{bucket}.sum_ms", 0.0) + dt_ms)
            b[f"{bucket}.max_ms"] = max(float(b.get(f"{bucket}.max_ms", 0.0)), dt_ms)

    def _session_retrieval_stats(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            return {}
        try:
            now = time.time()
            with self._stats_cache_lock:
                cached = self._session_stats_cache.get(session_id)
                if cached and (now - cached[0] <= self._stats_cache_ttl_sec):
                    return dict(cached[1])
            with self._retrieval_metrics_lock:
                metrics = dict(self._retrieval_metrics.get(session_id, {}))
            if not metrics:
                return {}
            out: Dict[str, Any] = {}
            sources = ["address_linked", "relation_linked", "api_linked", "semantic_linked"]
            for src in sources:
                total = int(metrics.get(f"{src}.total", 0))
                accepted = int(metrics.get(f"{src}.accepted", 0))
                kept = int(metrics.get(f"{src}.kept", 0))
                if total <= 0:
                    continue
                out[src] = {
                    "total": total,
                    "accepted": accepted,
                    "kept": kept,
                    "accept_rate": round(accepted / max(1, total), 3),
                    "hit_rate": round(kept / max(1, total), 3),
                }
            out["semantic_threshold"] = self._get_semantic_threshold(session_id)
            out["source_policy"] = self._session_source_policy(session_id)
            out["focus_feedback"] = self._focus_feedback_stats(session_id)
            with self._stats_cache_lock:
                self._session_stats_cache[session_id] = (now, dict(out))
            return out
        except Exception:
            return {}

    def _focus_feedback_stats(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            return {}
        try:
            with self._focus_feedback_lock:
                m = dict(self._focus_feedback.get(session_id, {}))
            suggested = int(m.get("suggested", 0))
            followed = int(m.get("followed", 0))
            successful = int(m.get("successful", 0))
            failed = int(m.get("failed", 0))
            out: Dict[str, Any] = {
                "suggested": suggested,
                "followed": followed,
                "successful": successful,
                "failed": failed,
                "follow_rate": round(followed / max(1, suggested), 3),
                "success_rate": round(successful / max(1, followed), 3),
            }
            action_stats: Dict[str, Dict[str, float]] = {}
            for k, v in m.items():
                if not k.startswith("action."):
                    continue
                # action.<tool:action>.<ok|fail>
                parts = k.split(".")
                if len(parts) != 3:
                    continue
                ta = parts[1]
                bucket = action_stats.setdefault(ta, {"ok": 0.0, "fail": 0.0})
                bucket[parts[2]] = float(v)
            if action_stats:
                per_action = {}
                for ta, vals in action_stats.items():
                    ok = vals.get("ok", 0.0)
                    fail = vals.get("fail", 0.0)
                    total = ok + fail
                    if total <= 0:
                        continue
                    per_action[ta] = {
                        "success_rate": round(ok / total, 3),
                        "samples": int(total),
                    }
                if per_action:
                    out["per_action"] = per_action
            return out
        except Exception:
            return {}

    def _run_housekeeping(self, session_id: str) -> None:
        """Periodic cleanup for pending focus and relation graph bounds."""
        now = time.time()
        if now - self._last_housekeeping_ts < 30.0:
            return
        if not self._housekeeping_lock.acquire(blocking=False):
            return
        try:
            self._last_housekeeping_ts = now
            # Expire stale pending focus suggestions.
            with self._pending_focus_lock:
                stale = [
                    sid for sid, rec in self._pending_focus.items()
                    if now - float(rec.get("ts") or 0.0) > self._pending_focus_ttl_sec
                ]
                for sid in stale:
                    self._pending_focus.pop(sid, None)

            # Bound relation graph size per session.
            if session_id:
                with self._related_addr_lock:
                    graph = self._related_addr_graph.get(session_id)
                    if graph:
                        total_edges = sum(len(v) for v in graph.values())
                        if total_edges > self._related_graph_max_edges:
                            # Drop smallest-degree nodes first.
                            nodes = sorted(graph.items(), key=lambda kv: len(kv[1]))
                            drop_budget = total_edges - self._related_graph_max_edges
                            for node, nbrs in nodes:
                                if drop_budget <= 0:
                                    break
                                drop_budget -= len(nbrs)
                                graph.pop(node, None)
        except Exception:
            pass
        finally:
            self._housekeeping_lock.release()

    def _collect_intelligence_health(self, session_id: str) -> Dict[str, Any]:
        """Compact health telemetry for adaptive intelligence quality."""
        out: Dict[str, Any] = {}
        try:
            with self._bb_cache_stats_lock:
                hits = int(self._bb_cache_hits)
                misses = int(self._bb_cache_misses)
            total = hits + misses
            out["bb_cache"] = {
                "entries": len(self._bb_entry_vec_cache),
                "hit_rate": round(hits / max(1, total), 3),
                "ops": total,
            }
            with self._pending_focus_lock:
                pending = self._pending_focus.get(session_id, {}) if session_id else {}
            if pending:
                age = time.time() - float(pending.get("ts") or time.time())
                out["pending_focus"] = {
                    "tool": pending.get("tool"),
                    "action": pending.get("action"),
                    "age_sec": round(age, 2),
                }
            with self._related_addr_lock:
                rel_nodes = len(self._related_addr_graph.get(session_id, {})) if session_id else 0
            out["relation_graph"] = {"nodes": rel_nodes}
            out["semantic_cache"] = {"entries": len(self._semantic_result_cache)}
            with self._policy_save_lock:
                out["policy_save_queue"] = len(self._policy_save_due_at)
            if session_id:
                out["semantic_threshold"] = self._get_semantic_threshold(session_id)
                out["semantic_circuit_open"] = self._semantic_circuit_open(session_id)
                out["semantic_budget"] = self._adaptive_semantic_budget(session_id, default_max=24)
                if _intel_profile_enabled():
                    with self._perf_lock:
                        b = dict(self._perf_buckets.get(session_id, {}))
                    perf = {}
                    for k in ("assemble", "decompile_enrich", "search_enrich"):
                        c = float(b.get(f"{k}.count", 0.0))
                        s = float(b.get(f"{k}.sum_ms", 0.0))
                        m = float(b.get(f"{k}.max_ms", 0.0))
                        if c > 0:
                            perf[k] = {"avg_ms": round(s / c, 3), "max_ms": round(m, 3), "count": int(c)}
                    if perf:
                        out["perf"] = perf
        except Exception:
            return {}
        return out


    def _build_llm_action_card(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """
        Compact, execution-ready card intended for direct LLM consumption.
        Keeps one primary call + two fallbacks with concrete args.
        """
        focus = pack.get("analysis_focus") or {}
        alts = list(pack.get("analysis_focus_alternatives") or [])
        primary = None
        if focus.get("tool") and focus.get("action"):
            primary = {
                "call": {
                    "tool": focus.get("tool"),
                    "action": focus.get("action"),
                    "addr": focus.get("addr") or addr,
                    "pattern": focus.get("pattern"),
                },
                "why": focus.get("reason") or "best next step",
            }
        fallbacks = []
        for a in alts[:2]:
            if not (a.get("tool") and a.get("action")):
                continue
            fallbacks.append(
                {
                    "call": {
                        "tool": a.get("tool"),
                        "action": a.get("action"),
                        "addr": a.get("addr") or addr,
                        "pattern": a.get("pattern"),
                    },
                    "why": a.get("reason") or "fallback",
                }
            )
        return {
            "primary": primary,
            "fallbacks": fallbacks,
            "stop_condition": "stop when new related_findings or hit_details appear",
        }

    def _build_llm_uncertainty(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        """Expose explicit uncertainty so LLM can avoid over-claiming."""
        risk = "low"
        checks: List[str] = []
        rf = pack.get("related_findings") or []
        if len(rf) == 0:
            checks.append("no_related_findings")
        sem_thr = float(((pack.get("retrieval_stats") or {}).get("semantic_threshold") or 0.5))
        sem_open = bool(((pack.get("intelligence_health") or {}).get("semantic_circuit_open")))
        if sem_open:
            checks.append("semantic_circuit_open")
        if sem_thr >= 0.65:
            checks.append("strict_semantic_threshold")
        if checks:
            risk = "medium"
        if "semantic_circuit_open" in checks and len(rf) == 0:
            risk = "high"
        return {
            "risk": risk,
            "checks": checks,
            "instruction": "state uncertainty and run primary action before concluding behavior",
        }

    def _build_llm_evidence_snippets(self, pack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Small provenance-tied facts for LLM responses."""
        out: List[Dict[str, Any]] = []
        for api in (pack.get("api_calls") or [])[:5]:
            out.append({"fact": f"API observed: {api}", "source": "decompile/api_extract"})
        st = pack.get("structural") or {}
        if st.get("entropy") is not None:
            out.append({"fact": f"Entropy: {st.get('entropy')}", "source": "schemaboot"})
        if st.get("xor_count"):
            out.append({"fact": f"XOR count: {st.get('xor_count')}", "source": "schemaboot"})
        for f in (pack.get("related_findings") or [])[:3]:
            ttl = str(f.get("title") or "finding")
            out.append({"fact": ttl, "source": f"blackboard/{f.get('retrieval_source') or 'unknown'}"})
        return out[:8]

    def _build_llm_tool_call_contract(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Strict call contract the LLM can emit with low ambiguity."""
        focus = pack.get("analysis_focus") or {}
        primary = {
            "tool": focus.get("tool") or "code",
            "action": focus.get("action") or "callers",
            "addr": focus.get("addr") or addr,
        }
        if focus.get("pattern"):
            primary["pattern"] = focus.get("pattern")
        return {
            "format": "json",
            "required_fields": ["tool", "action"],
            "optional_fields": ["addr", "pattern", "limit"],
            "primary": primary,
            "example": {"tool": primary["tool"], "action": primary["action"], "addr": primary.get("addr")},
        }

    def _build_llm_failover_route(self, pack: Dict[str, Any], addr: str) -> List[Dict[str, Any]]:
        """Fallback route when primary call yields weak/empty signal."""
        alts = list(pack.get("analysis_focus_alternatives") or [])
        route = []
        for a in alts[:2]:
            if not (a.get("tool") and a.get("action")):
                continue
            route.append(
                {
                    "if": "primary_empty_or_low_signal",
                    "call": {
                        "tool": a.get("tool"),
                        "action": a.get("action"),
                        "addr": a.get("addr") or addr,
                        "pattern": a.get("pattern"),
                    },
                    "expect": "new hit_details or related_findings",
                }
            )
        if not route:
            route.append(
                {
                    "if": "primary_empty_or_low_signal",
                    "call": {"tool": "code", "action": "callees", "addr": addr},
                    "expect": "graph expansion",
                }
            )
        return route

    def _build_llm_response_style_guard(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        """Claim-style guardrails to keep LLM outputs evidence-backed."""
        evid_n = len(pack.get("llm_evidence") or [])
        unc = pack.get("llm_uncertainty") or {}
        risk = str(unc.get("risk") or "low")
        mode = "assertive" if evid_n >= 3 and risk == "low" else "cautious"
        return {
            "mode": mode,
            "must_include": [
                "at least one cited evidence fact",
                "explicit next verification call when uncertainty is medium/high",
            ],
            "forbidden": [
                "definitive malware/vuln claims without cited evidence",
                "omitting uncertainty when risk is high",
            ],
        }

    def _compile_question_tool_plan(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Embedding-driven question->tool first-step compiler for RE workflows."""
        apis = set(pack.get("api_calls") or [])
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            return {
                "intent": "malware_triage",
                "first_calls": [
                    {"tool": "code", "action": "callers", "addr": addr},
                    {"tool": "graph", "action": "call_chain", "addr": addr},
                ],
            }
        intent = (self._llm_query_intent(pack) or {}).get("intent", "function_understanding")
        if intent == "malware_behavior":
            return {
                "intent": "malware_triage",
                "first_calls": [
                    {"tool": "code", "action": "callers", "addr": addr},
                    {"tool": "graph", "action": "call_chain", "addr": addr},
                ],
            }
        if intent == "obfuscation_or_packer":
            return {
                "intent": "packed_or_obfuscated",
                "first_calls": [
                    {"tool": "code", "action": "blocks", "addr": addr},
                    {"tool": "search", "action": "semantic", "addr": addr},
                ],
            }
        return {
            "intent": "function_understanding",
            "first_calls": [
                {"tool": "code", "action": "decompile", "addr": addr},
                {"tool": "code", "action": "callers", "addr": addr},
            ],
        }

    def _evidence_budget_gate(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Block high-risk claims unless evidence budget is satisfied."""
        evid = list(pack.get("llm_evidence") or [])
        apis = set(pack.get("api_calls") or [])
        claim_type = "general"
        required = 1
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            claim_type = "malware_behavior"
            required = 2
        if any("overflow" in str(x.get("fact", "")).lower() for x in evid):
            claim_type = "vulnerability"
            required = 3
        met = len(evid) >= required
        out = {
            "claim_type": claim_type,
            "required_evidence": required,
            "observed_evidence": len(evid),
            "claim_blocked": not met,
        }
        if not met:
            out["required_followup_call"] = {"tool": "code", "action": "callers", "addr": addr}
        return out

    def _dead_end_escalation(self, session_id: str, addr: str, pack: Dict[str, Any]) -> Dict[str, Any]:
        with self._activity_lock:
            recent = list(self._activity.get(session_id, []))[-12:]
        if not recent:
            return {"loop_detected": False}
        same_addr = sum(1 for r in recent if r.get("addr") == addr)
        repetitive = sum(1 for r in recent if f"{r.get('tool')}:{r.get('action')}" in ("code:decompile", "search:semantic"))
        no_findings = not bool(pack.get("related_findings") or pack.get("hit_details"))
        loop = same_addr >= 4 and repetitive >= 4 and no_findings
        if not loop:
            return {"loop_detected": False}
        return {
            "loop_detected": True,
            "required_followup_call": {"tool": "graph", "action": "call_chain", "addr": addr},
            "secondary": {"tool": "firmware_view", "action": "campaign", "start": addr, "end": addr},
        }

    def _mcp_value_score(self, session_id: str, pack: Dict[str, Any]) -> float:
        with self._session_call_outcomes_lock:
            o = self._session_call_outcomes[session_id]
            calls = int(o.get("calls", 0))
            wins = int(o.get("wins", 0))
        base = wins / max(1, calls)
        lift = 0.1 if (pack.get("related_findings") or pack.get("hit_details")) else 0.0
        return round(min(1.0, base + lift), 3)

    def _record_call_outcome(self, session_id: str, pack: Dict[str, Any]) -> None:
        with self._session_call_outcomes_lock:
            o = self._session_call_outcomes[session_id]
            o["calls"] = int(o.get("calls", 0)) + 1
            if pack.get("related_findings") or pack.get("hit_details") or pack.get("analysis_focus"):
                o["wins"] = int(o.get("wins", 0)) + 1

    def _mode_profile(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        apis = set(pack.get("api_calls") or [])
        if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.intersection(apis):
            return {"mode": "triage_mode", "mandatory_sequence": ["code.decompile", "code.callers", "graph.call_chain"]}
        intent = (self._llm_query_intent(pack) or {}).get("intent", "")
        if intent == "malware_behavior":
            return {"mode": "triage_mode", "mandatory_sequence": ["code.decompile", "code.callers", "graph.call_chain"]}
        if intent == "obfuscation_or_packer":
            return {"mode": "firmware_mode", "mandatory_sequence": ["firmware_view.region_profile", "firmware_view.pointer_clusters", "firmware_view.carve_plan"]}
        return {"mode": "analysis_mode", "mandatory_sequence": ["code.decompile", "code.callers"]}

    # --- 10 LLM-first feature payloads ---
    def _llm_query_intent(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        apis = " ".join(pack.get("api_calls") or [])
        st = pack.get("structural") or {}
        structural = " ".join(
            [
                f"entropy={st.get('entropy', 0)}",
                f"xor_count={st.get('xor_count', 0)}",
                f"cyclomatic={st.get('cyclomatic_complexity', st.get('cyclomatic', 0))}",
                f"api_count={st.get('api_count', 0)}",
            ]
        )
        query = f"{apis} {structural}".strip() or "function reverse engineering context"
        anchors = {
            "malware_behavior": "process injection c2 beacon payload loader remote thread write process memory",
            "obfuscation_or_packer": "packed obfuscated encrypted xor decoder anti debug high entropy shellcode unpacking",
            "function_understanding": "normal business logic parser dispatcher validation computation control flow",
        }
        try:
            qv = self._embedder.embed(query[:1200])
            sims: List[Tuple[str, float]] = []
            for k, a in anchors.items():
                av = self._embedder.embed(a)
                sims.append((k, float(BgeCodeEmbedder.cosine(qv, av))))
            sims.sort(key=lambda x: x[1], reverse=True)
            top_intent, top_score = sims[0]
            return {"intent": top_intent, "confidence": round(max(0.0, min(1.0, top_score)), 3)}
        except Exception:
            # Deterministic fallback without fixed score heuristics.
            intent = "function_understanding"
            if pack.get("api_calls"):
                intent = "malware_behavior"
            elif pack.get("structural"):
                intent = "obfuscation_or_packer"
            return {"intent": intent, "confidence": 0.5}

    def _llm_required_evidence_sources(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        src = set()
        if pack.get("api_calls"):
            src.add("api_extract")
        if pack.get("structural"):
            src.add("schemaboot")
        if pack.get("related_findings"):
            src.add("blackboard")
        return {"required_min": 2, "observed": sorted(src), "met": len(src) >= 2}

    def _llm_claim_templates(self) -> Dict[str, str]:
        return {
            "safe_claim": "Observed: {facts}. Likely: {inference}. Verify with: {next_call}.",
            "uncertain_claim": "Signals are incomplete ({checks}). Run: {next_call} before concluding.",
        }

    def _llm_call_sequence(self, pack: Dict[str, Any], addr: str) -> List[Dict[str, Any]]:
        seq = []
        prim = ((pack.get("llm_action_card") or {}).get("primary") or {}).get("call") or {}
        if prim.get("tool") and prim.get("action"):
            seq.append({"step": 1, **prim})
        for i, fb in enumerate((pack.get("llm_failover_route") or [])[:2], start=2):
            c = fb.get("call") or {}
            if c.get("tool") and c.get("action"):
                seq.append({"step": i, **c})
        if not seq:
            seq.append({"step": 1, "tool": "code", "action": "callers", "addr": addr})
        return seq

    def _llm_refusal_policy(self, pack: Dict[str, Any]) -> Dict[str, Any]:
        blocked = bool((pack.get("evidence_budget") or {}).get("claim_blocked"))
        return {
            "must_refuse_definitive_claim": blocked,
            "reason": "insufficient_evidence" if blocked else "none",
        }

    def _llm_tool_cooldowns(self, session_id: str) -> Dict[str, Any]:
        with self._activity_lock:
            recent = list(self._activity.get(session_id, []))[-10:]
        counts: Dict[str, int] = {}
        for r in recent:
            k = f"{r.get('tool')}:{r.get('action')}"
            counts[k] = counts.get(k, 0) + 1
        cooled = [k for k, c in counts.items() if c >= 4]
        return {"avoid_repeating": cooled, "window": 10}

    def _llm_context_capsule(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        return {
            "addr": addr,
            "apis": (pack.get("api_calls") or [])[:5],
            "top_findings": [str(x.get("title") or "") for x in (pack.get("related_findings") or [])[:3]],
            "focus": ((pack.get("analysis_focus") or {}).get("action") or "unknown"),
        }

    def _llm_verification_checklist(self, pack: Dict[str, Any], addr: str) -> List[str]:
        checks = [
            f"run code.callers at {addr}",
            f"run graph.call_chain at {addr}",
        ]
        if not pack.get("related_findings"):
            checks.append("write one blackboard note for newly verified behavior")
        return checks

    def _llm_next_best_question(self, pack: Dict[str, Any]) -> str:
        if not pack.get("related_findings"):
            return "Which caller path reaches this behavior first?"
        if not pack.get("structural"):
            return "What structural signals (entropy/xor/loops) support this hypothesis?"
        return "What is the minimum evidence to confirm or refute this behavior?"

    def _llm_auto_notes(self, pack: Dict[str, Any]) -> List[str]:
        notes = []
        for f in (pack.get("related_findings") or [])[:2]:
            notes.append(f"note: {f.get('title')}")
        for a in (pack.get("api_calls") or [])[:2]:
            notes.append(f"api: {a}")
        return notes

    def _build_llm_nudge(self, pack: Dict[str, Any], addr: str) -> Dict[str, Any]:
        """Strong, explicit nudge that makes tool-first behavior obvious."""
        must_call = bool(pack.get("must_call_before_answer"))
        req = pack.get("required_followup_call") or ((pack.get("llm_action_card") or {}).get("primary") or {}).get("call") or {}
        call_txt = f"{req.get('tool')}.{req.get('action')}" if req.get("tool") and req.get("action") else "code.callers"
        protocol = [
            "Do not conclude yet.",
            f"Run required MCP call now: {call_txt}",
            "Only after call result, update hypothesis and confidence.",
        ]
        if not must_call:
            protocol = [
                "Prefer MCP-first: run one call before final answer.",
                f"Recommended call: {call_txt}",
                "Use returned evidence snippets in your conclusion.",
            ]
        return {
            "must_call": must_call,
            "required_call": req if req else {"tool": "code", "action": "callers", "addr": addr},
            "protocol": protocol,
            "short": protocol[1],
        }

    def _focus_explainability(self, cands: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Explain why top focus won vs alternatives."""
        if not cands:
            return {}
        top = cands[0]
        out: Dict[str, Any] = {
            "selected": f"{top.get('tool')}:{top.get('action')}",
            "selected_score": float(top.get("score") or 0.0),
            "selected_reason": top.get("reason") or "",
        }
        if len(cands) > 1:
            second = cands[1]
            out["runner_up"] = f"{second.get('tool')}:{second.get('action')}"
            out["score_margin"] = round(float(top.get("score") or 0.0) - float(second.get("score") or 0.0), 3)
        return out

    def _semantic_circuit_open(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._circuit_breaker_lock:
            return int(self._semantic_circuit_breaker_until.get(session_id, 0)) > int(time.time())

    @staticmethod
    def _quantile(vals: List[float], q: float, default: float = 0.0) -> float:
        """Deterministic quantile helper with sane fallback."""
        try:
            return _helpers.quantile(vals, q, default)
        except Exception:
            return float(default)

    def _semantic_quality_profile(self, session_id: str) -> Dict[str, float]:
        """
        Build adaptive semantic-quality profile from session telemetry.
        Avoids fixed cutoffs by deriving baselines from observed distributions.
        """
        stats = self._session_retrieval_stats(session_id) if session_id else {}
        rates: List[float] = []
        totals: List[int] = []
        for src in ("address_linked", "relation_linked", "api_linked", "semantic_linked"):
            bucket = stats.get(src) if isinstance(stats, dict) else None
            if not isinstance(bucket, dict):
                continue
            if "hit_rate" in bucket:
                rates.append(float(bucket.get("hit_rate") or 0.0))
            if "total" in bucket:
                totals.append(int(bucket.get("total") or 0))
        q25 = self._quantile(rates, 0.25, default=0.35)
        q50 = self._quantile(rates, 0.50, default=0.5)
        q75 = self._quantile(rates, 0.75, default=0.65)
        total_sum = sum(max(0, int(x)) for x in totals)
        total_med = self._quantile([float(x) for x in totals if x > 0], 0.50, default=6.0)
        min_total = max(4, int(round(min(total_med, max(6.0, total_sum / 4.0)))))
        health = self._collect_intelligence_health(session_id)
        perf = (health.get("perf") or {}) if isinstance(health, dict) else {}
        perf_avgs = [
            float(((perf.get(k) or {}).get("avg_ms") or 0.0))
            for k in ("assemble", "decompile_enrich", "search_enrich")
            if float(((perf.get(k) or {}).get("avg_ms") or 0.0)) > 0.0
        ]
        perf_q25 = self._quantile(perf_avgs, 0.25, default=20.0)
        perf_q50 = self._quantile(perf_avgs, 0.50, default=45.0)
        perf_q75 = self._quantile(perf_avgs, 0.75, default=75.0)
        return {
            "hit_q25": q25,
            "hit_q50": q50,
            "hit_q75": q75,
            "perf_q25": perf_q25,
            "perf_q50": perf_q50,
            "perf_q75": perf_q75,
            "min_total": float(min_total),
        }

    def _adaptive_semantic_budget(self, session_id: str, default_max: int = 24) -> int:
        """Dynamically tune semantic candidate budget using quality/perf signals."""
        if not session_id:
            return default_max
        now = time.time()
        with self._semantic_budget_lock:
            cached = self._semantic_budget_cache.get(session_id)
            if cached and (now - cached[0] <= 2.0):
                return int(cached[1])
        budget = int(default_max)
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            hit = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            hit_iqr = max(0.05, profile["hit_q75"] - profile["hit_q25"])
            hit_center = profile["hit_q50"]
            hit_shift = (hit - hit_center) / hit_iqr
            budget += int(round(hit_shift * 4.0))

            health = self._collect_intelligence_health(session_id)
            perf = (health.get("perf") or {}).get("decompile_enrich") or {}
            avg_ms = float(perf.get("avg_ms") or 0.0)
            if avg_ms > 0.0:
                perf_iqr = max(5.0, profile["perf_q75"] - profile["perf_q25"])
                perf_shift = (avg_ms - profile["perf_q50"]) / perf_iqr
                budget -= int(round(perf_shift * 3.0))
            if self._semantic_circuit_open(session_id):
                budget = int(round(budget * 0.5))
        except Exception:
            pass
        floor = max(6, int(round(default_max * 0.33)))
        ceil = max(floor + 2, int(round(default_max * 2.0)))
        budget = max(floor, min(ceil, budget))
        with self._semantic_budget_lock:
            self._semantic_budget_cache[session_id] = (now, budget)
        return budget

    def _update_semantic_circuit_breaker(self, session_id: str) -> None:
        """Open semantic circuit briefly when quality is persistently weak."""
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            sem_total = int(sem.get("total") or 0)
            sem_hit = float(sem.get("hit_rate") or 0.0)
            health = self._collect_intelligence_health(session_id)
            cache_hit = float((health.get("bb_cache") or {}).get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            min_total = int(profile.get("min_total") or 6)
            expected_hit = max(profile["hit_q50"], self._get_semantic_threshold(session_id))
            quality_gap = expected_hit - sem_hit
            cache_gap = profile["hit_q25"] - cache_hit
            if sem_total >= min_total and quality_gap > max(0.05, profile["hit_q75"] - profile["hit_q25"]) and cache_gap > 0:
                with self._circuit_breaker_lock:
                    ttl = int(max(45, min(240, round(60 + (quality_gap * 180)))))
                    self._semantic_circuit_breaker_until[session_id] = int(time.time()) + ttl
        except Exception:
            return

    def _get_semantic_threshold(self, session_id: str) -> float:
        if not session_id:
            return 0.5
        with self._semantic_threshold_lock:
            return float(self._session_semantic_threshold.get(session_id, 0.5))

    def _tune_semantic_threshold(self, session_id: str) -> None:
        """
        Tune semantic threshold from observed semantic hit-rate.
        """
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") if isinstance(stats, dict) else None
            if not sem:
                return
            total = int(sem.get("total") or 0)
            hit_rate = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            min_total = int(profile.get("min_total") or 6)
            if total < min_total:
                return
            with self._semantic_threshold_lock:
                cur = float(self._session_semantic_threshold.get(session_id, 0.5))
                nxt = cur
                iqr = max(0.05, profile["hit_q75"] - profile["hit_q25"])
                z = (hit_rate - profile["hit_q50"]) / iqr
                step = max(0.01, min(0.06, abs(z) * 0.02))
                if z < -0.25:
                    nxt = min(0.9, cur + step)
                elif z > 0.25:
                    nxt = max(0.2, cur - step)
                if abs(nxt - cur) >= 0.005:
                    self._session_semantic_threshold[session_id] = round(nxt, 3)
                    self._invalidate_session_caches(session_id)
                    self._schedule_policy_save(session_id)
        except Exception:
            return

    def _get_bb_by_api_signals(
        self,
        bb_store,
        api_calls: List[str],
        addr: str,
        top_k: int = 4,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve blackboard findings related to the same behavior signal (APIs/tags),
        not just exact address matches.
        """
        if bb_store is None or not api_calls:
            return []
        try:
            ranked: List[Tuple[int, float, Dict[str, Any]]] = []
            seen_ids: set = set()
            # Query per API tag; blackboard tags are stored as JSON arrays and
            # list(tag=...) already supports LIKE matching.
            for api in api_calls[:8]:
                for entry in bb_store.list(tag=api, limit=6):
                    eid = entry.get("id")
                    if not eid or eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    eaddr = str(entry.get("addr") or "")
                    same_addr_penalty = 0 if (addr and eaddr and eaddr != addr) else 1
                    conf = float(entry.get("confidence") or 0.0)
                    ranked.append((same_addr_penalty, -int(conf * 1000), entry))
            ranked.sort(key=lambda x: (x[0], x[1]))
            return [e for _, _, e in ranked[:top_k]]
        except Exception:
            return []

    def _record_related_addresses(self, session_id: str, anchor_addr: str, related_addrs: List[str]) -> None:
        """Record caller/callee/xref relations observed in tool outputs."""
        if not session_id or not anchor_addr or not related_addrs:
            return
        try:
            with self._related_addr_lock:
                graph = self._related_addr_graph[session_id]
                for other in related_addrs:
                    if not other or other == anchor_addr:
                        continue
                    graph[anchor_addr].add(other)
                    graph[other].add(anchor_addr)
        except Exception:
            pass

    def _get_bb_by_related_addresses(
        self,
        session_id: str,
        addr: str,
        bb_store,
        top_k: int = 4,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve blackboard findings from addresses related through recent
        caller/callee/xref exploration in this session.
        """
        if bb_store is None or not session_id or not addr:
            return []
        try:
            with self._related_addr_lock:
                neighbors = list(self._related_addr_graph.get(session_id, {}).get(addr, set()))
            if not neighbors:
                return []
            out: List[Dict[str, Any]] = []
            seen: set = set()
            for naddr in neighbors[:8]:
                for entry in bb_store.list(addr=naddr, limit=3):
                    eid = entry.get("id")
                    if not eid or eid in seen:
                        continue
                    seen.add(eid)
                    out.append(entry)
                    if len(out) >= top_k:
                        return out
            return out
        except Exception:
            return []

    # ── stuck detection ──────────────────────────────────────────────────

    def record_call(self, session_id: str, tool: str, action: str, addr: str) -> None:
        with self._activity_lock:
            log = self._activity[session_id]
            log.append({"tool": tool, "action": action, "addr": addr, "ts": time.time()})
            # Keep last 50 calls
            if len(log) > 50:
                self._activity[session_id] = log[-50:]

    def check_stuck(
        self,
        session_id: str,
        addr: str,
        tool: str,
        action: str,
    ) -> Optional[Dict[str, Any]]:
        with self._activity_lock:
            log = list(self._activity.get(session_id, []))
        if len(log) < 4:
            return None

        # Same address analyzed 3+ times
        if addr:
            addr_hits = sum(1 for e in log[-20:] if e.get("addr") == addr)
            if addr_hits >= 3:
                return {
                    "type": "repeated_address",
                    "address": addr,
                    "count": addr_hits,
                    "message": f"This address has been analyzed {addr_hits} times. "
                               "Consider exploring callers, callees, or cross-references.",
                    "pivot_suggestions": [
                        f"code(action='callers', addr='{addr}')",
                        f"code(action='callees', addr='{addr}')",
                        f"graph(action='call_chain', addr='{addr}')",
                        "data(action='imports') — review imports for context",
                    ],
                }

        # Same tool:action repeated 5+ times in last 15 calls
        recent = log[-15:]
        ta = f"{tool}:{action}"
        ta_count = sum(1 for e in recent if f"{e['tool']}:{e['action']}" == ta)
        if ta_count >= 5:
            pivots = {
                "code:decompile":   ["code:callers", "code:callees", "search:semantic"],
                "search:find":      ["schemaboot:query", "data:imports", "code:decompile"],
                "code:disasm":      ["code:decompile", "code:blocks", "ctree:get"],
            }
            return {
                "type": "repeated_tool",
                "tool_action": ta,
                "count": ta_count,
                "message": f"Called {ta} {ta_count} times recently. Try a different approach.",
                "pivot_suggestions": pivots.get(ta, [
                    "blackboard(action='list') — review what you've found so far",
                    "predictor(action='suggest_focus') — get focus suggestions",
                ]),
            }

        return None

    # ── main entry point ─────────────────────────────────────────────────

    def assemble(
        self,
        tool: str,
        action: str,
        payload: Dict[str, Any],
        addr: str,
        session_id: str,
        idb_path: str,
        bb_store=None,
    ) -> Dict[str, Any]:
        """
        Build a context_pack for injection into the tool response.
        Non-blocking: slow operations (embedding new function) are async.
        Returns empty dict if nothing meaningful to inject.
        """
        t_all = self._perf_start()
        pack: Dict[str, Any] = {}

        self._load_session_policy(session_id, idb_path)
        self._run_housekeeping(session_id)
        followed_focus = self._consume_focus_follow(session_id, tool, action)

        # Record for stuck detection
        self.record_call(session_id, tool, action, addr)

        # ── 1. Address-matched blackboard findings
        bb_addr = self._get_bb_entries(addr, bb_store)
        if bb_addr:
            self._merge_related_findings(pack, bb_addr, "address_linked", session_id=session_id)

        # ── 2. Decompile-specific enrichment
        is_decompile = (tool == "code" and
                        action in ("decompile", "semantic_decompile", "decompile_chain"))
        pseudocode = ""
        if is_decompile:
            pseudocode = (payload.get("code") or payload.get("pseudocode") or
                          payload.get("output") or "")
            # For decompile_chain, grab the main pseudocode
            if not pseudocode and isinstance(payload.get("results"), list):
                for r in payload["results"]:
                    pseudocode = r.get("pseudocode") or r.get("code") or ""
                    if pseudocode:
                        break

        if pseudocode and len(pseudocode.strip()) > 80:
            t_dec = self._perf_start()
            try:
                self._enrich_decompile(pack, payload, pseudocode, addr, idb_path, bb_store, session_id)
            except Exception:
                pass
            self._perf_end(session_id, "decompile_enrich", t_dec)

        # ── 2b. Search/xref result enrichment ─────────────────────────────
        # When a search returns a list of addresses, enrich each with
        # schemaboot structural data so the LLM doesn't need extra tool calls
        # to assess which hits are interesting.
        is_search = tool in ("search", "graph", "code") and action in (
            "find", "api", "callers", "callees", "xrefs_to", "xrefs_from",
            "data_ref", "code_ref", "name", "string", "bytes",
            "call_chain", "common_callers", "hub_functions",
        )
        if is_search and idb_path:
            t_search = self._perf_start()
            try:
                # Collect addresses from the result payload
                hit_addrs: List[str] = []
                for key in ("matches", "items", "results", "callers", "callees",
                            "xrefs", "refs", "addresses", "functions"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, str) and item.startswith("0x"):
                                hit_addrs.append(item)
                            elif isinstance(item, dict):
                                for k in ("ea", "addr", "address", "from", "to"):
                                    v = item.get(k)
                                    if v and str(v).startswith("0x"):
                                        hit_addrs.append(str(v))
                                        break
                if hit_addrs:
                    if addr:
                        self._record_related_addresses(session_id, addr, hit_addrs)
                    enriched = self._enrich_address_list(hit_addrs, idb_path)
                    if enriched:
                        pack["hit_details"] = enriched
            except Exception:
                pass
            self._perf_end(session_id, "search_enrich", t_search)

        # ── 2c. Suggest next unanalyzed targets (after any tool call) ─────
        # Use schemaboot to recommend high-interest functions not yet seen.
        if idb_path:
            try:
                # Only inject next_targets occasionally — every 5 calls per session
                with self._activity_lock:
                    n_calls = len(self._activity.get(session_id, []))
                if n_calls % 5 == 0 and n_calls > 0:
                    targets = self.suggest_next_targets(idb_path, limit=3)
                    if targets:
                        pack["suggested_targets"] = targets
            except Exception:
                pass

        # ── 3. Stuck detection
        stuck = self.check_stuck(session_id, addr, tool, action)
        if stuck:
            pack["stuck"] = stuck

        if followed_focus:
            success = bool(
                pack.get("related_findings")
                or pack.get("hit_details")
                or pack.get("similar_functions")
                or pack.get("api_calls")
                or pack.get("analysis_focus")
            )
            self._record_focus_outcome(session_id, tool, action, success)

        health = self._collect_intelligence_health(session_id)
        if health:
            pack["intelligence_health"] = health

        if addr:
            pack["compiled_plan"] = self._compile_question_tool_plan(pack, addr)
            budget = self._evidence_budget_gate(pack, addr)
            pack["evidence_budget"] = budget
            escalation = self._dead_end_escalation(session_id, addr, pack)
            pack["dead_end_escalation"] = escalation
            # default-to-call policy: force at least one call under uncertainty/blocks
            must_call = bool(budget.get("claim_blocked") or escalation.get("loop_detected") or (pack.get("llm_uncertainty") or {}).get("risk") in ("medium", "high"))
            pack["must_call_before_answer"] = must_call
            req = budget.get("required_followup_call") or escalation.get("required_followup_call")
            if must_call and req:
                pack["required_followup_call"] = req
            pack["mode_profile"] = self._mode_profile(pack)

        self._record_call_outcome(session_id, pack)
        pack["mcp_value_score"] = self._mcp_value_score(session_id, pack)

        self._perf_end(session_id, "assemble", t_all)

        return pack

    def _query_schemaboot(self, idb_path: str, addr: str) -> Optional[Dict[str, Any]]:
        """Pull structural attributes from schemaboot for this function address."""
        if not idb_path or not addr:
            return None
        db = get_db_path(idb_path)
        if not os.path.exists(db):
            return None
        try:
            ea = _helpers.coerce_int(addr)
            with sqlite3.connect(db) as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT ea, name, size, entropy, bb_count, cyclomatic_complexity,
                           incoming_xrefs, outgoing_xrefs, call_count, xor_count,
                           api_count, string_count, has_loops
                    FROM function_attrs WHERE ea = ?
                """, (ea,))
                row = cur.fetchone()
                # Also fetch API list from junction table
                apis: List[str] = []
                if row:
                    cur.execute(
                        "SELECT api_name FROM function_apis WHERE func_ea = ? LIMIT 60",
                        (ea,),
                    )
                    apis = [r[0] for r in cur.fetchall()]
            if not row:
                return None
            return {
                "ea": hex(row[0]),
                "name": row[1],
                "size": row[2],
                "entropy": float(row[3] or 0),
                "bb_count": row[4],
                "cyclomatic_complexity": row[5],
                "incoming_xrefs": row[6],
                "outgoing_xrefs": row[7],
                "call_count": row[8],
                "xor_count": row[9],
                "api_count": row[10],
                "string_count": row[11],
                "has_loops": bool(row[12]),
                "known_apis": apis,
            }
        except Exception:
            return None

    def _enrich_decompile(
        self,
        pack: Dict[str, Any],
        payload: Dict[str, Any],
        pseudocode: str,
        addr: str,
        idb_path: str,
        bb_store,
        session_id: str,
    ) -> None:
        """
        Decompile-specific enrichment.  Deterministic first, embeddings second.

        Priority order:
          1. Deterministic API call extraction from pseudocode text (instant, high signal)
          2. Schemaboot structural attributes (fast SQL — xor_count, entropy, xrefs)
          3. Blackboard addr-match (fast SQL — past findings at this address)
          4. Function embedding + similarity search (slow, grows over session)
          5. Semantic blackboard retrieval (slow, only if bb_store populated)
        """
        func_name = payload.get("name") or f"sub_{addr}"

        # ── Step 1: Deterministic API extraction (no ML, instant) ─────────
        api_calls: List[str] = []
        string_refs: List[str] = []
        crypto_consts: List[str] = []
        try:
            api_calls = extract_api_calls(pseudocode)
            string_refs = extract_string_refs(pseudocode)
            crypto_consts = detect_crypto_constants(pseudocode)
        except Exception:
            pass

        # ── Step 2: Schemaboot structural attributes (fast SQL) ──────────
        sb_attrs: Optional[Dict[str, Any]] = None
        try:
            sb_attrs = self._query_schemaboot(idb_path, addr)
            # Merge API list from schemaboot with what we found in pseudocode
            if sb_attrs and sb_attrs.get("known_apis"):
                extra = [a for a in sb_attrs["known_apis"] if a not in api_calls]
                api_calls = (api_calls + extra)[:40]
        except Exception:
            pass

        # ── Step 3: Surface the extracted facts ───────────────────────────
        if api_calls:
            pack["api_calls"] = api_calls
        if string_refs:
            pack["string_refs"] = string_refs
        if crypto_consts:
            pack["crypto_constants_detected"] = crypto_consts

        if sb_attrs:
            structural: Dict[str, Any] = {}
            if sb_attrs.get("incoming_xrefs") is not None:
                structural["xref_count"] = sb_attrs["incoming_xrefs"]
            if sb_attrs.get("xor_count", 0) > 0:
                structural["xor_count"] = sb_attrs["xor_count"]
            if sb_attrs.get("entropy", 0) > 0:
                structural["entropy"] = round(sb_attrs["entropy"], 2)
            if sb_attrs.get("cyclomatic_complexity", 0) > 0:
                structural["cyclomatic_complexity"] = sb_attrs["cyclomatic_complexity"]
            if sb_attrs.get("has_loops"):
                structural["has_loops"] = True
            if sb_attrs.get("bb_count", 0) > 0:
                structural["bb_count"] = sb_attrs["bb_count"]
            if structural:
                pack["structural"] = structural

        # ── Step 3b: Behavior classification via the shared zero-shot classifier
        # This is intentionally separate from API/structural extraction so the
        # response can expose both deterministic and semantic signals.
        behavior_hits: List[Dict[str, Any]] = []
        if pseudocode.strip():
            try:
                behavior_hits = self._behavior_classifier().classify(
                    pseudocode,
                    threshold=0.25,
                    top_k=4,
                    block=True,
                )
            except Exception:
                behavior_hits = []
        if behavior_hits:
            pack["behavior_classifications"] = behavior_hits
            pack["behavior_tags"] = [hit.get("behavior") for hit in behavior_hits if hit.get("behavior")]

        # ── Step 4: Rule-based actions from API patterns + structural attrs
        actions: List[Dict[str, Any]] = []
        seen_act: set = set()
        try:
            for act in actions_from_apis(api_calls, addr):
                key = f"{act['tool']}:{act['action']}"
                if key not in seen_act:
                    seen_act.add(key)
                    actions.append(act)
        except Exception:
            pass
        try:
            if sb_attrs:
                for act in actions_from_schemaboot(sb_attrs, addr):
                    key = f"{act['tool']}:{act['action']}"
                    if key not in seen_act:
                        seen_act.add(key)
                        actions.append(act)
        except Exception:
            pass
        # Always suggest callers if we haven't already
        if f"code:callers" not in seen_act and addr:
            actions.append({
                "tool": "code", "action": "callers", "addr": addr,
                "reason": "See what calls this function",
            })
        if actions:
            pack["suggested_next_actions"] = actions[:6]


        # -- Step 4b: Auto-blackboard -- write dangerous findings automatically --
        # The LLM should not have to manually blackboard every dangerous finding.
        if bb_store is not None and addr and api_calls:
            try:
                _DANGEROUS_COMBOS = [
                    ({"VirtualAllocEx", "WriteProcessMemory"}, "process_injection",
                     "Process injection", ["injection", "shellcode", "dangerous"]),
                    ({"CreateRemoteThread"}, "remote_exec",
                     "Remote thread creation", ["injection", "dangerous"]),
                    ({"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess"}, "anti_debug",
                     "Anti-debugging", ["anti_debug", "evasion"]),
                    ({"AdjustTokenPrivileges"}, "privilege_escalation",
                     "Privilege escalation", ["privesc", "dangerous"]),
                    ({"RegSetValueEx", "CreateService"}, "persistence",
                     "Persistence mechanism", ["persistence"]),
                ]
                api_set = set(api_calls)
                for required, category, label, tags in _DANGEROUS_COMBOS:
                    if required & api_set:
                        matched = sorted(required & api_set)
                        title = f"{label} at {addr}"
                        if not bb_store.exists(addr, category, title):
                            bb_store.write(
                                title=title,
                                content=(
                                    f"Function {func_name} ({addr}) uses: "
                                    f"{', '.join(matched)}. Detected automatically."
                                ),
                                category=category,
                                addr=addr,
                                tags=tags,
                                confidence=0.92,
                            )
            except Exception:
                pass

        # ── Step 5: Embedding-based function similarity (background-safe) ─
        query_vec: Optional[List[float]] = None
        if idb_path:
            try:
                query_vec = self._embedder.embed(pseudocode[:3000])
                idx = self._get_index(idb_path)
                # Update cache + persist async
                idx._cache[addr] = query_vec
                blob = idx._pack(query_vec)
                ph   = idx._phash(pseudocode)
                sig  = _extract_signature(pseudocode, max_idents=64) or ""
                sig_hash = hashlib.md5((sig or pseudocode).encode("utf-8", errors="replace")).hexdigest()[:16]
                def _persist(ea=addr, name=func_name, b=blob, p=ph, v=query_vec):
                    try:
                        with idx._conn() as conn:
                            conn.execute(
                                """INSERT INTO func_embeddings
                                   (ea, name, dim, vec_blob, pseudo_hash, indexed_at, signature_text, signature_hash)
                                   VALUES(?,?,?,?,?,?,?,?)
                                   ON CONFLICT(ea) DO UPDATE SET
                                        name=excluded.name, vec_blob=excluded.vec_blob,
                                        pseudo_hash=excluded.pseudo_hash,
                                        indexed_at=excluded.indexed_at,
                                        signature_text=excluded.signature_text,
                                        signature_hash=excluded.signature_hash""",
                                (ea, name, len(v), b, p, time.time(), sig, sig_hash),
                            )
                            conn.commit()
                    except Exception:
                        pass
                threading.Thread(target=_persist, daemon=True).start()

                # Similarity search over in-memory cache (instant)
                cache_snap = list(idx._cache.items())
                if len(cache_snap) > 1:
                    scored = sorted(
                        [(BgeCodeEmbedder.cosine(query_vec, v), ea)
                         for ea, v in cache_snap if ea != addr],
                        reverse=True,
                    )
                    top = [(sim, ea) for sim, ea in scored[:3] if sim >= 0.6]
                    if top:
                        top_eas = [ea for _, ea in top]
                        names: Dict[str, str] = {}
                        try:
                            with idx._conn() as conn:
                                ph2 = ",".join("?" * len(top_eas))
                                for row in conn.execute(
                                    f"SELECT ea, name FROM func_embeddings WHERE ea IN ({ph2})",
                                    top_eas,
                                ):
                                    names[row[0]] = row[1] or row[0]
                        except Exception:
                            pass
                        pack["similar_functions"] = [
                            {"ea": ea, "name": names.get(ea, ea), "similarity": round(sim, 4)}
                            for sim, ea in top
                        ]
            except Exception:
                pass

        # ── Step 6: Cross-address blackboard retrieval (callgraph-linked) ─
        if bb_store is not None and addr and session_id:
            try:
                rel_bb = self._get_bb_by_related_addresses(session_id, addr, bb_store, top_k=4)
                if rel_bb:
                    self._merge_related_findings(pack, rel_bb, "relation_linked", session_id=session_id)
            except Exception:
                pass

        # ── Step 7: Cross-address blackboard retrieval (API/tag linked) ───
        if bb_store is not None and api_calls:
            try:
                api_bb = self._get_bb_by_api_signals(bb_store, api_calls, addr, top_k=4)
                if api_bb:
                    self._merge_related_findings(pack, api_bb, "api_linked", session_id=session_id)
            except Exception:
                pass

        # ── Step 8: Semantic blackboard retrieval (if bb_store populated) ─
        if query_vec is not None and bb_store is not None and not self._semantic_circuit_open(session_id):
            try:
                sem_thr = self._get_semantic_threshold(session_id)
                # Use stored vectors in the new blackboard (fast cosine scan, no re-embedding)
                if hasattr(bb_store, "semantic_search"):
                    # New blackboard: vectors already stored, O(n) cosine scan
                    sig = _extract_signature(pseudocode, max_idents=40) or pseudocode[:512]
                    sem_bb = bb_store.semantic_search(
                        query=sig,
                        top_k=5,
                        threshold=sem_thr,
                    )
                    # Exclude the entry for this exact address to avoid self-reference
                    sem_bb = [e for e in sem_bb if e.get("addr") != addr][:3]
                else:
                    # Legacy blackboard: embed on-the-fly
                    sem_budget = self._adaptive_semantic_budget(session_id, default_max=24)
                    sem_bb = self._get_bb_semantic_vec(
                        query_vec,
                        bb_store,
                        top_k=3,
                        threshold=sem_thr,
                        max_entries=sem_budget,
                        api_calls=api_calls,
                        session_id=session_id,
                    )
                if sem_bb:
                    self._merge_related_findings(pack, sem_bb, "semantic_linked", session_id=session_id)
            except Exception:
                pass

        self._tune_semantic_threshold(session_id)
        self._update_semantic_circuit_breaker(session_id)
        stats = self._session_retrieval_stats(session_id)
        if stats:
            pack["retrieval_stats"] = stats
        alts = self._derive_focus_candidates(pack, addr, session_id)
        if alts:
            pack["analysis_focus"] = alts[0]
            self._record_focus_suggestion(session_id, alts[0])
            if len(alts) > 1:
                pack["analysis_focus_alternatives"] = alts[1:3]
            explain = self._focus_explainability(alts)
            if explain:
                pack["analysis_focus_explain"] = explain

        # LLM-first payloads: action card, uncertainty, and provenance snippets.
        if addr:
            pack["llm_action_card"] = self._build_llm_action_card(pack, addr)
            pack["llm_tool_call_contract"] = self._build_llm_tool_call_contract(pack, addr)
            pack["llm_failover_route"] = self._build_llm_failover_route(pack, addr)
        pack["llm_uncertainty"] = self._build_llm_uncertainty(pack)
        evid = self._build_llm_evidence_snippets(pack)
        if evid:
            pack["llm_evidence"] = evid
        pack["llm_response_style_guard"] = self._build_llm_response_style_guard(pack)
        if addr:
            pack["llm_query_intent"] = self._llm_query_intent(pack)
            pack["llm_required_evidence_sources"] = self._llm_required_evidence_sources(pack)
            pack["llm_claim_templates"] = self._llm_claim_templates()
            pack["llm_call_sequence"] = self._llm_call_sequence(pack, addr)
            pack["llm_refusal_policy"] = self._llm_refusal_policy(pack)
            pack["llm_tool_cooldowns"] = self._llm_tool_cooldowns(session_id)
            pack["llm_context_capsule"] = self._llm_context_capsule(pack, addr)
            pack["llm_verification_checklist"] = self._llm_verification_checklist(pack, addr)
            pack["llm_next_best_question"] = self._llm_next_best_question(pack)
            pack["llm_auto_notes"] = self._llm_auto_notes(pack)
            pack["llm_nudge"] = self._build_llm_nudge(pack, addr)



    def _enrich_address_list(
        self,
        addresses: List[str],
        idb_path: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of addresses with schemaboot structural data.
        Used to annotate search/xref results without extra tool calls.
        Returns a list of enriched entries (only for addresses that exist in schemaboot).
        """
        if not addresses or not idb_path:
            return []
        db = get_db_path(idb_path)
        if not os.path.exists(db):
            return []
        try:
            eas: List[int] = []
            for a in addresses[:limit]:
                try:
                    eas.append(_helpers.coerce_int(a))
                except (ValueError, TypeError):
                    pass
            if not eas:
                return []
            with sqlite3.connect(db) as conn:
                cur = conn.cursor()
                ph = ",".join("?" * len(eas))
                cur.execute(f"""
                    SELECT ea, name, size, entropy, cyclomatic_complexity,
                           xor_count, incoming_xrefs, api_count, has_loops
                    FROM function_attrs WHERE ea IN ({ph})
                """, eas)
                rows = {row[0]: row for row in cur.fetchall()}
                # Fetch APIs for these functions
                cur.execute(f"""
                    SELECT func_ea, api_name FROM function_apis
                    WHERE func_ea IN ({ph}) LIMIT 200
                """, eas)
                apis_by_ea: Dict[int, List[str]] = {}
                for func_ea, api_name in cur.fetchall():
                    apis_by_ea.setdefault(func_ea, []).append(api_name)

            enriched = []
            for a_str in addresses[:limit]:
                try:
                    ea_int = _helpers.coerce_int(a_str)
                except (ValueError, TypeError):
                    continue
                row = rows.get(ea_int)
                if not row:
                    continue
                entry: Dict[str, Any] = {
                    "ea":   hex(row[0]),
                    "name": row[1],
                }
                if row[2]:
                    entry["size"] = row[2]
                if float(row[3] or 0) > 4.5:
                    entry["entropy"] = round(float(row[3]), 2)
                if (row[4] or 0) > 5:
                    entry["cyclomatic"] = row[4]
                if (row[5] or 0) > 3:
                    entry["xor_count"] = row[5]
                if row[6] is not None:
                    entry["callers"] = row[6]
                apis = [a for a in apis_by_ea.get(ea_int, [])
                        if a in ALL_INTERESTING_APIS][:5]
                if apis:
                    entry["dangerous_apis"] = apis
                if row[8]:
                    entry["has_loops"] = True
                enriched.append(entry)
            return enriched
        except Exception:
            return []


    def suggest_next_targets(
        self,
        idb_path: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Recommend unanalyzed functions worth examining next, ranked by
        embedding similarity over structural summaries.

        Excludes functions already in the embedding index (already seen).
        Returns an empty list if schemaboot has not been ingested yet.
        """
        if not idb_path:
            return []
        db = get_db_path(idb_path)
        if not os.path.exists(db):
            return []

        # Functions already indexed (= already decompiled this session)
        try:
            idx = self._get_index(idb_path)
            analyzed = set(idx._cache.keys())
        except Exception:
            analyzed = set()

        try:
            with sqlite3.connect(db) as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT ea, name,
                           xor_count, entropy, cyclomatic_complexity,
                           api_count, incoming_xrefs, string_count, has_loops
                    FROM function_attrs
                    WHERE size > 64
                    LIMIT 200
                """)
                rows = cur.fetchall()

                # Fetch top dangerous-API functions separately
                cur.execute("""
                    SELECT DISTINCT fa.ea, fa.name, fa.xor_count, fa.entropy,
                           fa.cyclomatic_complexity, fa.api_count, fa.incoming_xrefs,
                           fa.string_count, fa.has_loops
                    FROM function_attrs fa
                    JOIN function_apis fapi ON fapi.func_ea = fa.ea
                    WHERE fapi.api_name IN (
                        'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
                        'IsDebuggerPresent','AdjustTokenPrivileges',
                        'RegSetValueEx','CreateService',
                        'WSASocket','InternetOpen','WinHttpOpen'
                    )
                    LIMIT 50
                """)
                danger_rows = cur.fetchall()
        except Exception:
            return []

        seen_eas: set = set()
        results: List[Dict[str, Any]] = []

        def _add(row, reason: str, interest_score: float):
            ea_int = row[0]
            ea = hex(ea_int)
            if ea in analyzed or ea in seen_eas:
                return
            seen_eas.add(ea)
            xor   = row[2] or 0
            entr  = float(row[3] or 0)
            cc    = row[4] or 0
            apis  = row[5] or 0
            xrefs = row[6] or 0
            results.append({
                "ea":    ea,
                "name":  row[1] or f"sub_{ea_int:X}",
                "reason": reason,
                "interest_score": round(float(interest_score), 3),
                "xor_count":  xor,
                "entropy":    round(entr, 2),
                "cyclomatic": cc,
                "api_count":  apis,
                "callers":    xrefs,
            })

        # Embedding-first structural ranking
        row_scores: Dict[int, float] = {}
        try:
            anchor = (
                "high value reverse engineering target with suspicious behavior, "
                "complex control flow, many cross references, and high analysis payoff"
            )
            qv = self._embedder.embed(anchor)
            text_rows: List[str] = []
            ea_rows: List[int] = []
            for row in rows:
                ea_int = int(row[0] or 0)
                if not ea_int:
                    continue
                summary = (
                    f"name={row[1] or ''} xor_count={row[2] or 0} entropy={float(row[3] or 0):.2f} "
                    f"cyclomatic={row[4] or 0} api_count={row[5] or 0} callers={row[6] or 0} "
                    f"strings={row[7] or 0} loops={bool(row[8])}"
                )
                text_rows.append(summary)
                ea_rows.append(ea_int)
            if text_rows:
                vecs = self._embedder.embed_batch(text_rows)
                for ea_int, v in zip(ea_rows, vecs):
                    row_scores[ea_int] = float(BgeCodeEmbedder.cosine(qv, v))
        except Exception:
            row_scores = {}

        # Dangerous-API functions first (highest priority)
        for row in danger_rows:
            base = row_scores.get(int(row[0] or 0), 0.0)
            _add(row, "calls dangerous API", min(1.0, base + 0.15))
            if len(results) >= limit:
                break

        # Then highest-scoring structural candidates
        ranked_rows = sorted(
            rows,
            key=lambda r: row_scores.get(int(r[0] or 0), float((r[6] or 0) / 1000.0)),
            reverse=True,
        )
        for row in ranked_rows:
            if len(results) >= limit:
                break
            name = row[1] or ""
            reason = (
                f"xor={row[2]}, entropy={row[3]:.1f}"
                if (row[2] or 0) > 3 or float(row[3] or 0) > 5.5
                else f"complexity={row[4]}, apis={row[5]}"
            )
            _add(row, reason, row_scores.get(int(row[0] or 0), 0.0))

        results.sort(key=lambda x: x["interest_score"], reverse=True)
        return results[:limit]


    def bulk_index(self, functions: List[Dict[str, Any]], idb_path: str) -> int:
        """
        Index a batch of functions (e.g. after schemaboot ingest).
        Each dict: {ea, name, pseudocode}.
        Returns count indexed.
        """
        if not idb_path or not functions:
            return 0
        idx = self._get_index(idb_path)
        count = 0
        for f in functions:
            pseudo = f.get("pseudocode") or f.get("code") or ""
            ea = str(f.get("ea") or f.get("addr") or "")
            name = str(f.get("name") or ea)
            if pseudo and ea:
                idx.index(ea, name, pseudo)
                count += 1
        return count

    def stop(self) -> None:
        """Shut down the llama-server subprocess cleanly."""
        self.flush_policy_saves()
        # Give background save workers a short chance to flush.
        time.sleep(0.05)
        self._embedder.stop()

    @property
    def status(self) -> Dict[str, Any]:
        return {
            "backend": self._embedder.backend,
            "llama_server_bin": self._embedder._server_bin or "not found",
            "model_path": self._embedder._model_path or "not found",
            "model_ready": self._embedder._ready,
            "embed_dim": EMBED_DIM,
            "indexes": {
                idb: {"functions_indexed": idx.size}
                for idb, idx in self._indexes.items()
            },
            "policy_save_queue": len(self._policy_save_due_at),
            "embed_batch_size": getattr(self._embedder, "_batch_size", 1),
        }


# Module-level singleton access
# ─────────────────────────────────────────────────────────────────────────────

_assembler: Optional[ContextAssembler] = None
_assembler_lock = threading.Lock()


def get_assembler() -> ContextAssembler:
    global _assembler
    with _assembler_lock:
        if _assembler is None:
            _assembler = ContextAssembler()
    return _assembler


def _shutdown_intelligence_singleton() -> None:
    global _assembler
    try:
        if _assembler is not None:
            _assembler.stop()
    except Exception:
        pass


atexit.register(_shutdown_intelligence_singleton)
