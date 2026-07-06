"""
Context assembly layer for IDA Pro MCP.

Extracted from intelligence.py so the core embedding / classifier / memory
backends can live in a smaller dedicated module.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Any

from . import helpers as _helpers
from .core import (
    EMBED_DIM,
    BehaviorClassifier,
    BgeCodeEmbedder,
    FunctionEmbeddingIndex,
    _extract_signature,
)


def _intel_profile_enabled() -> bool:
    """Look up the canonical symbol at call time so tests/runtime can toggle
    the profile flag by mutating the module attribute on intelligence_core."""
    from . import core as intelligence_core
    return bool(intelligence_core.INTEL_PROFILE)


class ContextAssembler:
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
        self._indexes: dict[str, FunctionEmbeddingIndex] = {}
        self._idx_lock   = threading.Lock()
        # Activity tracking for stuck detection (in-memory, per session)
        self._activity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._activity_lock = threading.Lock()
        self._related_addr_graph: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._related_addr_lock = threading.Lock()
        self._retrieval_metrics: dict[str, dict[str, int]] = defaultdict(dict)
        self._retrieval_metrics_lock = threading.Lock()
        self._session_semantic_threshold: dict[str, float] = {}
        self._semantic_threshold_lock = threading.Lock()
        self._last_housekeeping_ts = 0.0
        self._housekeeping_lock = threading.Lock()
        self._related_graph_max_edges = 1200
        self._semantic_circuit_breaker_until: dict[str, int] = {}
        self._circuit_breaker_lock = threading.Lock()
        self._session_stats_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._stats_cache_lock = threading.Lock()
        self._stats_cache_ttl_sec = 1.5
        self._perf_buckets: dict[str, dict[str, float]] = defaultdict(dict)
        self._perf_lock = threading.Lock()
        self._semantic_budget_cache: dict[str, tuple[float, int]] = {}
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

    def _get_bb_entries(self, addr: str, bb_store) -> list[dict[str, Any]]:
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
        pack: dict[str, Any],
        entries: list[dict[str, Any]],
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
        min_conf = 0.0
        max_take = 8
        weight = 1.0
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
        merged: dict[str, dict[str, Any]] = {}
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
            if new_rank == prev_rank and float(e.get("confidence") or 0.0) > float(prev.get("confidence") or 0.0):
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
            except Exception:
                pass

    def _invalidate_session_caches(self, session_id: str) -> None:
        if not session_id:
            return
        with self._stats_cache_lock:
            self._session_stats_cache.pop(session_id, None)

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

    def _session_retrieval_stats(self, session_id: str) -> dict[str, Any]:
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
            out: dict[str, Any] = {}
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
            with self._stats_cache_lock:
                self._session_stats_cache[session_id] = (now, dict(out))
            return out
        except Exception:
            return {}

    def _run_housekeeping(self, session_id: str) -> None:
        """Periodic cleanup for relation graph bounds."""
        now = time.time()
        if now - self._last_housekeeping_ts < 30.0:
            return
        if not self._housekeeping_lock.acquire(blocking=False):
            return
        try:
            self._last_housekeeping_ts = now
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

    def _semantic_circuit_open(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._circuit_breaker_lock:
            return int(self._semantic_circuit_breaker_until.get(session_id, 0)) > int(time.time())

    @staticmethod
    def _quantile(vals: list[float], q: float, default: float = 0.0) -> float:
        """Deterministic quantile helper with sane fallback."""
        try:
            return _helpers.quantile(vals, q, default)
        except Exception:
            return float(default)

    def _semantic_quality_profile(self, session_id: str) -> dict[str, float]:
        """
        Build adaptive semantic-quality profile from session telemetry.
        Avoids fixed cutoffs by deriving baselines from observed distributions.
        """
        stats = self._session_retrieval_stats(session_id) if session_id else {}
        rates: list[float] = []
        totals: list[int] = []
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
        # Read perf data directly from _perf_buckets
        perf_avgs = []
        if _intel_profile_enabled() and session_id:
            with self._perf_lock:
                b = dict(self._perf_buckets.get(session_id, {}))
            for k in ("assemble", "decompile_enrich", "search_enrich"):
                cnt = float(b.get(f"{k}.count", 0.0))
                sm = float(b.get(f"{k}.sum_ms", 0.0))
                if cnt > 0:
                    perf_avgs.append(sm / cnt)
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

            # Read perf data directly from _perf_buckets
            avg_ms = 0.0
            if _intel_profile_enabled() and session_id:
                with self._perf_lock:
                    b = dict(self._perf_buckets.get(session_id, {}))
                cnt = float(b.get("decompile_enrich.count", 0.0))
                sm = float(b.get("decompile_enrich.sum_ms", 0.0))
                if cnt > 0:
                    avg_ms = sm / cnt
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
        """Open semantic circuit briefly when retrieval quality is persistently weak."""
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            sem_total = int(sem.get("total") or 0)
            sem_hit = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            min_total = int(profile.get("min_total") or 6)
            expected_hit = max(profile["hit_q50"], self._get_semantic_threshold(session_id))
            quality_gap = expected_hit - sem_hit
            if sem_total >= min_total and quality_gap > max(0.05, profile["hit_q75"] - profile["hit_q25"]):
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

    def _record_related_addresses(self, session_id: str, anchor_addr: str, related_addrs: list[str]) -> None:
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
    ) -> list[dict[str, Any]]:
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
            out: list[dict[str, Any]] = []
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
    ) -> dict[str, Any] | None:
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
                "search:find":      ["search:structured", "data:imports", "code:decompile"],
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
        payload: dict[str, Any],
        addr: str,
        session_id: str,
        idb_path: str,
        bb_store=None,
        mode: str = "full",
    ) -> dict[str, Any]:
        """
        Build a context_pack for injection into the tool response.
        Non-blocking: slow operations (embedding new function) are async.
        Returns empty dict if nothing meaningful to inject.
        """
        _full = mode == "full"
        t_all = self._perf_start()
        pack: dict[str, Any] = {}

        self._run_housekeeping(session_id)

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
            with contextlib.suppress(Exception):
                self._enrich_decompile(pack, payload, pseudocode, addr, idb_path, bb_store, session_id, mode=mode)
            self._perf_end(session_id, "decompile_enrich", t_dec)

        # ── 2b. Search/xref result enrichment ─────────────────────────────
        # When a search returns a list of addresses, enrich each with
        # structural data so the LLM doesn't need extra tool calls
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
                hit_addrs: list[str] = []
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
                    if _full and enriched:
                        pack["hit_details"] = enriched
            except Exception:
                pass
            self._perf_end(session_id, "search_enrich", t_search)

        # ── 2c. Suggest next unanalyzed targets (after any tool call) ─────
        # Use the embedding index to recommend high-interest functions not yet seen.
        if idb_path:
            try:
                # Only inject next_targets occasionally — every 5 calls per session
                with self._activity_lock:
                    n_calls = len(self._activity.get(session_id, []))
                if n_calls % 5 == 0 and n_calls > 0:
                    targets = self.suggest_next_targets(idb_path, limit=3)
                    if _full and targets:
                        pack["suggested_targets"] = targets
            except Exception:
                pass

        # ── 3. Stuck detection
        stuck = self.check_stuck(session_id, addr, tool, action)
        if _full and stuck:
            pack["stuck"] = stuck

        self._perf_end(session_id, "assemble", t_all)

        return pack


    def _enrich_decompile(
        self,
        pack: dict[str, Any],
        payload: dict[str, Any],
        pseudocode: str,
        addr: str,
        idb_path: str,
        bb_store,
        session_id: str,
        mode: str = "full",
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
        _full = mode == "full"
        func_name = payload.get("name") or f"sub_{addr}"

        # ── Behavior classification via the shared zero-shot classifier ──
        if _full and pseudocode.strip():
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
        # Only surfaced in full mode, so skip the rule evaluation entirely in
        # compact mode.
        if _full:
            actions: list[dict[str, Any]] = []
            seen_act: set = set()
            # Always suggest callers if we haven't already
            if "code:callers" not in seen_act and addr:
                actions.append({
                    "tool": "code", "action": "callers", "addr": addr,
                    "reason": "See what calls this function",
                })
            if actions:
                pack["suggested_next_actions"] = actions[:6]


        # ── Step 5: Embedding-based function similarity (background-safe) ─
        query_vec: list[float] | None = None
        if idb_path:
            try:
                query_vec = self._embedder.embed_vector(pseudocode[:3000])
                if query_vec is None:
                    raise RuntimeError("embedding unavailable")
                idx = self._get_index(idb_path)
                # Update cache + persist async
                idx.cache_store(addr, query_vec)
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

                # Similarity search over in-memory cache. Only surfaced in full
                # mode, so skip the cosine scan entirely in compact mode — the
                # embed + async persist above is the valuable indexing side-effect.
                if _full:
                    cache_snap = idx.cache_snapshot()
                    if len(cache_snap) > 1:
                        scored = sorted(
                            [(BgeCodeEmbedder.cosine(query_vec, v), ea)
                             for ea, v in cache_snap if ea != addr],
                            reverse=True,
                        )
                        top = [(sim, ea) for sim, ea in scored[:3] if sim >= 0.6]
                        if top:
                            top_eas = [ea for _, ea in top]
                            names: dict[str, str] = {}
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

        # ── Step 7: Semantic blackboard retrieval ─────────────────────────
        # Runs in all modes: this is the recall that makes the blackboard useful
        # to the LLM — semantically related past findings are surfaced without
        # the LLM having to query for them. BlackboardStore.semantic_search
        # embeds the signature once and cosine-scans stored vectors (no
        # re-embedding of entries).
        if query_vec is not None and bb_store is not None and not self._semantic_circuit_open(session_id):
            try:
                sem_thr = self._get_semantic_threshold(session_id)
                sig = _extract_signature(pseudocode, max_idents=40) or pseudocode[:512]
                sem_bb = bb_store.semantic_search(
                    query=sig,
                    top_k=5,
                    threshold=sem_thr,
                )
                # Exclude the entry for this exact address to avoid self-reference
                sem_bb = [e for e in sem_bb if e.get("addr") != addr][:3]
                if sem_bb:
                    self._merge_related_findings(pack, sem_bb, "semantic_linked", session_id=session_id)
            except Exception:
                pass

        self._tune_semantic_threshold(session_id)
        self._update_semantic_circuit_breaker(session_id)
        stats = self._session_retrieval_stats(session_id)
        if _full and stats:
            pack["retrieval_stats"] = stats


    def _enrich_address_list(
        self,
        addresses: list[str],
        idb_path: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Enrich addresses with structural data from the embedding index."""
        if not addresses or not idb_path:
            return []
        try:
            idx = self._get_index(idb_path)
            if idx is None or idx.size == 0:
                return []
            # The ea column stores hex strings like "0x401000", so
            # convert inputs to hex strings to match exactly.
            def _to_hex(a: str) -> str | None:
                try:
                    n = int(a, 0)
                    return hex(n)
                except (ValueError, TypeError):
                    return None

            eas = [_to_hex(a) for a in addresses[:limit]]
            eas = [a for a in eas if a is not None]
            if not eas:
                return []
            # Query embedding index for structural metadata
            enriched = []
            with idx._conn() as conn:
                ph = ",".join("?" * len(eas))
                for row in conn.execute(
                    f"SELECT ea, name, func_size, bb_count, has_loops, api_count, string_count, segment, cyclomatic "
                    f"FROM func_embeddings WHERE ea IN ({ph})", eas
                ):
                    entry = {"ea": hex(int(row[0], 16)) if row[0] else "", "name": row[1] or ""}
                    if row[2]: entry["size"] = row[2]
                    if row[3]: entry["bb_count"] = row[3]
                    if row[4]: entry["has_loops"] = True
                    if row[5]: entry["api_count"] = row[5]
                    if row[6]: entry["string_count"] = row[6]
                    if row[7]: entry["segment"] = row[7]
                    if row[8]: entry["cyclomatic"] = row[8]
                    enriched.append(entry)
            return enriched
        except Exception:
            return []


    def suggest_next_targets(
        self,
        idb_path: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend unanalyzed functions worth examining next.

        Uses the embedding index to find high-value structural candidates.
        """
        if not idb_path:
            return []
        try:
            idx = self._get_index(idb_path)
            if idx is None or idx.size == 0:
                return []
            # Query embedding index for interesting functions
            rows = idx.search_structured(
                {"min_size": 64, "min_bb": 3},
                query="high value reverse engineering target",
                top_k=limit * 4,
            )
            analyzed = idx.cache_keys()
            results = []
            seen = set()
            dangerous_apis = {
                'virtualallocex', 'writeprocessmemory', 'createremotethread',
                'isdebuggerpresent', 'adjusttokenprivileges',
                'regsetvalueex', 'createservice',
                'wsasocket', 'internetopen', 'winhttpopen'
            }
            for r in rows:
                ea = r["ea"]
                if ea in analyzed or ea in seen:
                    continue
                seen.add(ea)
                results.append({
                    "ea": ea,
                    "name": r["name"],
                    "reason": f"size={r['func_size']}, bb={r['bb_count']}, apis={r['api_count']}",
                    "interest_score": 0.5,
                    "api_count": r["api_count"],
                    "bb_count": r["bb_count"],
                    "has_loops": r["has_loops"],
                })
            return results[:limit]
        except Exception:
            return []

    def stop(self) -> None:
        """Shut down the llama-server subprocess cleanly."""
        self._embedder.stop()

    @property
    def status(self) -> dict[str, Any]:
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
            "embed_batch_size": getattr(self._embedder, "_batch_size", 1),
        }


# Module-level singleton access
# ─────────────────────────────────────────────────────────────────────────────

_assembler: ContextAssembler | None = None
_assembler_lock = threading.Lock()


def get_assembler() -> ContextAssembler:
    global _assembler
    with _assembler_lock:
        if _assembler is None:
            _assembler = ContextAssembler()
    return _assembler


def _shutdown_intelligence_singleton() -> None:
    try:
        if _assembler is not None:
            _assembler.stop()
    except Exception:
        pass


atexit.register(_shutdown_intelligence_singleton)
