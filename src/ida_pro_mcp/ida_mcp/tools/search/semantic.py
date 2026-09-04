"""SEARCH.SEMANTIC — Orchestration point for embedding/behavior NL search.

All semantic/behavior NL actions in the search tool delegate here.  Other
tool modules (gadgets, modify, intelligence) also call
FunctionEmbeddingIndex / BehaviorClassifier directly, so this module is a
convenience orchestrator, not the sole caller.

Architecture:
  get_backend()         — resolves (index, classifier, idb_path) with graceful error
  search_nl()           — natural language retrieval via FunctionEmbeddingIndex.search()
  search_behavior()     — tag-based lookup via insight index + BehaviorClassifier
"""

from __future__ import annotations

import time as _time

from .._common import (
    MCPError,
    ida_hexrays,
    idautils,
    idc,
    make_error,
    os
)

from .core import (
    SearchTimeout,
)


# Absolute confidence floor for behavior-driven query expansion.  Expansion
# only fires when the classifier clears this AND the relative median/quartile
# margin gate, so an unrelated behavior label never becomes a search query.
EXPANSION_MIN_CONFIDENCE = float(
    os.environ.get("IDA_MCP_EXPANSION_MIN_CONFIDENCE", "0.50") or 0.50
)

# Cross-encoder rerank budget.  The native CPU backend costs roughly
# 0.5-5s per (query, doc) pair on an 8-core box, so an unbounded pool turns
# a "quick" search into a silent multi-minute CPU burn that the host RPC
# timeout then reports as a hang.  These caps keep the rerank phase bounded
# while preserving its purpose: re-ordering the TOP of the recall list, not
# re-scoring the long tail.
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


# Max (query, doc) pairs scored by the cross-encoder in one search. The
# 0.6B Qwen3 benchmark reaches 12/12 top-1 on an 8-candidate pool while
# avoiding the extra CPU forward passes of the old 12-candidate default.
RERANK_POOL_MAX = max(1, _env_int("IDA_MCP_RERANK_POOL", 8))
# Per-document character budget handed to the cross-encoder (~260 tokens).
# Longer docs are what make an 8-pair rerank take minutes on CPU (a 0.6B
# cross-encoder runs at ~15-60 tok/s on an 8-core box); the first ~250
# tokens of a function's pseudocode carry the decisive signal.
RERANK_DOC_BUDGET_CHARS = max(256, _env_int("IDA_MCP_RERANK_DOC_BUDGET_CHARS", "800"))

# Bounded document text handed to the cross-encoder when a candidate has no
# persisted document_text (legacy index row).  Matches the reranker's own
# payload truncation so the decompile fallback never exceeds it.
RERANK_MAX_DOC_CHARS = 6000


# ---------------------------------------------------------------------------
# Backend resolution
# ---------------------------------------------------------------------------

def get_backend():
    """Resolve the semantic search backend.

    Returns (index, classifier, idb_path, degraded) — ``degraded`` is "" when
    the embedding backend started, or a note when it could not start but the
    index is non-empty (lexical-only ranking is still meaningful).  Returns a
    descriptive error dict when the index is empty too, or the environment
    cannot resolve an IDB.  Either import path is supported so this works in
    both package and test modes.
    """
    try:
        from ida_pro_mcp.services import get_assembler
        asm = get_assembler()
    except ImportError:
        try:
            from host.intelligence.context import get_assembler  # type: ignore
            asm = get_assembler()
        except ImportError:
            return _err("Semantic search unavailable: could not import context.assembler.")

    idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
    if not idb_path:
        return _err(
            "Semantic search requires an active IDB.",
            hint="Open a binary and retry.",
        )

    idx = asm._get_index(idb_path)
    if idx.size == 0 or idx.db_changed_since_load():
        # The host may have copied an exact-binary index into this session
        # after the IDA-side assembler first cached an empty reader, or the
        # index was rebuilt (fast -> decompile quality) behind our back.
        # Either way the in-RAM vectors are stale and must be reloaded.
        try:
            idx.refresh_from_disk()
        except Exception:
            pass
    if idx.size == 0:
        return _err(
            "No embeddings indexed yet.",
            hint=(
                "Run intelligence(action='index_fast') (seconds, disassembly-based) "
                "or intelligence(action='index_batch') (minutes, decompile-based) first."
            ),
        )

    # This is the explicit semantic-search path.  It is the right place to
    # activate the local model; routine tool/context paths intentionally do
    # not cold-start llama.cpp.  When the model cannot start but the index has
    # rows, degrade to lexical-only ranking instead of refusing the search: a
    # user on an opaque firmware blob is better served by partial results with
    # an honest note than by a crisp "backend unavailable" error.
    if not asm.ensure_embedding_server():
        return idx, None, idb_path, (
            "degraded — embedding backend unavailable; results ranked by "
            "lexical overlap only. Configure an embedding model and "
            "llama-server, then retry."
        )

    classifier = asm._behavior_classifier()
    return idx, classifier, idb_path, ""


def _err(message: str, hint: str = "") -> dict:
    payload = make_error(MCPError.NOT_FOUND, message)
    if hint:
        payload["hint"] = hint
    return payload


def _call_rerank(rr, query: str, docs: list[str], deadline: float):
    """Invoke a reranker, passing the deadline when the backend accepts it.

    The real Reranker.rerank/NativeReranker.rerank take an optional
    ``deadline`` keyword; lightweight/scripted rerankers used in tests do not.
    ``inspect.signature`` lets us detect support without catching a TypeError
    that might otherwise mask a genuine runtime failure inside the reranker.
    """
    try:
        import inspect
        sig = inspect.signature(rr.rerank)
    except Exception:
        sig = None
    if sig is not None and "deadline" in sig.parameters:
        return rr.rerank(query, docs, deadline=deadline)
    return rr.rerank(query, docs)



# ---------------------------------------------------------------------------
# search_nl — natural language retrieval
# ---------------------------------------------------------------------------

def search_nl(
    query: str,
    limit: int = 10,
    mode: str = "expand",
    *,
    min_score: float = 0.0,
    timeout_ms: int = 0,
    include_items: bool = False,
    classifier_threshold: float = 0.25,
    range_start: int | None = None,
    range_end: int | None = None,
    center_ea: int | None = None,
    radius: int | None = None,
    rerank: bool | None = None,
) -> dict:
    """Natural language search via FunctionEmbeddingIndex.

    Args:
        query: Natural language query (e.g. "function that handles AES key schedule").
        limit: Max results to return.
        mode: "quick" for hybrid search only, "expand" for behavior-driven expansion.
        min_score: Minimum similarity threshold (0.0 = no threshold).
        timeout_ms: Timeout in ms (0 = 10s default).
        include_items: Include structured items in response.
        classifier_threshold: Confidence threshold for behavior expansion.
        rerank: Cross-encode the recalled candidates with the reranker to fix
            the top of the list.  None (default) auto-selects: applied in
            "expand" mode, skipped in "quick" mode so quick stays bounded;
            pass True to force or False to disable.  A no-op when no rerank
            model is installed or the model is non-discriminating.

    Returns:
        Response dict with results, similarity scores, and expansion metadata.
    """
    if not query or not query.strip():
        return make_error(MCPError.INVALID_ARGS, "query required for nl search")

    backend = get_backend()
    if isinstance(backend, dict):
        return backend
    if len(backend) == 4:
        idx, classifier, _idb_path, degraded_note = backend
    else:  # tolerate a legacy 3-tuple backend (older callers / test stubs)
        idx, classifier, _idb_path = backend
        degraded_note = ""

    if not timeout_ms or timeout_ms <= 0:
        timeout_ms = 10000

    started_at = _time.time()

    scope_start = range_start
    scope_end = range_end
    if center_ea is not None and radius is not None:
        try:
            radius_int = int(radius)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "radius must be an integer")
        if radius_int <= 0:
            return make_error(MCPError.INVALID_ARGS, "radius must be greater than zero")
        try:
            from ida_pro_mcp.host.intelligence.scope_window import radius_address_range
        except ImportError:
            from host.intelligence.scope_window import radius_address_range  # type: ignore
        try:
            radius_start, radius_end = radius_address_range(int(center_ea), radius_int)
        except ValueError as exc:
            return make_error(MCPError.INVALID_ARGS, str(exc))
        scope_start = max(scope_start, radius_start) if scope_start is not None else radius_start
        scope_end = min(scope_end, radius_end) if scope_end is not None else radius_end
    if scope_start is not None and scope_end is not None and scope_end <= scope_start:
        return make_error(MCPError.INVALID_ARGS, "range and radius scopes do not overlap")
    address_ranges = (
        [(scope_start if scope_start is not None else 0, scope_end if scope_end is not None else (1 << 64))]
        if scope_start is not None or scope_end is not None
        else None
    )

    # Phase 0: decide rerank before recall so the candidate pool can be aligned
    # to it.  When the cross-encoder is going to re-score the top of the list,
    # recalling a wide 64-pool we then truncate to the rerank budget wastes
    # Stage-1 work; when it is not, inflating recall to RERANK_MAX_CANDIDATES
    # is equally wasteful.
    want_rerank = bool(rerank) if rerank is not None else (mode == "expand")
    try:
        from ida_pro_mcp.host.intelligence.rerank import RERANK_MAX_CANDIDATES
    except Exception:
        RERANK_MAX_CANDIDATES = 64
    if want_rerank:
        candidate_limit = min(max(limit, RERANK_POOL_MAX), 256)
    else:
        candidate_limit = min(max(24, limit * 5), 256)

    # Phase 1: primary search via hybrid semantic+lexical. The embedding index
    # applies address_ranges before top-k truncation.
    raw_results = idx.search(
        query,
        top_k=candidate_limit,
        threshold=0.0,
        address_ranges=address_ranges,
    )

    # Phase 2: behavior-driven query expansion (only in "expand" mode)
    expansion_queries: list[str] = []
    if mode == "expand" and classifier is not None:
        try:
            hits = classifier.classify(query[:600], threshold=classifier_threshold, top_k=4, block=False)
            if hits:
                # The zero-shot classifier is cosine between a natural-language
                # query and pseudocode anchors — that similarity is inherently
                # mushy.  A low floor (0.25-0.30) lets unrelated behaviors
                # (e.g. "crypto symmetric" for a GPU-allocation query) leak in
                # and pollute the merged ranking, so expansion must clear a
                # real bar: an absolute floor plus a relative margin over the
                # tail (same median/quartile rule search_behavior uses).
                confs = sorted(
                    float(h.get("confidence") or 0.0) for h in hits
                )
                q50 = confs[len(confs) // 2]
                q75 = confs[min(len(confs) - 1, int(round((len(confs) - 1) * 0.75)))]
                gate = max(
                    float(classifier_threshold or 0.0),
                    EXPANSION_MIN_CONFIDENCE,
                    q50 + max(0.0, q75 - q50),
                )
                expansion_queries = [
                    str(h.get("behavior") or "").strip().replace("_", " ")
                    for h in hits
                    if h.get("behavior")
                    and float(h.get("confidence") or 0.0) >= gate
                ]
                expansion_queries = [q for q in expansion_queries if q]
        except Exception:
            pass

        if expansion_queries:
            merged_by_ea: dict[str, dict] = {}
            for r in raw_results:
                ea_key = str(r.get("ea") or "")
                if ea_key:
                    merged_by_ea[ea_key] = dict(r)

            # Run each expansion search only over the top recalled EAs instead
            # of the whole binary: each extra hybrid_search is otherwise a full
            # embedding scan.  One (ea, ea+1) range per recalled entry limits
            # the candidate set to exactly those functions, so expansion cost
            # stays O(top-K) regardless of binary size.
            try:
                idx_size = int(getattr(idx, "size", 0) or 0)
            except Exception:
                idx_size = 0
            recalled_eas = []
            for r in raw_results[: max(limit * 2, 16)]:
                try:
                    recalled_eas.append(int(str(r.get("ea") or ""), 0))
                except (TypeError, ValueError):
                    continue
            if recalled_eas:
                expansion_ranges = [(ea, ea + 1) for ea in recalled_eas]
            else:
                expansion_ranges = address_ranges
            # Very large binaries gate expansion to a single extra query so a
            # behavior explosion cannot extend the search past the deadline.
            cap_extra = 1 if idx_size > 8000 else 3

            for extra_q in expansion_queries[:cap_extra]:
                if (_time.time() - started_at) >= (timeout_ms / 1000.0):
                    break
                try:
                    extra_hits = idx.search(
                        extra_q,
                        top_k=max(3, limit),
                        threshold=0.0,
                        address_ranges=expansion_ranges,
                    )
                except Exception:
                    continue
                for h in extra_hits:
                    ea_key = str(h.get("ea") or "")
                    if not ea_key:
                        continue
                    base = merged_by_ea.get(ea_key)
                    extra_sim = float(h.get("similarity") or 0.0)
                    if not base:
                        merged_by_ea[ea_key] = dict(h)
                        merged_by_ea[ea_key]["similarity"] = extra_sim * 0.92
                        merged_by_ea[ea_key]["expansion_query"] = extra_q
                    else:
                        base_sim = float(base.get("similarity") or 0.0)
                        if extra_sim > base_sim:
                            base["similarity"] = max(base_sim, extra_sim * 0.96)
                            base["expansion_query"] = extra_q

            raw_results = sorted(
                merged_by_ea.values(),
                key=lambda x: float(x.get("similarity") or 0.0),
                reverse=True,
            )

    # Phase 3: deterministic address scoping before score gating. Fetching a
    # wider candidate set above ensures a narrow radius is not starved by
    # globally higher-ranked functions outside the requested region.
    if scope_start is not None or scope_end is not None:
        scoped_results = []
        for result in raw_results:
            try:
                ea = int(str(result.get("ea") or ""), 0)
            except (TypeError, ValueError):
                continue
            if scope_start is not None and ea < scope_start:
                continue
            if scope_end is not None and ea >= scope_end:
                continue
            scoped_results.append(result)
        raw_results = scoped_results

    # Phase 3.5: cross-encoder reranking of the scoped candidate pool.  Stage 1
    # recall is a bi-encoder — query and document vectors never see each other.
    # The reranker re-scores each (query, doc) pair with full cross-attention so
    # the top of the list is correct, not merely nearby.  This is a quality
    # boost, never a hard gate: if the reranker is unavailable, misconfigured,
    # or returns non-discriminating scores (e.g. a headless conversion), the
    # recall order is preserved and the response says why.
    rerank_meta = {"profile": None, "applied": False, "pool": 0, "latency_ms": 0}
    if not want_rerank:
        if rerank is None:
            rerank_meta["reason"] = (
                f"quick mode keeps latency bounded; pass rerank=true to force "
                f"cross-encoder re-scoring (pool capped at {RERANK_POOL_MAX})"
            )
        else:
            rerank_meta["reason"] = "rerank disabled by caller"
    if want_rerank and raw_results:
        try:
            from ida_pro_mcp.host.intelligence.rerank import Reranker
        except Exception:
            Reranker = None  # type: ignore[assignment]
        if Reranker is not None:
            try:
                rr = Reranker()
            except Exception:
                rr = None
            if rr is not None and getattr(rr, "_use_llama", False):
                # The rerank phase shares the caller's search deadline: check
                # before starting and hand the deadline into the reranker so it
                # can bail between CPU chunks.  An expired deadline keeps the
                # recall order and explains itself instead of burning the budget.
                budget_sec = (timeout_ms / 1000.0) - max(0.0, _time.time() - started_at)
                rerank_deadline = _time.monotonic() + max(0.0, budget_sec)
                if _time.monotonic() >= rerank_deadline:
                    rerank_meta["reason"] = "timeout"
                else:
                    pool = raw_results[: min(RERANK_MAX_CANDIDATES, candidate_limit)]
                    eas = [str(r.get("ea") or "") for r in pool]
                    docs: list[str] = []
                    try:
                        stored = (
                            idx._row_docs_for_eas(eas)
                            if hasattr(idx, "_row_docs_for_eas") else {}
                        )
                    except Exception:
                        # Persisted document text is an optimization.  A
                        # damaged or unavailable side table must not turn a
                        # useful recall result into a failed search.
                        stored = {}
                    for ea, r in zip(eas, pool, strict=True):
                        doc = stored.get(ea) or r.get("signature") or ""
                        if not doc and ea:
                            try:
                                ea_int = int(ea, 0)
                                cfunc = ida_hexrays.decompile(ea_int)
                                doc = str(cfunc)[:RERANK_MAX_DOC_CHARS] if cfunc else ""
                            except Exception:
                                doc = ""
                        docs.append((doc or str(r.get("name") or ea))[:RERANK_DOC_BUDGET_CHARS])
                    rerank_started = _time.time()
                    scored = _call_rerank(rr, query, docs, rerank_deadline) if docs else None
                    rerank_meta["latency_ms"] = round((_time.time() - rerank_started) * 1000)
                    if scored:
                        by_index = {int(item["index"]): float(item["score"]) for item in scored}
                        discriminating = len(set(by_index.values())) >= 2
                        indices_in_pool = bool(by_index) and max(by_index) < len(pool) and min(by_index) >= 0
                        if discriminating and len(by_index) == len(pool) and indices_in_pool:
                            for i, r in enumerate(pool):
                                r["rerank_score"] = by_index.get(i)
                                r["rank_reason"] = {
                                    **(r.get("rank_reason") or {}),
                                    "rerank": round(by_index.get(i, 0.0), 4),
                                }
                            pool.sort(key=lambda r: float(r.get("rerank_score") or 0.0), reverse=True)
                            raw_results = pool
                            rerank_meta["applied"] = True
                        rerank_meta["profile"] = rr.status().get("profile_name")
                    rerank_meta["pool"] = len(pool)
        if rerank_meta["applied"]:
            for r in raw_results:
                if "rerank_score" in r:
                    r["score"] = r["rerank_score"]

    # Phase 4: adaptive gating on the score used to rank the hybrid results.
    # Gating only on raw cosine similarity discarded strong lexical matches
    # (for example, an exact API or string reference) after hybrid_search had
    # correctly promoted them.  When reranking applied, the rerank score is the
    # ordering signal and gates here.
    def rank_score(result: dict) -> float:
        return float(result.get("score") or result.get("similarity") or 0.0)

    scores = [rank_score(r) for r in raw_results]
    if scores and min_score <= 0.0:
        ss = sorted(scores)
        q50 = ss[len(ss) // 2]
        q75 = ss[min(len(ss) - 1, int(round((len(ss) - 1) * 0.75)))]
        gate = q50 + max(0.0, q75 - q50)
        filtered = [r for r in raw_results if rank_score(r) >= gate]
        raw_results = (filtered or raw_results)[:limit]
    elif min_score > 0.0:
        raw_results = [r for r in raw_results if rank_score(r) >= min_score][:limit]
    else:
        raw_results = raw_results[:limit]

    rows = []
    for r in raw_results:
        ea_str = r.get("ea", "")
        name = r.get("name", ea_str)
        sim = r.get("similarity", 0)
        rows.append(f"{ea_str}  {name}  similarity={sim:.3f}")

    response = {
        "ok": True,
        "action": "nl",
        "query": query,
        "mode": mode,
        "backend_bge": getattr(idx, "_embedder", None) and getattr(idx._embedder, "backend", "unavailable"),
        "results": "\n".join(rows),
        "count": len(rows),
        "scope": {
            "start": hex(scope_start) if scope_start is not None else None,
            "end": hex(scope_end) if scope_end is not None else None,
            "center": hex(center_ea) if center_ea is not None else None,
            "radius": int(radius) if radius is not None else None,
        },
        "items": [
            {
                "addr": r.get("ea"),
                "name": r.get("name"),
                "similarity": r.get("similarity"),
                "score": r.get("score"),
                "rerank_score": r.get("rerank_score"),
                "signature": r.get("signature"),
                "expansion_query": r.get("expansion_query"),
                "rank_reason": r.get("rank_reason"),
            }
            for r in raw_results
        ],
        "note": (
            f"Natural language retrieval via FunctionEmbeddingIndex.search() "
            f"(mode={mode}, expansion_queries={len(expansion_queries)}, "
            f"rerank={'on' if rerank_meta['applied'] else 'off'})."
        ),
        "rerank": rerank_meta,
    }
    if degraded_note:
        response["degraded"] = degraded_note
    if expansion_queries:
        response["expansion_queries"] = expansion_queries[:3]
    return response


# ---------------------------------------------------------------------------
# search_behavior — tag-based classification lookup
# ---------------------------------------------------------------------------

def search_behavior(
    tag: str,
    limit: int = 100,
    *,
    timeout_ms: int = 0,
    include_items: bool = False,
) -> dict:
    """Find functions matching a behavior tag.

    Two-stage lookup:
      1. L1 insight index (fast tag_map query).
      2. BehaviorClassifier on unnamed functions (if needed).

    Args:
        tag: Behavior tag (e.g. "crypto_symmetric", "network_http").
        limit: Max results.
        timeout_ms: Timeout in ms (0 = 10s default).
        include_items: Include structured items.

    Returns:
        Response dict with matched functions and their sources.
    """
    if not tag or not tag.strip():
        return make_error(
            MCPError.INVALID_ARGS,
            "tag required for behavior search",
            hint="Common tags: crypto_symmetric, network_http, network_socket, file_io, memory_alloc, process_exec, anti_analysis, persistence, credential_access",
        )

    normalized_tag = tag.strip().lower().replace(" ", "_")

    if not timeout_ms or timeout_ms <= 0:
        timeout_ms = 10000

    timer = SearchTimeout(timeout_ms)
    rows: list[dict] = []

    # Stage 1: L1 insight index
    try:
        from . import _query_insight_by_tags

        l1_addrs = _query_insight_by_tags([normalized_tag], mode="or")
    except Exception:
        # The optional L1 index is an accelerator, not a prerequisite for the
        # classifier path below.
        l1_addrs = []
    if l1_addrs:
        for addr_str in l1_addrs[:limit]:
            try:
                timer.check()
            except TimeoutError:
                break
            try:
                ea = int(addr_str, 16)
                name = idc.get_func_name(ea) or addr_str
                rows.append({"addr": addr_str, "name": name, "source": "insight_index"})
            except Exception:
                pass

    # Stage 2: BehaviorClassifier on unnamed functions (if needed)
    classifier_cold = False
    if len(rows) < limit // 2:
        try:
            backend = get_backend()
            if isinstance(backend, dict):
                pass
            else:
                if len(backend) == 4:
                    idx, classifier, _idb_path, _degraded = backend
                else:  # tolerate a legacy 3-tuple backend
                    idx, classifier, _idb_path = backend
                # A classifier whose anchor cache was never populated cannot
                # produce meaningful zero-shot labels; every classify() call
                # would be a wasted decompile.  Skip the up-to-200 decompile
                # loop and say so instead of silently returning partials.
                anchors = getattr(classifier, "_anchor_embs", None) or {}
                if not anchors:
                    classifier_cold = True
                else:
                    checked = 0
                    for func_ea in idautils.Functions():
                        if checked >= 200 or len(rows) >= limit:
                            break
                        try:
                            timer.check()
                        except TimeoutError:
                            break
                        fname = idc.get_func_name(func_ea) or ""
                        if not (fname.startswith(("sub_", "j_"),)):
                            continue
                        try:
                            cfunc = ida_hexrays.decompile(func_ea)
                            if not cfunc:
                                continue
                            pseudo = str(cfunc)[:2000]
                            hits = classifier.classify(pseudo, threshold=0.0, top_k=5, block=False)
                            if hits:
                                hs = sorted(
                                    float(h.get("confidence", h.get("score", 0.0)) or 0.0)
                                    for h in hits
                                )
                                q50 = hs[len(hs) // 2]
                                q75 = hs[min(len(hs) - 1, int(round((len(hs) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [
                                    h for h in hits
                                    if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate
                                ]
                            if any(h.get("behavior", "").lower() == normalized_tag for h in hits):
                                rows.append({
                                    "addr": hex(func_ea),
                                    "name": fname,
                                    "source": "classifier",
                                    "confidence": max(
                                        (
                                            float(h.get("confidence", h.get("score", 0)) or 0)
                                            for h in hits
                                            if h.get("behavior", "").lower() == normalized_tag
                                        ),
                                        default=0,
                                    ),
                                })
                        except Exception:
                            pass
                        checked += 1
        except Exception:
            pass

    lines = [
        f"{r['addr']}  {r['name']}  [{r['source']}]"
        + (f"  conf={r.get('confidence', 0):.2f}" if r.get("confidence") else "")
        for r in rows
    ]

    response = {
        "ok": True,
        "action": "behavior",
        "behavior": normalized_tag,
        "results": "\n".join(lines),
        "count": len(rows),
        "items": rows,
        "note": (
            f"Functions classified as '{normalized_tag}' via "
            f"L1 insight index ({sum(1 for r in rows if r['source'] == 'insight_index')}) "
            f"+ BehaviorClassifier ({sum(1 for r in rows if r['source'] == 'classifier')})."
        ),
    }
    if classifier_cold:
        response["classifier_cold"] = True
        response["timed_out"] = True
        response["note"] += (
            " Classifier cold — Stage 2 (BehaviorClassifier) skipped; "
            "run intelligence(action='index') first."
        )
    return response
