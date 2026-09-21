"""Bounded lexical search with optional provider-backed advisory ranking.

All natural-language search actions delegate here.  The index is deterministic
and lexical; Jev/custom typed questions may add advisory behavior expansion or
reranking, but never replace the lexical result set or authorize an action.
"""

from __future__ import annotations

import time as _time

from .._common import MCPError, idautils, idc, make_error, os
from ..intelligence import _build_fast_signature
from ... import compat as _compat

from .core import (
    SearchTimeout,
)


# Absolute confidence floor for behavior-driven query expansion.  Expansion
# only fires when the classifier clears this AND the relative median/quartile
# margin gate, so an unrelated behavior label never becomes a search query.
EXPANSION_MIN_CONFIDENCE = float(os.environ.get("IDA_MCP_EXPANSION_MIN_CONFIDENCE", "0.50") or 0.50)


# Typed-question rerank budget. Provider requests are bounded and advisory;
# lexical order remains authoritative when the provider is disabled/unavailable.
# These are code-level safety bounds, not provider-selection settings.
RERANK_POOL_MAX = 8
# Per-document character budget before signature extraction.
RERANK_DOC_BUDGET_CHARS = 800

# Bounded source text handed to signature extraction when a candidate has no
# persisted signature.
RERANK_MAX_DOC_CHARS = 6000


# ---------------------------------------------------------------------------
# Backend resolution
# ---------------------------------------------------------------------------


def get_backend():
    """Resolve the deterministic lexical search view.

    Typed-question providers do not create or compare vectors.  Existing
    signature/index rows remain searchable through the bounded lexical path;
    model-backed ranking is explicit provider work elsewhere.
    """
    idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
    if not idb_path:
        return _err("Semantic search requires an active IDB.", hint="Open a binary and retry.")
    try:
        from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path
    except ImportError:
        from host.intelligence.lexical import LexicalFunctionIndex, signature_index_path  # type: ignore
    idx = LexicalFunctionIndex(signature_index_path(idb_path))
    try:
        from ida_pro_mcp.host.intelligence.core import BehaviorClassifier

        classifier = BehaviorClassifier.instance()
    except Exception:
        classifier = None
    if idx.size == 0:
        return _err(
            "No lexical function signatures indexed yet.",
            hint="Run deterministic function listing/search or migrate an existing signature index first.",
        )
    return idx, classifier, idb_path, "lexical-only — typed-question providers do not expose embeddings"


def _err(message: str, hint: str = "") -> dict:
    payload = make_error(MCPError.NOT_FOUND, message)
    if hint:
        payload["hint"] = hint
    return payload


def _call_rerank(rr, query: str, docs: list[str], deadline: float, session_id: str = ""):
    """Invoke a reranker, passing the deadline when the backend accepts it.

    The provider-backed reranker accepts an optional ``deadline`` keyword;
    lightweight/scripted rerankers used in tests do not.
    ``inspect.signature`` lets us detect support without catching a TypeError
    that might otherwise mask a genuine runtime failure inside the reranker.
    """
    try:
        import inspect

        sig = inspect.signature(rr.rerank)
    except Exception:
        sig = None
    call_kwargs = {}
    if sig is not None and "deadline" in sig.parameters:
        call_kwargs["deadline"] = deadline
    if sig is not None and "session_id" in sig.parameters:
        call_kwargs["session_id"] = session_id
    return rr.rerank(query, docs, **call_kwargs)


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
    session_id: str = "",
) -> dict:
    """Natural-language search via the deterministic lexical function index.

    Args:
        query: Natural language query (e.g. "function that handles AES key schedule").
        limit: Max results to return.
        mode: "quick" for hybrid search only, "expand" for behavior-driven expansion.
        min_score: Minimum similarity threshold (0.0 = no threshold).
        timeout_ms: Timeout in ms (0 = 10s default).
        include_items: Include structured items in response.
        classifier_threshold: Confidence threshold for behavior expansion.
        rerank: Ask the explicit provider to score bounded signatures.  None
            (default) enables this in "expand" mode and skips it in "quick"
            mode; pass True to force or False to disable.  A no-op when the
            provider is disabled, unavailable, or non-discriminating.

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
    address_ranges = [(scope_start if scope_start is not None else 0, scope_end if scope_end is not None else (1 << 64))] if scope_start is not None or scope_end is not None else None

    # Phase 0: decide advisory scoring before recall so the candidate pool can
    # be aligned to it. When the typed-question provider scores the top of the list,
    # recalling a wide 64-pool we then truncate to the rerank budget wastes
    # Stage-1 work; when it is not, inflating recall to RERANK_MAX_CANDIDATES
    # is equally wasteful.
    # Typed providers may score bounded candidates through an explicit
    # advisory path. Disabled/unavailable providers preserve lexical order;
    # this operation never starts a local model implicitly.
    want_rerank = bool(rerank) or (rerank is None and mode == "expand")
    try:
        from ida_pro_mcp.host.intelligence.rerank import RERANK_MAX_CANDIDATES
    except Exception:
        RERANK_MAX_CANDIDATES = 64
    if want_rerank:
        candidate_limit = min(max(limit, RERANK_POOL_MAX), 256)
    else:
        candidate_limit = min(max(24, limit * 5), 256)

    # Phase 1: primary deterministic lexical search. The index applies
    # address_ranges before top-k truncation.
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
            try:
                hits = classifier.classify(
                    query[:600],
                    threshold=classifier_threshold,
                    top_k=4,
                    block=False,
                    session_id=session_id,
                )
            except TypeError:
                # Preserve compatibility with injected legacy test doubles;
                # production BehaviorClassifier accepts session attribution.
                hits = classifier.classify(query[:600], threshold=classifier_threshold, top_k=4, block=False)
            if hits:
                # The zero-shot classifier is cosine between a natural-language
                # query and pseudocode anchors — that similarity is inherently
                # mushy.  A low floor (0.25-0.30) lets unrelated behaviors
                # (e.g. "crypto symmetric" for a GPU-allocation query) leak in
                # and pollute the merged ranking, so expansion must clear a
                # real bar: an absolute floor plus a relative margin over the
                # tail (same median/quartile rule search_behavior uses).
                confs = sorted(float(h.get("confidence") or 0.0) for h in hits)
                q50 = confs[len(confs) // 2]
                q75 = confs[min(len(confs) - 1, int(round((len(confs) - 1) * 0.75)))]
                gate = max(
                    float(classifier_threshold or 0.0),
                    EXPANSION_MIN_CONFIDENCE,
                    q50 + max(0.0, q75 - q50),
                )
                expansion_queries = [str(h.get("behavior") or "").strip().replace("_", " ") for h in hits if h.get("behavior") and float(h.get("confidence") or 0.0) >= gate]
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

    # Phase 3.5: optional provider advisory scoring of the bounded signature
    # pool.  This is a quality boost, never a hard gate: if the provider is
    # unavailable, misconfigured, or non-discriminating, lexical order remains
    # authoritative and the response says why.
    rerank_meta = {"profile": None, "applied": False, "pool": 0, "latency_ms": 0}
    if not want_rerank:
        if rerank is None:
            rerank_meta["reason"] = f"quick mode keeps latency bounded; pass rerank=true to force typed-question advisory scoring (pool capped at {RERANK_POOL_MAX})"
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
            enabled = True
            if rr is not None and hasattr(rr, "is_enabled"):
                try:
                    enabled = bool(rr.is_enabled())
                except Exception:
                    enabled = False
            if rr is not None and not enabled:
                provider_error = getattr(rr, "last_error", None)
                if provider_error:
                    rerank_meta["error"] = provider_error
                    rerank_meta["reason"] = "provider_error"
            if rr is not None and enabled:
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
                        stored = idx._row_docs_for_eas(eas) if hasattr(idx, "_row_docs_for_eas") else {}
                    except Exception:
                        # Persisted document text is an optimization.  A
                        # damaged or unavailable side table must not turn a
                        # useful recall result into a failed search.
                        stored = {}
                    for ea, r in zip(eas, pool, strict=True):
                        doc = stored.get(ea) or r.get("signature") or ""
                        # Never decompile solely for provider scoring. A
                        # persisted signature or name is sufficient and keeps
                        # raw pseudocode outside the advisory transport.
                        docs.append((doc or str(r.get("name") or ea))[:RERANK_DOC_BUDGET_CHARS])
                    rerank_started = _time.time()
                    scored = _call_rerank(
                        rr,
                        query,
                        docs,
                        rerank_deadline,
                        session_id,
                    ) if docs else None
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
                        status = rr.status() if hasattr(rr, "status") else {}
                        rerank_meta["profile"] = status.get("profile_name") if isinstance(status, dict) else None
                    rerank_meta["pool"] = len(pool)
                    provider_error = getattr(rr, "last_error", None) if rr is not None else None
                    if provider_error and not rerank_meta["applied"]:
                        rerank_meta["error"] = provider_error
                        rerank_meta["reason"] = "provider_error"
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
        "backend": "lexical",
        "advisory_provider": getattr(idx, "_embedder", None) and getattr(idx._embedder, "backend", "unavailable"),
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
        "note": (f"Deterministic lexical retrieval with optional typed-question advisory scoring (mode={mode}, expansion_queries={len(expansion_queries)}, rerank={'on' if rerank_meta['applied'] else 'off'})."),
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
      2. Bounded provider behavior questions on unnamed functions (if needed).

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
    classifier_cold = False

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

    # Stage 2: provider-backed behavior questions on unnamed functions (if needed)
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
                # Preserve the old no-work guard for injected classifier
                # doubles that explicitly expose an empty anchor cache.  The
                # production provider-backed classifier has a different class
                # and evaluates bounded typed questions per request.
                if (
                    classifier is not None
                    and classifier.__class__.__name__ != "BehaviorClassifier"
                    and hasattr(classifier, "_anchor_embs")
                    and not getattr(classifier, "_anchor_embs", None)
                ):
                    classifier_cold = True
                checked = 0
                for func_ea in () if classifier_cold else idautils.Functions():
                    if checked >= 200 or len(rows) >= limit:
                        break
                    try:
                        timer.check()
                    except TimeoutError:
                        break
                    fname = idc.get_func_name(func_ea) or ""
                    if not fname.startswith(("sub_", "j_")):
                        continue
                    try:
                        func = _compat.get_func_info(func_ea)
                        if func is None:
                            continue
                        signature = _build_fast_signature(func_ea, func)
                        hits = classifier.classify(signature, threshold=0.0, top_k=5, block=False)
                        if hits:
                            hs = sorted(
                                float(h.get("confidence", h.get("score", 0.0)) or 0.0)
                                for h in hits
                            )
                            q50 = hs[len(hs) // 2]
                            q75 = hs[min(len(hs) - 1, int(round((len(hs) - 1) * 0.75)))]
                            gate = q50 + max(0.0, q75 - q50)
                            hits = [
                                h
                                for h in hits
                                if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate
                            ]
                        matching = [
                            h for h in hits
                            if str(h.get("behavior", "")).lower() == normalized_tag
                        ]
                        if matching:
                            rows.append(
                                {
                                    "addr": hex(func_ea),
                                    "name": fname,
                                    "source": "classifier",
                                    "confidence": max(
                                        (float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in matching),
                                        default=0.0,
                                    ),
                                }
                            )
                    except Exception:
                        pass
                    checked += 1
        except Exception:
            pass

    lines = [f"{r['addr']}  {r['name']}  [{r['source']}]" + (f"  conf={r.get('confidence', 0):.2f}" if r.get("confidence") else "") for r in rows]

    response = {
        "ok": True,
        "action": "behavior",
        "behavior": normalized_tag,
        "results": "\n".join(lines),
        "count": len(rows),
        "items": rows,
        "note": (
            "Classifier cold; provider advisory was not queried. "
            if classifier_cold
            else f"Functions classified as '{normalized_tag}' via "
            f"L1 insight index ({sum(1 for r in rows if r['source'] == 'insight_index')}) "
            f"+ provider advisory ({sum(1 for r in rows if r['source'] == 'classifier')})."
        ),
    }
    if classifier_cold:
        response["classifier_cold"] = True
        response["timed_out"] = True
    return response
