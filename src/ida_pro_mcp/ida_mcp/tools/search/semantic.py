"""Bounded lexical search with optional host-side provider advisory ranking.

All natural-language search actions delegate here.  The index is deterministic
and lexical; Jev/custom typed questions may add advisory behavior expansion or
reranking, but never replace the lexical result set or authorize an action.
"""

from __future__ import annotations

import time as _time

from .._common import MCPError, idautils, idc, make_error
from ..intelligence import _build_fast_signature
from ... import compat as _compat

from .core import (
    SearchTimeout,
)


# Typed-question rerank budget. Provider requests are bounded and advisory;
# lexical order remains authoritative when the provider is disabled/unavailable.
# These are code-level safety bounds, not provider-selection settings.
RERANK_POOL_MAX = 8
# Keep the transport candidate cap provider-neutral here. Importing the host
# reranker into IDA would load provider modules in the analysis process.
HOST_RERANK_MAX_CANDIDATES = 64
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
    if idx.size == 0:
        return _err(
            "No lexical function signatures indexed yet.",
            hint="Run deterministic function listing/search or migrate an existing signature index first.",
        )
    return idx, None, idb_path, "lexical-only — typed-question providers do not expose embeddings"


def _err(message: str, hint: str = "") -> dict:
    payload = make_error(MCPError.NOT_FOUND, message)
    if hint:
        payload["hint"] = hint
    return payload


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
    host_expansion_queries: list[str] | None = None,
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
        idx, _classifier, _idb_path, degraded_note = backend
    else:  # tolerate a legacy 3-tuple backend (older callers / test stubs)
        idx, _classifier, _idb_path = backend
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
    if mode == "expand":
        expansion_queries = [
            str(value).strip()[:128]
            for value in (host_expansion_queries or [])[:3]
            if str(value).strip()
        ]
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

    # Phase 3.5: scoring happens in the MCP host after this deterministic
    # search returns. Include a bounded pre-gate candidate pool so host-side
    # advisory scoring can reorder the same recall set without putting provider
    # configuration or credentials in the IDA process.
    rerank_meta = {"profile": None, "applied": False, "pool": 0, "latency_ms": 0}
    if not want_rerank:
        if rerank is None:
            rerank_meta["reason"] = f"quick mode keeps latency bounded; pass rerank=true to force typed-question advisory scoring (pool capped at {RERANK_POOL_MAX})"
        else:
            rerank_meta["reason"] = "rerank disabled by caller"
    rerank_candidates = [dict(item) for item in raw_results[: min(HOST_RERANK_MAX_CANDIDATES, candidate_limit)]] if want_rerank else []

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
        "advisory_provider": None,
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
        **({"_host_rerank_candidates": rerank_candidates} if rerank_candidates else {}),
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
      2. Collect bounded signatures for host-side behavior questions (if needed).

    Args:
        tag: Behavior tag (e.g. "crypto_symmetric", "network_http").
        limit: Max results.
        timeout_ms: Timeout in ms (0 = 10s default) for deterministic collection;
            the MCP host uses the remaining advisory budget after the RPC.
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
    provider_candidates: list[dict] = []

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

    # Stage 2: collect bounded signatures for host-side behavior questions.
    if len(rows) < limit // 2:
        try:
            for func_ea in idautils.Functions():
                if len(provider_candidates) >= 64 or len(rows) + len(provider_candidates) >= limit:
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
                    if signature:
                        provider_candidates.append({
                            "addr": hex(func_ea),
                            "name": fname[:256],
                            "signature": signature[:2048],
                        })
                except Exception:
                    continue
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
            f"Functions classified as '{normalized_tag}' via the L1 insight index "
            f"({sum(1 for r in rows if r['source'] == 'insight_index')}); "
            "the MCP host may add bounded provider advisory classifications."
        ),
        **({"_host_behavior_candidates": provider_candidates} if provider_candidates else {}),
    }
    return response
