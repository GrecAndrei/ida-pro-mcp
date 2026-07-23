"""SEARCH.SEMANTIC — Single orchestration point for ALL embedding/behavior search.

This module is the ONLY place that calls FunctionEmbeddingIndex and BehaviorClassifier.
All semantic/behavior NL actions in the search tool delegate here.

Architecture:
  get_backend()         — resolves (index, classifier, idb_path) with graceful error
  search_nl()           — natural language retrieval via FunctionEmbeddingIndex.search()
  search_behavior()     — tag-based lookup via insight index + BehaviorClassifier
"""

from __future__ import annotations

import time as _time

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    SearchTimeout,
)


# ---------------------------------------------------------------------------
# Backend resolution
# ---------------------------------------------------------------------------

def get_backend():
    """Resolve the semantic search backend.

    Returns (index, classifier, idb_path) or raises a descriptive error dict.
    Either import path is supported so this works in both package and test modes.
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
    if idx.size == 0:
        # The host may have copied an exact-binary index into this session
        # after the IDA-side assembler first cached an empty reader.
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
    # not cold-start llama.cpp.
    if not asm.ensure_embedding_server():
        return _err(
            "Semantic search backend is unavailable.",
            hint="Configure an embedding model and llama-server, then retry.",
        )

    classifier = asm._behavior_classifier()
    return idx, classifier, idb_path


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

    Returns:
        Response dict with results, similarity scores, and expansion metadata.
    """
    if not query or not query.strip():
        return make_error(MCPError.INVALID_ARGS, "query required for nl search")

    backend = get_backend()
    if isinstance(backend, dict):
        return backend
    idx, classifier, _idb_path = backend

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

    # Phase 1: primary search via hybrid semantic+lexical. The embedding index
    # applies address_ranges before top-k truncation.
    candidate_limit = max(6, limit * 3)
    raw_results = idx.search(
        query,
        top_k=candidate_limit,
        threshold=0.0,
        address_ranges=address_ranges,
    )

    # Phase 2: behavior-driven query expansion (only in "expand" mode)
    expansion_queries: list[str] = []
    if mode == "expand":
        try:
            hits = classifier.classify(query[:600], threshold=classifier_threshold, top_k=4, block=False)
            expansion_queries = [
                str(h.get("behavior") or "").strip().replace("_", " ")
                for h in (hits or [])
                if h.get("behavior")
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

            for extra_q in expansion_queries[:3]:
                if (_time.time() - started_at) >= (timeout_ms / 1000.0):
                    break
                try:
                    extra_hits = idx.search(
                        extra_q,
                        top_k=max(3, limit),
                        threshold=0.0,
                        address_ranges=address_ranges,
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

    # Phase 4: adaptive gating on the score used to rank the hybrid results.
    # Gating only on raw cosine similarity discarded strong lexical matches
    # (for example, an exact API or string reference) after hybrid_search had
    # correctly promoted them.
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
                "signature": r.get("signature"),
                "expansion_query": r.get("expansion_query"),
                "rank_reason": r.get("rank_reason"),
            }
            for r in raw_results
        ],
        "note": (
            f"Natural language retrieval via FunctionEmbeddingIndex.search() "
            f"(mode={mode}, expansion_queries={len(expansion_queries)})."
        ),
    }
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
    from . import _query_insight_by_tags

    l1_addrs = _query_insight_by_tags([normalized_tag], mode="or")
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
    if len(rows) < limit // 2:
        try:
            backend = get_backend()
            if isinstance(backend, dict):
                pass
            else:
                idx, classifier, _idb_path = backend
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
    return response
