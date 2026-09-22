"""Intelligence tool — bounded evidence collection and deterministic search.

Extracted from `agent.py` in the dedup pass (commit series: shim removal,
comment_mgr merge, firmware_bootstrap fold, **intelligence
extraction**). The 14 actions previously hung off `agent` now live here
because they have a distinct operational identity (advisory and indexing) and
dominated ~400 LOC of the agent dispatcher without sharing any of its
neighbor actions.

Payload shapes remain compatible with the old `agent.*` actions so existing
host-side call sites and CLIs continue to work. The IDA tool gathers bounded
signatures and performs deterministic lexical indexing; the MCP host owns
provider requests and does not start a local model.
"""

import hashlib

from ._common import Annotated, Literal, MCPError, Optional, handle_error, ida_funcs, idaapi, idaread, idautils, idc, make_error, public_arg, tool, validate_addr

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from .. import compat as _compat

from typing import Any

# Known crypto constant values — imported from central registry

from .code_helpers import _build_function_structure_summary


def _build_fast_signature(fea: int, func=None) -> str:
    """Build a bounded disassembly/metadata signature for advisory questions."""
    if func is None:
        func = _compat.get_func_info(fea)
    if func is None:
        return ida_funcs.get_func_name(fea) or hex(fea)
    name = ida_funcs.get_func_name(fea) or hex(fea)
    parts = [name]
    # Auto-named functions (sub_*/j_*/loc_*/nullsub_* — the common case on
    # opaque, symbol-poor firmware) carry no meaningful name signal, so the
    # lexical signature must discriminate on structure: a larger code sample
    # plus an opcode histogram and instruction-bigram fingerprint give the
    # index non-name signal without a decompile.
    auto_named = name.startswith(("sub_", "j_", "loc_", "nullsub_", "unknown_libname_"))
    # Keep the fast-index document deliberately small. Name, APIs, string
    # fingerprints, and a short instruction sample carry useful retrieval
    # signal. Full decompilations remain outside this provider context.
    # API calls
    apis = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            ref_name = idc.get_name(ref) or ""
            if ref_name:
                apis.add(ref_name)
        if len(apis) > 12:
            break
    if apis:
        parts.append("apis:" + ",".join(sorted(apis)[:12]))
    # String refs
    str_refs = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(ref, -1, 0)
            if s:
                try:
                    s = s.decode("utf-8", errors="replace")[:256]
                    # Preserve only a stable identifier for provider context;
                    # literal contents are never sent outside IDA.
                    str_refs.add(hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:16])
                except Exception:
                    pass
        if len(str_refs) > 4:
            break
    if str_refs:
        parts.append("strings:" + ",".join(sorted(str_refs)[:4]))
    _tag_remove = getattr(idc, "tag_remove", None)
    # A few instructions distinguish otherwise similar wrappers without
    # turning index_fast into a decompiler-sized embedding request.
    insns = []
    sample_ea_max = func.start_ea + (512 if auto_named else 256)
    for head in idautils.Heads(func.start_ea, min(sample_ea_max, func.end_ea)):
        dis = idc.generate_disasm_line(head, 0)
        if dis:
            insns.append(_tag_remove(dis) if _tag_remove else dis)
        if len(insns) >= (12 if auto_named else 6):
            break
    if insns:
        parts.append("code:" + "; ".join(i[:56] for i in insns))
    # Opcode histogram + instruction-bigram lexical fingerprint for
    # auto-named functions (discriminates firmware handlers by instruction
    # mix even when no names/strings/APIs are present).
    if auto_named:
        hist: dict[str, int] = {}
        prev = None
        ngrams: list[str] = []
        _pn = getattr(idc, "print_insn_mnem", None)
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if _pn is not None:
                mnem = (_pn(head) or "").lower()
            else:
                dis = idc.generate_disasm_line(head, 0)
                mnem = ((_tag_remove(dis) if _tag_remove else dis) or "").split()[0].lower() if dis else ""
            if mnem:
                hist[mnem] = hist.get(mnem, 0) + 1
                if prev is not None:
                    ngrams.append(f"{prev}:{mnem}")
                prev = mnem
        if hist:
            top = ",".join(f"{m}x{c}" for m, c in sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))[:10])
            parts.append("opcodes:" + top[:180])
        if ngrams:
            bigram = " ".join(sorted(set(ngrams))[:12])
            parts.append("insns:" + bigram[:240])
    # Fast mode must remain Hex-Rays-free, but a compact CFG + call-target
    # summary carries control-flow semantics that instruction samples lose.
    try:
        structure = _build_function_structure_summary(func, max_items=8)
        if structure.get("evidence"):
            parts.append(str(structure["evidence"])[:360])
    except Exception:
        pass
    return " | ".join(parts)[:768]


def _function_index_metadata(func) -> dict[str, Any]:
    """Collect search filters in one function walk."""
    api_count = 0
    string_count = 0
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            if idc.get_name(ref):
                api_count += 1
        for ref in idautils.DataRefsFrom(head):
            if idc.get_strlit_contents(ref, -1, 0):
                string_count += 1

    blocks = list(_compat.get_flow_chart(func.start_ea) or [])
    edge_count = 0
    has_loops = False
    for block in blocks:
        successors = list(block.succs())
        edge_count += len(successors)
        if any(succ.start_ea <= block.start_ea for succ in successors):
            has_loops = True
    bb_count = len(blocks)
    cyclomatic = max(1, edge_count - bb_count + 2) if bb_count else 0
    return {
        "func_size": int(func.end_ea - func.start_ea),
        "bb_count": bb_count,
        "has_loops": 1 if has_loops else 0,
        "api_count": min(api_count, 999),
        "string_count": min(string_count, 999),
        "segment": _compat.get_segment_name(func.start_ea) or "",
        "is_thunk": 1 if (getattr(func, "flags", _compat.get_func_flags(func.start_ea) or 0) & idaapi.FUNC_THUNK) else 0,
        "cyclomatic": cyclomatic,
    }


def _lexical_index_functions(
    *,
    idb_path: str,
    mode: str = "fast",
    limit: int | None = None,
    start_after: str | None = None,
    start: Any = None,
    end: Any = None,
    addr: Any = None,
    radius: Any = None,
    ranges: Any = None,
    query: str | None = None,
    min_size: Any = None,
    max_size: Any = None,
) -> dict[str, Any]:
    """Index bounded metadata/signatures without a model or decompilation.

    The old action names are retained for client compatibility, but their
    durable representation is now a lexical signature index.  This keeps
    deterministic search and structural filters useful while ensuring a
    provider request is never hidden behind an indexing operation.
    """
    from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path

    def _address(value: Any) -> int | None:
        if value is None or str(value).strip() == "":
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            try:
                return int(str(value), 16)
            except (TypeError, ValueError):
                return None

    ranges_out: list[tuple[int, int]] = []
    if isinstance(ranges, (list, tuple)):
        for item in ranges:
            if not isinstance(item, dict):
                continue
            lo, hi = _address(item.get("start")), _address(item.get("end"))
            if lo is not None and hi is not None and lo < hi:
                ranges_out.append((lo, hi))
    lo = _address(start)
    hi = _address(end)
    center = _address(addr)
    if lo is not None and hi is not None and lo < hi:
        ranges_out.append((lo, hi))
    if center is not None and radius is not None:
        try:
            span = max(1, int(radius))
            ranges_out.append((max(0, center - span), center + span + 1))
        except (TypeError, ValueError):
            pass
    cursor = _address(start_after)
    try:
        min_size_value = max(0, int(min_size)) if min_size is not None else None
    except (TypeError, ValueError):
        min_size_value = None
    try:
        max_size_value = max(0, int(max_size)) if max_size is not None else None
    except (TypeError, ValueError):
        max_size_value = None
    name_query = str(query or "").strip().lower()
    try:
        max_count = max(1, min(10_000, int(limit))) if limit is not None else 10_000
    except (TypeError, ValueError):
        max_count = 10_000

    selected: list[tuple[int, Any]] = []
    for fea in idautils.Functions():
        try:
            address = int(fea)
            if cursor is not None and address <= cursor:
                continue
            if ranges_out and not any(begin <= address < finish for begin, finish in ranges_out):
                continue
            func = _compat.get_func_info(address)
            if func is None:
                continue
            size = max(0, int(func.end_ea - func.start_ea))
            if min_size_value is not None and size < min_size_value:
                continue
            if max_size_value is not None and size > max_size_value:
                continue
            name = str(ida_funcs.get_func_name(address) or hex(address))
            if name_query and name_query not in name.lower():
                continue
            selected.append((address, func))
        except Exception:
            continue
    selected.sort(key=lambda item: item[0])
    eligible = len(selected)
    batch = selected[:max_count]
    rows = []
    for address, func in batch:
        name = str(ida_funcs.get_func_name(address) or hex(address))
        try:
            signature = _build_fast_signature(address, func)
            metadata = _function_index_metadata(func)
        except Exception:
            continue
        rows.append((hex(address), name, signature, {**metadata, "index_quality": "lexical"}))
    index = LexicalFunctionIndex(signature_index_path(idb_path))
    result = index.index_many(rows)
    _invalidate_tool_cache()
    next_cursor = hex(batch[-1][0]) if len(batch) >= max_count and batch else None
    complete = len(batch) >= eligible
    return {
        "ok": True,
        "backend": "lexical",
        "quality": "lexical",
        "mode": str(mode or "fast"),
        "indexed": int(result.get("indexed") or 0),
        "attempted": len(rows),
        "failed": int(result.get("failed") or 0) + max(0, len(batch) - len(rows)),
        "eligible": eligible,
        "complete": complete,
        "fully_indexed": complete,
        "next_cursor": None if complete else next_cursor,
        "index": index.build_embedding_state_payload(),
        "input": {"pseudocode_chars": 0, "document_chars": 0},
        "note": "Stored bounded names, disassembly, and signatures for deterministic lexical search; no model or decompilation was used.",
    }


def _invalidate_tool_cache() -> None:
    """Drop cached @idaread responses after the index changes on disk.

    Indexing is not an @idawrite operation, but it rewrites the embedding
    index that search/nl and similar_* rank against — so every cached
    search response is stale the moment a rebuild commits.  Index-mutating
    actions call this before returning.
    """
    # Resolve the same ToolResultCache singleton @idaread/@idawrite use via
    # sync._tool_cache — the single canonical resolver (sync.py tries
    # ida_mcp.ida_mcp.cache -> cache -> ida_pro_mcp.ida_mcp.cache). Importing
    # via a different path (e.g. a hard-coded ida_pro_mcp.ida_mcp.cache) would
    # yield a second module instance with its own TOOL_CACHE, and invalidation
    # would silently no-op against the cache the search tool actually reads.
    from ..sync import _tool_cache

    _cache = _tool_cache()
    if _cache is not None:
        _cache.invalidate_all()


@tool
@idaread
def intelligence(
    action: Annotated[
        Literal[
            "intelligence_status",
            "embedder_status",
            "reranker_status",
            "usage_status",
            "usage_report",
            "anchor_status",
            "refresh_anchors",
            "classify_text",
            "classify_function",
            "index_function",
            "index_batch",
            "index_fast",
            "index_range",
            "similar_functions",
            "semantic_search",
            "blackboard_search",
            "export_index_summary",
            "function_families",
        ],
        "Action: intelligence_status|embedder_status|reranker_status|usage_status|usage_report|anchor_status|refresh_anchors|classify_text|classify_function|index_function|index_batch|index_fast|index_range|similar_functions|semantic_search|blackboard_search|export_index_summary|function_families",
    ],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Free-form text or comma-separated list"] = None,
    max_items: Annotated[Optional[int], "Top-K / explicit indexing cap"] = None,
    **kwargs,
) -> dict:
    """Typed-question advisory classification and deterministic lexical search.

    intelligence_status - provider readiness, capabilities, and usage metadata.
    embedder_status     - compatibility alias for provider status.
    reranker_status     - typed-question scoring capability status.
    anchor_status       - compatibility status for removed anchor vectors.
    refresh_anchors     - reports that local anchor-vector refresh is unavailable.
    classify_text       - host-side behavior question over a bounded query signature.
    classify_function   - bounded IDA metadata/signature for host-side advice.
    index_function      - store a bounded metadata/signature row for `addr`.
    index_batch         - store bounded metadata/signature rows for selected functions.
    similar_functions   - deterministic lexical scan over the per-IDB index for `addr`.
    semantic_search     - deterministic lexical search over the index.
    blackboard_search   - deterministic related-by-behavior search on the blackboard.
    export_index_summary - return index path/size/metadata.
    function_families   - reports that vector-family clustering is unavailable.
    """
    try:
        # Public MCP names stay on the wire; accept them beside legacy aliases.
        addr = public_arg(kwargs, "address", addr)

        # The public intelligence contract is provider-neutral.  Do not
        # construct the legacy local/Gemini/native embedding stack merely to
        # answer status or typed-question classification calls.
        if action in {"intelligence_status", "embedder_status", "reranker_status", "usage_status", "usage_report", "anchor_status"}:
            return {
                "error": True,
                "code": "HOST_ONLY_OPERATION",
                "message": "provider status and usage are served by the MCP host",
            }
        if action == "refresh_anchors":
            return {
                "error": True,
                "code": "CAPABILITY_UNAVAILABLE",
                "message": "anchor embedding refresh is unavailable; typed-question behavior decisions are evaluated per request",
            }
        if action in {"classify_text", "classify_function"}:
            if action == "classify_text":
                if not query:
                    return make_error(MCPError.INVALID_ARGS, "query required for classify_text")
                return {
                    "ok": True,
                    "backend": "provider_advisory",
                    "_provider_source_kind": "operator_query",
                }
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for classify_function")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            try:
                func = _compat.get_func_info(ea)
                name = ida_funcs.get_func_name(ea) or hex(ea)
                signature = _build_fast_signature(ea, func)
            except Exception:
                return make_error(MCPError.IDA_ERROR, "failed to build bounded function context")
            return {
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "backend": "provider_advisory",
                "_provider_signature": signature,
                "_provider_source_kind": "function_signature",
            }
        if action == "blackboard_search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for blackboard_search")
            try:
                from ida_pro_mcp.ida_mcp.tools.blackboard import blackboard as blackboard_tool

                result = blackboard_tool(
                    action="related_by_behavior",
                    query=str(query),
                    top_k=max(1, int(kwargs.get("top_k", max_items or 25))),
                    threshold=float(kwargs.get("threshold", 0.0)),
                    include_resolved=bool(kwargs.get("include_resolved", False)),
                )
                if isinstance(result, dict) and result.get("ok"):
                    return {
                        "ok": True,
                        "query": str(query),
                        "backend": "lexical",
                        "blackboard": result,
                    }
                return result
            except Exception:
                return {"error": True, "code": "PROVIDER_ERROR", "message": "lexical blackboard search failed"}
        if action in {"index_function", "index_batch", "index_fast", "index_range"}:
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
            if not idb_path:
                return make_error(MCPError.SESSION_REQUIRED, "no active IDB path")
            if action == "index_function":
                if not addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required for index_function")
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func = _compat.get_func_info(ea)
                if func is None:
                    return make_error(MCPError.INVALID_ARGS, "address is not a function")
                name = str(ida_funcs.get_func_name(ea) or hex(ea))
                signature = _build_fast_signature(ea, func)
                from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path

                index = LexicalFunctionIndex(signature_index_path(idb_path))
                stored = index.index(hex(ea), name, signature, {**_function_index_metadata(func), "index_quality": "lexical"})
                _invalidate_tool_cache()
                return {
                    "ok": bool(stored),
                    "backend": "lexical",
                    "quality": "lexical",
                    "indexed": 1 if stored else 0,
                    "failed": 0 if stored else 1,
                    "addr": hex(ea),
                    "note": "Bounded lexical signature stored; no model or decompilation was used.",
                }
            return _lexical_index_functions(
                idb_path=idb_path,
                mode=str(kwargs.get("mode") or "fast"),
                limit=kwargs.get("index_limit", kwargs.get("_index_total_limit", max_items or kwargs.get("limit"))),
                start_after=kwargs.get("start_after"),
                start=kwargs.get("start"),
                end=kwargs.get("end"),
                addr=kwargs.get("addr"),
                radius=kwargs.get("radius"),
                ranges=kwargs.get("ranges"),
                query=kwargs.get("query"),
                min_size=kwargs.get("min_size"),
                max_size=kwargs.get("max_size"),
            )
        if action == "similar_functions":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for similar_functions")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
            if not idb_path:
                return make_error(MCPError.SESSION_REQUIRED, "no active IDB path")
            func = _compat.get_func_info(ea)
            if func is None:
                return make_error(MCPError.INVALID_ARGS, "address is not a function")
            from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path

            index = LexicalFunctionIndex(signature_index_path(idb_path))
            rows = index.search_text(
                _build_fast_signature(ea, func),
                top_k=max(1, min(200, int(max_items or kwargs.get("top_k", 10)))),
                exclude_ea=hex(ea),
            )
            return {"ok": True, "backend": "lexical", "matches": rows, "count": len(rows), "note": "Lexical signature similarity; no vector model was used."}
        if action == "function_families":
            return {
                "error": True,
                "code": "CAPABILITY_UNAVAILABLE",
                "message": "vector-family clustering is unavailable; use ida_semantic_search or deterministic structural filters",
            }
        if action == "semantic_search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for semantic_search")
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
            if not idb_path:
                return make_error(MCPError.SESSION_REQUIRED, "no active IDB path")
            try:
                from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path

                idx = LexicalFunctionIndex(signature_index_path(idb_path))
                rows = idx.search_text(str(query), top_k=max(1, int(kwargs.get("top_k", max_items or 25))))
            except Exception:
                rows = []
            return {"ok": True, "query": str(query), "backend": "lexical", "search_strategy": "lexical_fallback", "matches": rows}
        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
