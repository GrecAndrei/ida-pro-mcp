"""SEARCH — pattern, reference, and semantic search router.

Core agent surface: find, nl, string, bytes, api, callers/callees,
xrefs_to_string, symbol/symbol_info, decompiled, behavior.

Advanced actions (path, outlier, …) remain callable but are not the
default tools/list enum. Semantic NL/behavior live in search/semantic.py.
"""

import json
import os
import re

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ...support.semantic_matching import normalize_action
except ImportError:
    from support.semantic_matching import normalize_action  # type: ignore[import-not-found]

from ...support.query_lang import run_query_lang
from .advanced import search_constants, search_decompiled, search_structured
from .basic import search_bytes, search_immediate, search_name, search_string
from .code import search_comment, search_insns, search_operand, search_text
from .combinators import (
    search_analyze,
    search_bool,
    search_fingerprint,
    search_neighborhood,
    search_noreach,
    search_outlier,
    search_path,
    search_reach,
)
from .core import (
    _CANONICAL_TAGS,
    MAX_LIMIT,
    SCORE_SUBSTRING,
    SEARCH_ACTIONS,
    SEARCH_ALIASES,
    SEARCH_INTENT_PATTERNS,
    normalize_search_result,
)
from .meta import search_export, search_summary, search_type
from .refs import search_code_ref, search_data_ref, search_func_by_sig, search_regex
from .semantic import search_behavior as _search_behavior_impl, search_nl as _search_nl_impl
from .unified import (
    search_api,
    search_callees,
    search_callers,
    search_demangle,
    search_find,
    search_symbol,
    search_symbol_info,
    search_xrefs_to_string,
)

# ============================================================================
# L1 Insight Index Pre-filtering
# ============================================================================

def _insight_index_path() -> str:
    """Return the default insight index JSON path on the host side."""
    cache_dir = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
    if not cache_dir:
        import tempfile
        cache_dir = os.path.join(tempfile.gettempdir(), "ida-pro-mcp")
    return os.path.join(cache_dir, "insight_index.json")


def _load_insight_index(path: str = "") -> dict:
    """Load the persisted L1 insight index from JSON."""
    target = path or _insight_index_path()
    if not os.path.exists(target):
        return {}
    try:
        with open(target, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _query_insight_by_tags(tags: list, mode: str = "and") -> list:
    """
    Query the on-disk insight index for function addresses matching tags.

    Returns a list of function address strings (e.g., ["0x401000", ...]).
    """
    if not tags:
        return []
    payload = _load_insight_index()
    tag_map = payload.get("tag_map", {})
    func_map = payload.get("func_map", {})

    tags = [t.lower() for t in tags if t]
    if mode == "and":
        candidates = None
        for tag in tags:
            addrs = set(tag_map.get(tag, []))
            if candidates is None:
                candidates = addrs
            else:
                candidates &= addrs
            if not candidates:
                return []
        result_addrs = list(candidates) if candidates else []
    else:  # "or"
        seen = set()
        result_addrs = []
        for tag in tags:
            for addr in tag_map.get(tag, []):
                if addr not in seen:
                    seen.add(addr)
                    result_addrs.append(addr)

    # Validate that addresses still exist in func_map
    return [addr for addr in result_addrs if addr in func_map]


def _extract_tags_from_pattern(pattern: str) -> list:
    """Extract canonical behavior tags from a search pattern string."""
    if not pattern:
        return []
    words = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", pattern.lower())
    return [w for w in words if w in _CANONICAL_TAGS]


# ============================================================================
# Router
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal[
        "bytes", "string", "immediate", "name", "insns", "mnemonic", "instruction",
        "text", "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig",
        "find", "callers", "callees", "api", "vulnerable", "constants", "decompiled", "structured",
        "type", "export", "summary", "query_lang", "nl", "behavior",
        "bool", "analyze", "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
        "symbol", "symbol_info", "demangle", "xrefs_to_string",
    ], "Action: bytes|string|immediate|name|insns|mnemonic|instruction|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled|structured|type|export|summary|query_lang|nl|behavior|bool|analyze|neighborhood|outlier|fingerprint|path|reach|noreach|symbol|symbol_info|demangle|xrefs_to_string"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern"] = None,
    limit: Annotated[int, "Max results"] = 100,
    offset: Annotated[int, "Results offset"] = 0,
    start: Annotated[Optional[str], "Start address"] = None,
    end: Annotated[Optional[str], "End address"] = None,
    case_sensitive: Annotated[bool, "Case sensitive"] = False,
    include_context: Annotated[bool, "Include context"] = False,
    include_items: Annotated[bool, "Include structured items"] = False,
    include_breakdown: Annotated[bool, "Include breakdown"] = False,
    semantic_action: Annotated[Optional[str], "Semantic action alias"] = None,
    intent: Annotated[Optional[str], "Natural language intent"] = None,
    semantic_min_score: Annotated[float, "Minimum semantic score"] = 0.0,
    include_semantic_alternatives: Annotated[bool, "Include alternatives"] = False,
    constraints: Annotated[Optional[dict], "Schema constraints for structured search"] = None,
    timeout_ms: Annotated[int, "Timeout in milliseconds for long searches (0 = no limit)"] = 0,
    **kwargs
) -> dict:
    """
    Search for patterns, bytes, references, and semantic targets in the binary.
    All results use compact text format (one match per line) to minimize LLM context.

    QUICK ACTIONS:
    - find: Smart unified search (auto-detects names, strings, imports, instructions, xrefs)
    - nl: Natural language search via FunctionEmbeddingIndex (bge-code-v1 embeddings)
            Supports mode="quick" (hybrid search only) or mode="expand" (with behavior expansion)
    - behavior: Find functions matching a behavior tag (crypto_symmetric, network_http, etc.)
    - callers: Functions calling a target
    - callees: Functions called by a target
    - api: Find usages of an imported API
    - vulnerable: Scan for dangerous API patterns (buffer overflows, format strings, etc.)
    - constants: Find crypto/magic constants in instruction immediates
    - decompiled: Search pseudocode across all functions (with caching)
    - structured: Schema-based pre-filtered semantic retrieval
    - summary: Quick count overview across categories (fast planning aid)

    DETAILED ACTIONS:
    - bytes, string, immediate, name, insns, mnemonic, instruction, text, operand, comment
    - data_ref, code_ref, regex, func_by_sig
    - type: Search type library names and type usages
    - export: Search exported symbols

    COMPOSITION ACTIONS (combinators):
    - bool: Composite boolean query language across name/api/string/mnem/caller/callee
            Example: "(api:Crypt* AND name:key) OR (string:password AND NOT obf:true)"
    - analyze: Unified structural analysis (neighborhood/outlier/similar/vulnerable/semantic scopes)
    - neighborhood: 360-degree context card around a function (callers, callees, similar, tags)
    - outlier: Find structurally anomalous functions (size/complexity/orphan/leaf/hub/deep)
    - fingerprint: Embedding-similar functions via bge-code-v1 cosine similarity
    - path: Shortest call-graph path between two symbols
    - reach: Functions reachable from a root within N hops
    - noreach: Functions NOT reachable from any known entrypoint
    """
    try:
        # Resolve pattern
        actual_pattern = pattern or query or intent
        if not actual_pattern:
            # Compatibility: data_ref/code_ref callers often send addr/target.
            compat_target = kwargs.get("addr") or kwargs.get("target") or kwargs.get("ea")
            if compat_target is not None:
                actual_pattern = str(compat_target)
        try:
            semantic_min_score = max(0.0, min(200.0, float(semantic_min_score)))
        except Exception:
            semantic_min_score = 0.0

        # Normalize action
        requested = str(action)
        normalized = normalize_action(
            semantic_action or requested,
            actions=tuple(SEARCH_ACTIONS),
            aliases=SEARCH_ALIASES,
            fallback=requested,
            threshold=35.0,
            substring_bonus=SCORE_SUBSTRING,
        )
        interpreted_action = None
        interpreted_pattern = None
        if normalized != requested:
            interpreted_action = normalized
            action = normalized

        # Intent parsing
        if action == "find" and actual_pattern:
            for intent_re, intent_action in SEARCH_INTENT_PATTERNS:
                m = intent_re.match(actual_pattern)
                if m:
                    extracted = (m.group(1) or "").strip()
                    if extracted:
                        action = intent_action
                        interpreted_action = intent_action
                        interpreted_pattern = extracted
                        actual_pattern = extracted
                        break

        # Validate pattern
        pattern_not_required = {"vulnerable", "constants", "summary", "outlier", "noreach", "demangle", "symbol_info", "structured"}
        if not actual_pattern and action not in pattern_not_required:
            return make_error(MCPError.INVALID_ARGS, "pattern or query required")
        if action == "export" and not actual_pattern:
            return make_error(
                MCPError.INVALID_ARGS,
                "export requires pattern or query",
                hint="Example: search(action='export', pattern='Create*')",
            )
        if action == "structured" and not actual_pattern and not isinstance(constraints, dict):
            return make_error(
                MCPError.INVALID_ARGS,
                "structured requires constraints dict or pattern/query",
                hint="Example: search(action='structured', constraints={'behavior_tags':['crypto']})",
            )

        # Resolve range
        range_start = range_end = None
        if start is not None or end is not None:
            if start is None or end is None:
                return make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
            range_start, range_end, err = validate_range(start, end)
            if err:
                return err

        # Clamp limit
        try:
            limit = max(1, min(int(limit), MAX_LIMIT))
        except Exception:
            limit = 100
        try:
            offset = max(0, int(offset))
        except Exception:
            offset = 0

        # timeout_ms=0 means no limit (SearchTimeout treats 0 as unlimited)

        # L1 Insight Index pre-filtering
        l1_pre_filtered_addrs = None
        if action == "structured" and isinstance(constraints, dict):
            behavior_tags = constraints.get("behavior_tags")
            if behavior_tags:
                tags = behavior_tags if isinstance(behavior_tags, list) else [behavior_tags]
                l1_pre_filtered_addrs = _query_insight_by_tags(tags, mode=constraints.get("tag_mode", "and"))
                if l1_pre_filtered_addrs:
                    constraints = dict(constraints)
                    constraints["addrs"] = l1_pre_filtered_addrs
        elif action in ("find", "callers", "callees", "api") and actual_pattern:
            tags = _extract_tags_from_pattern(actual_pattern)
            if tags:
                l1_pre_filtered_addrs = _query_insight_by_tags(tags, mode="or")

        # Route
        response = None
        if action == "bytes":
            response = search_bytes(actual_pattern, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "string":
            response = search_string(actual_pattern, case_sensitive, include_context, offset, limit, timeout_ms)
        elif action == "immediate":
            response = search_immediate(actual_pattern, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "name":
            response = search_name(actual_pattern, case_sensitive, offset, limit)
        elif action == "insns":
            response = search_insns(actual_pattern, range_start, range_end, include_context, offset, limit)
        elif action in ("mnemonic", "instruction"):
            response = search_analyze(scope="semantic", pattern=actual_pattern, offset=offset, limit=limit, include_items=include_items)
        elif action == "text":
            response = search_text(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "operand":
            response = search_operand(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "comment":
            response = search_comment(actual_pattern, case_sensitive, range_start, range_end, offset, limit, timeout_ms)
        elif action == "data_ref":
            response = search_data_ref(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives)
        elif action == "code_ref":
            response = search_code_ref(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives)
        elif action == "regex":
            response = search_regex(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "func_by_sig":
            response = search_func_by_sig(actual_pattern, offset, limit, timeout_ms)
        elif action == "find":
            response = search_find(actual_pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms)
        elif action == "callers":
            response = search_callers(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items)
        elif action == "callees":
            response = search_callees(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items)
        elif action == "api":
            response = search_api(actual_pattern, include_context, offset, limit, include_items, include_breakdown)
        elif action == "vulnerable":
            response = search_analyze(
                scope="vulnerable", pattern=actual_pattern,
                depth=int(kwargs.get("depth", 5)),
                offset=offset, limit=limit,
                include_items=include_items,
            )
        elif action == "constants":
            response = search_constants(actual_pattern, range_start, range_end, include_context, offset, limit, include_items)
        elif action == "decompiled":
            response = search_decompiled(actual_pattern, case_sensitive, range_start, range_end, offset, limit, include_items, **kwargs)
        elif action == "structured":
            response = search_structured(constraints or {}, actual_pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms)
        elif action == "type":
            response = search_type(actual_pattern, case_sensitive, offset, limit, include_items)
        elif action == "export":
            response = search_export(actual_pattern, case_sensitive, offset, limit, include_items)
        elif action == "summary":
            response = search_summary(actual_pattern, case_sensitive, range_start, range_end)
        elif action == "query_lang":
            # query_lang uses the 'query' parameter directly, not pattern
            response = run_query_lang(query or actual_pattern or "")
        elif action == "nl":
            mode = str(kwargs.get("mode", "expand"))
            center_ea = None
            raw_center = kwargs.get("addr")
            raw_radius = kwargs.get("radius")
            if raw_radius is not None and raw_center is None:
                return make_error(MCPError.INVALID_ARGS, "addr is required when radius is set")
            if raw_center is not None:
                center_ea, center_error = validate_addr(raw_center, require_func=False)
                if center_error:
                    return center_error
            response = _search_nl_impl(
                actual_pattern,
                limit=limit,
                mode=mode,
                min_score=semantic_min_score,
                timeout_ms=timeout_ms,
                include_items=include_items,
                range_start=range_start,
                range_end=range_end,
                center_ea=center_ea,
                radius=raw_radius,
            )

        elif action == "behavior":
            response = _search_behavior_impl(
                actual_pattern,
                limit=limit,
                timeout_ms=timeout_ms,
                include_items=include_items,
            )

        elif action == "bool":
            response = search_bool(actual_pattern, case_sensitive, offset, limit)
        elif action == "analyze":
            response = search_analyze(
                addr=actual_pattern or kwargs.get("addr"),
                scope=str(kwargs.get("scope", "auto")),
                metric=str(kwargs.get("metric", "size")),
                top=int(kwargs.get("top", 50)),
                top_k=int(kwargs.get("top_k", 10)),
                radius=int(kwargs.get("radius", 5)),
                depth=int(kwargs.get("depth", 5)),
                pattern=actual_pattern,
                offset=offset,
                limit=limit,
                include_context=include_context,
                include_items=include_items,
            )
        elif action == "neighborhood":
            radius = int(kwargs.get("radius", 10))
            response = search_neighborhood(actual_pattern, radius, offset, limit)
        elif action == "outlier":
            metric = str(kwargs.get("metric", "size"))
            response = search_outlier(metric, int(kwargs.get("top", 50)), offset, limit)
        elif action == "fingerprint":
            top_k = int(kwargs.get("top_k", 20))
            response = search_fingerprint(actual_pattern, top_k, offset, limit)
        elif action == "path":
            src = str(kwargs.get("src", actual_pattern or ""))
            dst = str(kwargs.get("dst", ""))
            max_depth = int(kwargs.get("max_depth", 12))
            if not dst:
                return make_error(MCPError.INVALID_ARGS,
                                  "path action requires both src and dst",
                                  hint="Example: search(action='path', pattern='main', dst='WSAStartup')")
            response = search_path(src, dst, max_depth)
        elif action == "reach":
            depth = int(kwargs.get("depth", 5))
            response = search_reach(actual_pattern, depth, offset, limit)
        elif action == "noreach":
            depth = int(kwargs.get("depth", 20))
            response = search_noreach(depth, offset, limit)

        elif action == "symbol":
            response = search_symbol(
                actual_pattern,
                include_alternatives=kwargs.get("include_alternatives", True),
                offset=offset,
                limit=limit,
            )
        elif action == "symbol_info":
            response = search_symbol_info(
                actual_pattern or "",
                include_xrefs=kwargs.get("include_xrefs", False),
            )
        elif action == "demangle":
            response = search_demangle(
                actual_pattern or "",
                limit=limit,
                offset=offset,
            )
        elif action == "xrefs_to_string":
            response = search_xrefs_to_string(
                actual_pattern,
                include_context=include_context,
                offset=offset,
                limit=limit,
                timeout_ms=timeout_ms,
            )

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        # Inject blackboard context into find/nl/behavior results
        if action in ("find", "nl", "behavior") and isinstance(response, dict):
            try:
                from blackboard import BlackboardStore  # type: ignore
                store = BlackboardStore()
                items = response.get("items", [])
                if items:
                    bb_by_addr = {}
                    for item in items[:20]:
                        addr = item.get("addr") or item.get("address") or item.get("ea", "")
                        if addr and addr not in bb_by_addr:
                            entries = store.list(addr=str(addr), limit=2, include_resolved=False)
                            if entries:
                                bb_by_addr[addr] = [{"title": e["title"],
                                                     "category": e["category"],
                                                     "confidence": e.get("confidence")}
                                                    for e in entries]
                    if bb_by_addr:
                        response["blackboard_context"] = bb_by_addr
            except Exception:
                pass

        # Add interpretation metadata
        if l1_pre_filtered_addrs and isinstance(response, dict):
            try:
                allowed = {str(a).lower() for a in l1_pre_filtered_addrs}
                items = response.get("items")
                if isinstance(items, list):
                    filtered = []
                    for it in items:
                        if not isinstance(it, dict):
                            continue
                        a = str(it.get("addr") or it.get("address") or it.get("ea") or "").lower()
                        if a in allowed:
                            filtered.append(it)
                    if filtered and len(filtered) != len(items):
                        response["items"] = filtered
                        response["count"] = len(filtered)
                        if "results" in response:
                            lines = []
                            for it in filtered:
                                a = str(it.get("addr") or it.get("address") or it.get("ea") or "")
                                n = str(it.get("name") or "")
                                lines.append(f"{a}  {n}".rstrip())
                            response["results"] = "\n".join(lines)
            except Exception:
                pass

        # Add interpretation metadata
        if interpreted_action and isinstance(response, dict):
            response["interpreted_action"] = interpreted_action
        if interpreted_pattern and isinstance(response, dict):
            response["interpreted_query"] = interpreted_pattern

        if isinstance(response, dict) and not response.get("error"):
            response = normalize_search_result(
                response,
                action=str(action),
                query=str(actual_pattern or ""),
            )
        return response

    except Exception as e:
        return handle_error(e)
