"""SEARCH — pattern, reference, and semantic search router.

Core agent surface: find, nl, string, bytes, api, callers/callees,
xrefs_to_string, symbol/symbol_info, decompiled, behavior.

Advanced actions (path, outlier, …) remain callable but are not the
default tools/list enum. Semantic NL/behavior live in search/semantic.py.
"""

import json
import os
import re

from .._common import (
    Annotated,
    Literal,
    MCPError,
    Optional,
    handle_error,
    idaread,
    looks_like_address,
    make_error,
    public_arg,
    run_action,
    tool,
    validate_addr,
    validate_range
)

from ...support.semantic_matching import normalize_action

from ...support.query_lang import run_query_lang
from .advanced import search_constants, search_decompiled, search_structured
from .basic import search_bytes, search_data_value, search_immediate, search_name, search_string
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

# Bounded default deadline for whole-binary scans.  A raw opaque firmware blob
# with no EXEC segment and no analysis can make a full-binary scan crawl; a
# caller who does not opt in to "no limit" gets a bounded budget that reports
# ``timed_out`` plus the partial results instead of running to completion or
# tripping the host RPC timeout.
DEFAULT_SEARCH_TIMEOUT_MS = 8000


# ============================================================================
# L1 Insight Index Pre-filtering
# ============================================================================

def _insight_index_path() -> str:
    """Return the insight index JSON path scoped to the active IDB when possible."""
    try:
        from ida_pro_mcp.host.intelligence.insight_paths import resolve_insight_index_path
    except ImportError:
        from host.intelligence.insight_paths import resolve_insight_index_path  # type: ignore
    return resolve_insight_index_path()


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
        "symbol", "symbol_info", "demangle", "xrefs_to_string", "data_value",
    ], "Action: bytes|string|immediate|name|insns|mnemonic|instruction|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled|structured|type|export|summary|query_lang|nl|behavior|bool|analyze|neighborhood|outlier|fingerprint|path|reach|noreach|symbol|symbol_info|demangle|xrefs_to_string|data_value"],
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
    timeout_ms: Annotated[Optional[int], "Timeout in milliseconds for long searches (None = bounded default, 0 = no limit)"] = None,
    kind: Annotated[Optional[str], "Restrict action='find' to one category: strings|names|imports|comments|instructions|refs (default: all)"] = None,
    **kwargs
) -> dict:
    """
    Search for patterns, bytes, references, and semantic targets in the binary.
    All results use compact text format (one match per line) to minimize LLM context.

    QUICK ACTIONS:
    - find: Smart unified search (auto-detects names, strings, imports, instructions, xrefs).
            Pass kind='strings' for a dedicated string-literal search, kind='names'
            for symbols only, or kind='imports'|'comments'|'instructions'|'refs' to
            restrict to that one category.
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
    - data_value: Find raw pointer-sized words equal to an address (dispatch/vector
      tables, function-pointer arrays) that IDA created no data xref for.
      Pass value/pattern=ADDR, endian='both'|'le'|'be' (default both),
      word_size='auto'|'u32'|'u64' (default auto = IDB pointer width), and
      region='0x1000-0x2000' / a segment name / start+end to narrow.
      Each item reports {address, value, endian, kind} where kind is
      code/data/unknown from the item flags.
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
        # Resolve pattern. Public ida_search_data_value sends `value`.
        actual_pattern = pattern or query or intent
        if not actual_pattern:
            # Compatibility: data_ref/code_ref callers often send addr/target.
            compat_target = (
                kwargs.get("value")
                or kwargs.get("addr")
                or kwargs.get("target")
                or kwargs.get("ea")
            )
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
        pattern_not_required = {"vulnerable", "constants", "summary", "outlier", "noreach", "demangle", "symbol_info", "structured", "data_value"}
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

        # timeout_ms=None (the default) resolves to a bounded whole-binary
        # budget; the caller can pass 0 for an explicit no-limit opt-out.
        if timeout_ms is None:
            timeout_ms = DEFAULT_SEARCH_TIMEOUT_MS

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
        actual_pattern = public_arg(kwargs, "query", actual_pattern)
        semantic_min_score = public_arg(kwargs, "min_score", semantic_min_score)
        if kwargs.get("address") is not None and kwargs.get("addr") is None:
            kwargs["addr"] = kwargs["address"]

        def _search_nl():
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
            return _search_nl_impl(
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
                rerank=None if kwargs.get("rerank") is None else bool(kwargs.get("rerank")),
            )

        def _search_path():
            src = str(kwargs.get("src", actual_pattern or ""))
            dst = str(kwargs.get("dst", ""))
            max_depth = int(kwargs.get("max_depth", 12))
            if not dst:
                return make_error(MCPError.INVALID_ARGS,
                                  "path action requires both src and dst",
                                  hint="Example: search(action='path', pattern='main', dst='WSAStartup')")
            return search_path(src, dst, max_depth)

        def _search_data_value():
            target_value = actual_pattern
            if target_value is None:
                target_value = kwargs.get("value") or kwargs.get("target")
            if target_value is None:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "data_value requires a target value (address or symbol name)",
                )
            endian = str(kwargs.get("endian", "both") or "both").lower()
            endian = {"little": "le", "big": "be"}.get(endian, endian)
            if isinstance(target_value, int):
                text = hex(target_value)
                numeric = True
            else:
                text = str(target_value).strip()
                try:
                    int(text, 0)
                    numeric = True
                except (TypeError, ValueError):
                    numeric = looks_like_address(text)
            if not numeric:
                return search_string(
                    text,
                    case_sensitive,
                    include_context,
                    offset,
                    limit,
                    timeout_ms,
                    range_start,
                    range_end,
                )
            result = search_data_value(
                target_value,
                range_start=range_start,
                range_end=range_end,
                endian=endian,
                word_size=str(kwargs.get("word_size", "auto")),
                offset=offset,
                limit=limit,
                timeout_ms=timeout_ms,
                region=kwargs.get("region"),
            )
            return result

        handlers = {
            "bytes": lambda: search_bytes(actual_pattern, range_start, range_end, include_context, offset, limit, timeout_ms),
            "string": lambda: search_string(actual_pattern, case_sensitive, include_context, offset, limit, timeout_ms, range_start, range_end),
            "immediate": lambda: search_immediate(actual_pattern, range_start, range_end, include_context, offset, limit, timeout_ms),
            "name": lambda: search_name(actual_pattern, case_sensitive, offset, limit),
            "insns": lambda: search_insns(actual_pattern, range_start, range_end, include_context, offset, limit),
            "mnemonic": lambda: search_analyze(scope="semantic", pattern=actual_pattern, offset=offset, limit=limit, include_items=include_items),
            "instruction": lambda: search_analyze(scope="semantic", pattern=actual_pattern, offset=offset, limit=limit, include_items=include_items),
            "text": lambda: search_text(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms),
            "operand": lambda: search_operand(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms),
            "comment": lambda: search_comment(actual_pattern, case_sensitive, range_start, range_end, offset, limit, timeout_ms),
            "data_ref": lambda: search_data_ref(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives),
            "code_ref": lambda: search_code_ref(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives),
            "regex": lambda: search_regex(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms),
            "func_by_sig": lambda: search_func_by_sig(actual_pattern, offset, limit, timeout_ms),
            "find": lambda: search_find(actual_pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms, kind),
            "callers": lambda: search_callers(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items),
            "callees": lambda: search_callees(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items),
            "api": lambda: search_api(actual_pattern, include_context, offset, limit, include_items, include_breakdown),
            "vulnerable": lambda: search_analyze(
                scope="vulnerable", pattern=actual_pattern,
                depth=int(kwargs.get("depth", 5)),
                offset=offset, limit=limit,
                include_items=include_items,
            ),
            "constants": lambda: search_constants(actual_pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms=timeout_ms),
            "decompiled": lambda: search_decompiled(actual_pattern, case_sensitive, range_start, range_end, offset, limit, include_items, timeout_ms=timeout_ms, **kwargs),
            "structured": lambda: search_structured(constraints or {}, actual_pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms),
            "type": lambda: search_type(actual_pattern, case_sensitive, offset, limit, include_items),
            "export": lambda: search_export(actual_pattern, case_sensitive, offset, limit, include_items),
            "summary": lambda: search_summary(actual_pattern, case_sensitive, range_start, range_end),
            "query_lang": lambda: run_query_lang(query or actual_pattern or "", limit=limit),
            "nl": _search_nl,
            "behavior": lambda: _search_behavior_impl(
                actual_pattern,
                limit=limit,
                timeout_ms=timeout_ms,
                include_items=include_items,
            ),
            "bool": lambda: search_bool(actual_pattern, case_sensitive, offset, limit),
            "analyze": lambda: search_analyze(
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
            ),
            "neighborhood": lambda: search_neighborhood(actual_pattern, int(kwargs.get("radius", 10)), offset, limit),
            "outlier": lambda: search_outlier(str(kwargs.get("metric", "size")), int(kwargs.get("top", 50)), offset, limit),
            "fingerprint": lambda: search_fingerprint(actual_pattern, int(kwargs.get("top_k", 20)), offset, limit),
            "path": _search_path,
            "reach": lambda: search_reach(actual_pattern, int(kwargs.get("depth", 5)), offset, limit),
            "noreach": lambda: search_noreach(int(kwargs.get("depth", 20)), offset, limit),
            "symbol": lambda: search_symbol(
                actual_pattern,
                include_alternatives=kwargs.get("include_alternatives", True),
                offset=offset,
                limit=limit,
            ),
            "symbol_info": lambda: search_symbol_info(
                actual_pattern or "",
                include_xrefs=kwargs.get("include_xrefs", False),
            ),
            "demangle": lambda: search_demangle(actual_pattern or "", limit=limit, offset=offset),
            "xrefs_to_string": lambda: search_xrefs_to_string(
                actual_pattern,
                include_context=include_context,
                offset=offset,
                limit=limit,
                timeout_ms=timeout_ms,
            ),
            "data_value": _search_data_value,
        }

        response = run_action(action, handlers, tool_name="search")

        # Inject blackboard context into find/nl/behavior results
        if action in ("find", "nl", "behavior") and isinstance(response, dict):
            try:
                from ..blackboard import BlackboardStore
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
