"""SEARCH - Unified pattern, reference, and semantic search for LLM-centric RE.

VOERA Architecture:
- Neuro-Symbolic Governance: semantic target resolution with score thresholds
- Structured Semantic Retrieval: schema-based pre-filtering via structured action
- Context Density Optimization: compact text output with optional structured items
- Bridge-Conditioned Multi-Hop: find action supports intermediate entity chaining
- Task Skill Crystallization: search workflows are cacheable and reusable
- L1 Insight Index: fast tag-based pre-filtering before any search

This module is a thin router. All actions live in submodules to avoid monoliths.
"""

import json
import os
import re

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ..semantic_matching import normalize_action
except ImportError:
    from semantic_matching import normalize_action  # type: ignore[import-not-found]

from .core import (
    SEARCH_ACTIONS, SEARCH_ALIASES, SEARCH_INTENT_PATTERNS,
    MAX_LIMIT, SCORE_SUBSTRING,
)

from .basic import search_bytes, search_string, search_immediate, search_name
from .code import search_insns, search_mnemonic, search_instruction, search_text, search_operand, search_comment
from .refs import search_data_ref, search_code_ref, search_regex, search_func_by_sig
from .unified import search_find, search_semantic, search_callers, search_callees, search_api
from .advanced import search_vulnerable, search_constants, search_decompiled, search_structured
from .meta import search_type, search_export, search_summary
from ..query_lang import run_query_lang

# ============================================================================
# L1 Insight Index Pre-filtering
# ============================================================================

# Canonical tags shared with host/insight_index.py
_CANONICAL_TAGS = frozenset({
    "crypto", "network", "file_io", "registry", "process",
    "string_decode", "allocator", "exception_handler",
    "obfuscation", "compression", "hashing", "encoding",
    "parser", "main", "init", "cleanup", "loop",
    "recursive", "thunk", "library", "data",
})


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
        with open(target, "r", encoding="utf-8") as f:
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
        "find", "semantic", "callers", "callees", "api", "vulnerable", "constants", "decompiled", "structured",
        "type", "export", "summary", "query_lang",
    ], "Action: bytes|string|immediate|name|insns|mnemonic|instruction|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|semantic|callers|callees|api|vulnerable|constants|decompiled|structured|type|export|summary|query_lang"],
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
    timeout_ms: Annotated[int, "Timeout in milliseconds for long searches (0 = no timeout)"] = 0,
    **kwargs
) -> dict:
    """
    Search for patterns, bytes, references, and semantic targets in the binary.
    All results use compact text format (one match per line) to minimize LLM context.
    
    QUICK ACTIONS:
    - find: Smart unified search (auto-detects names, strings, imports, instructions, xrefs)
    - semantic: Natural-language semantic ranking across symbols/imports/strings/disasm
    - callers: Functions calling a target
    - callees: Functions called by a target
    - api: Find usages of an imported API
    - vulnerable: Delegate to vuln_scan for dynamic vulnerability discovery
    - constants: Find crypto/magic constants in instruction immediates
    - decompiled: Search pseudocode across all functions (with caching)
    - structured: Schema-based pre-filtered semantic retrieval
    - summary: Quick count overview across categories (fast planning aid)
    
    DETAILED ACTIONS:
    - bytes, string, immediate, name, insns, mnemonic, instruction, text, operand, comment
    - data_ref, code_ref, regex, func_by_sig
    - type: Search type library names and type usages
    - export: Search exported symbols
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
        pattern_not_required = {"vulnerable", "constants", "structured"}
        if not actual_pattern and action not in pattern_not_required:
            return make_error(MCPError.INVALID_ARGS, "pattern or query required")

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
                if l1_pre_filtered_addrs:
                    # Narrow range to tagged function addresses if possible
                    kwargs = dict(kwargs)
                    kwargs["_l1_addrs"] = l1_pre_filtered_addrs

        # Route
        response = None
        if action == "bytes":
            response = search_bytes(actual_pattern, range_start, range_end, include_context, offset, limit, timeout_ms)
        elif action == "string":
            response = search_string(actual_pattern, case_sensitive, include_context, offset, limit)
        elif action == "immediate":
            response = search_immediate(actual_pattern, range_start, range_end, include_context, offset, limit)
        elif action == "name":
            response = search_name(actual_pattern, case_sensitive, offset, limit)
        elif action == "insns":
            response = search_insns(actual_pattern, range_start, range_end, include_context, offset, limit)
        elif action == "mnemonic":
            response = search_mnemonic(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, include_items, include_breakdown, timeout_ms)
        elif action == "instruction":
            response = search_instruction(actual_pattern, case_sensitive, range_start, range_end, include_context, offset, limit, include_items, timeout_ms)
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
            response = search_func_by_sig(actual_pattern, offset, limit)
        elif action == "find":
            response = search_find(actual_pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms)
        elif action == "semantic":
            response = search_semantic(actual_pattern, include_context, range_start, range_end, offset, limit, include_items, timeout_ms)
        elif action == "callers":
            response = search_callers(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items)
        elif action == "callees":
            response = search_callees(actual_pattern, include_context, offset, limit, semantic_min_score, include_semantic_alternatives, include_items)
        elif action == "api":
            response = search_api(actual_pattern, include_context, offset, limit, include_items, include_breakdown)
        elif action == "vulnerable":
            response = search_vulnerable(actual_pattern, include_context, offset, limit, include_items, include_breakdown)
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
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        # Add interpretation metadata
        if interpreted_action and isinstance(response, dict):
            response["interpreted_action"] = interpreted_action
        if interpreted_pattern and isinstance(response, dict):
            response["interpreted_query"] = interpreted_pattern
        return response

    except Exception as e:
        return handle_error(e)
