"""SEARCH - Unified pattern, reference, and semantic search for LLM-centric RE.

Architecture:
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
    from ...support.semantic_matching import normalize_action
except ImportError:
    from support.semantic_matching import normalize_action  # type: ignore[import-not-found]

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
from .combinators import (
    search_bool, search_hunt, search_neighborhood, search_outlier,
    search_fingerprint, search_path, search_reach, search_noreach,
)
from ...support.query_lang import run_query_lang

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
        "find", "semantic", "smart_bundle", "callers", "callees", "api", "vulnerable", "constants", "decompiled", "structured",
        "type", "export", "summary", "query_lang", "nl", "behavior",
        "bool", "hunt", "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
    ], "Action: bytes|string|immediate|name|insns|mnemonic|instruction|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|semantic|smart_bundle|callers|callees|api|vulnerable|constants|decompiled|structured|type|export|summary|query_lang|nl|behavior|bool|hunt|neighborhood|outlier|fingerprint|path|reach|noreach"],
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
    - smart_bundle: Fused find+semantic view with deduplicated structured items
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
    - hunt: Named workflow recipes (backdoor, anti_debug, c2, crypto, parser, ...)
            Pass recipe='list' to see all 14 available recipes.
    - neighborhood: 360-degree context card around a function (callers, callees, similar, tags)
    - outlier: Find structurally anomalous functions (size/complexity/orphan/leaf/hub/deep)
    - fingerprint: Structural (callgraph) similarity, NOT embedding-based
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
        pattern_not_required = {"vulnerable", "constants", "summary", "outlier", "noreach", "hunt"}
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
            response = search_func_by_sig(actual_pattern, offset, limit, timeout_ms)
        elif action == "find":
            response = search_find(actual_pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms)
        elif action == "semantic":
            response = search_semantic(actual_pattern, include_context, range_start, range_end, offset, limit, include_items, timeout_ms)
        elif action == "smart_bundle":
            find_res = search_find(actual_pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms)
            sem_res = search_semantic(actual_pattern, include_context, range_start, range_end, offset, limit, include_items, timeout_ms)
            if isinstance(find_res, dict) and find_res.get("error"):
                return find_res
            if isinstance(sem_res, dict) and sem_res.get("error"):
                return sem_res

            find_items = list((find_res or {}).get("items") or []) if isinstance(find_res, dict) else []
            sem_items = list((sem_res or {}).get("items") or []) if isinstance(sem_res, dict) else []
            merged_items = []
            seen = set()
            for item in find_items + sem_items:
                if not isinstance(item, dict):
                    continue
                key = (
                    str(item.get("addr") or item.get("ea") or "").lower(),
                    str(item.get("name") or item.get("text") or "").lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                merged_items.append(item)
                if len(merged_items) >= limit:
                    break

            lines = []
            for item in merged_items:
                addr = item.get("addr") or item.get("ea") or "?"
                name = item.get("name") or item.get("text") or item.get("match") or "match"
                lines.append(f"{addr}  {name}")
            response = {
                "ok": True,
                "query": actual_pattern,
                "mode": "smart_bundle",
                "results": "\n".join(lines),
                "count": len(merged_items),
                "items": merged_items,
                "components": {
                    "find_count": len(find_items),
                    "semantic_count": len(sem_items),
                },
            }
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
        elif action == "nl":
            # Natural language search using bge-code-v1 embeddings (FunctionEmbeddingIndex)
            # Much more accurate than heuristic semantic scoring for RE queries like
            # "function that handles AES key schedule" or "packet parser with length check"
            if not actual_pattern:
                return make_error(MCPError.INVALID_ARGS, "pattern or query required for nl search")
            try:
                from ida_pro_mcp.host.intelligence.context import get_assembler
                asm = get_assembler()
                idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
                if not idb_path:
                    return make_error(MCPError.INVALID_ARGS,
                                      "nl search requires an active IDB with indexed embeddings. "
                                      "Run agent(action='analyze_function') on some functions first.")
                idx = asm._get_index(idb_path)
                if idx.size == 0:
                    return make_error(MCPError.INVALID_ARGS,
                                      "No embeddings indexed yet. Decompile some functions first "
                                      "or run schemaboot(action='ingest').")
                # Hybrid search over indexed functions, then behavior-driven expansion.
                results_raw = idx.search(actual_pattern, top_k=max(6, limit * 3), threshold=0.0)
                expansion_queries = []
                try:
                    classifier = asm._behavior_classifier()
                    q_hits = classifier.classify(actual_pattern[:600], threshold=0.0, top_k=4, block=False)
                    expansion_queries = [
                        str(h.get("behavior") or "").strip().replace("_", " ")
                        for h in q_hits
                        if h.get("behavior")
                    ]
                    expansion_queries = [q for q in expansion_queries if q]
                except Exception:
                    expansion_queries = []

                if expansion_queries:
                    merged_by_ea = {}
                    for r in results_raw:
                        ea_key = str(r.get("ea") or "")
                        if ea_key:
                            merged_by_ea[ea_key] = dict(r)
                    for extra_q in expansion_queries[:3]:
                        try:
                            extra_hits = idx.search(extra_q, top_k=max(3, limit), threshold=0.0)
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
                    results_raw = sorted(
                        merged_by_ea.values(),
                        key=lambda x: float(x.get("similarity") or 0.0),
                        reverse=True,
                    )
                sims = [float(r.get("similarity") or 0.0) for r in results_raw]
                if sims:
                    ss = sorted(sims)
                    q50 = ss[len(ss) // 2]
                    q75 = ss[min(len(ss) - 1, int(round((len(ss) - 1) * 0.75)))]
                    gate = q50 + max(0.0, q75 - q50)
                    filtered = [r for r in results_raw if float(r.get("similarity") or 0.0) >= gate]
                    results_raw = (filtered or results_raw)[:limit]
                rows = []
                for r in results_raw:
                    ea_str = r.get("ea", "")
                    name = r.get("name", ea_str)
                    sim = r.get("similarity", 0)
                    rows.append(f"{ea_str}  {name}  similarity={sim:.3f}")
                response = {
                    "ok": True,
                    "query": actual_pattern,
                    "expansion_queries": expansion_queries[:3],
                    "results": "\n".join(rows),
                    "count": len(rows),
                    "items": [{"addr": r.get("ea"), "name": r.get("name"),
                               "similarity": r.get("similarity"),
                               "score": r.get("score"),
                               "signature": r.get("signature")} for r in results_raw],
                    "note": "Results ranked by hybrid function-index retrieval: embedding similarity plus indexed lexical signature overlap.",
                }
            except Exception as e:
                response = make_error(MCPError.IDA_ERROR, f"nl search failed: {e}",
                                      hint="Ensure bge-code-v1 model is available and functions have been decompiled.")

        elif action == "behavior":
            # Find all functions matching a behavior tag using BehaviorClassifier
            # Example: search(action="behavior", pattern="crypto_symmetric")
            # Falls back to schemaboot tag search if embedder unavailable
            if not actual_pattern:
                return make_error(MCPError.INVALID_ARGS,
                                  "pattern required: behavior tag to search for "
                                  "(e.g. crypto_symmetric, network_http, memory_alloc)")
            tag = actual_pattern.strip().lower().replace(" ", "_")
            rows = []
            # Try L1 insight index first (fast)
            l1_addrs = _query_insight_by_tags([tag], mode="or")
            if l1_addrs:
                for addr_str in l1_addrs[:limit]:
                    try:
                        ea = int(addr_str, 16)
                        name = idc.get_func_name(ea) or addr_str
                        rows.append({"addr": addr_str, "name": name, "source": "insight_index"})
                    except Exception:
                        pass
            # Try BehaviorClassifier on unnamed functions if not enough results
            if len(rows) < limit // 2:
                try:
                    from ida_pro_mcp.host.intelligence.context import get_assembler
                    asm = get_assembler()
                    classifier = asm._behavior_classifier()
                    checked = 0
                    for func_ea in idautils.Functions():
                        if checked >= 200 or len(rows) >= limit:
                            break
                        fname = idc.get_func_name(func_ea) or ""
                        if not (fname.startswith("sub_") or fname.startswith("j_")):
                            continue  # skip already-named functions
                        try:
                            cfunc = ida_hexrays.decompile(func_ea)
                            if not cfunc:
                                continue
                            pseudo = str(cfunc)[:2000]
                            hits = classifier.classify(pseudo, threshold=0.0, top_k=5, block=False)
                            if hits:
                                hs = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in hits)
                                q50 = hs[len(hs) // 2]
                                q75 = hs[min(len(hs) - 1, int(round((len(hs) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [h for h in hits if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate]
                            if any(h.get("behavior", "").lower() == tag for h in hits):
                                rows.append({
                                    "addr": hex(func_ea),
                                    "name": fname,
                                    "source": "classifier",
                                    "confidence": max((float(h.get("confidence", h.get("score", 0)) or 0) for h in hits
                                                       if h.get("behavior", "").lower() == tag), default=0),
                                })
                        except Exception:
                            pass
                        checked += 1
                except Exception:
                    pass
            lines = [f"{r['addr']}  {r['name']}  [{r['source']}]" +
                     (f"  conf={r.get('confidence', 0):.2f}" if r.get("confidence") else "")
                     for r in rows]
            response = {
                "ok": True,
                "behavior": tag,
                "results": "\n".join(lines),
                "count": len(rows),
                "items": rows,
                "note": f"Functions classified as '{tag}'. "
                        "Use code(action='smart_decompile') on top results for full analysis.",
            }

        elif action == "bool":
            response = search_bool(actual_pattern, case_sensitive, offset, limit)
        elif action == "hunt":
            recipe = str(kwargs.get("recipe") or actual_pattern or "")
            response = search_hunt(recipe, case_sensitive, offset, limit)
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        # Inject blackboard context into find/semantic/nl results
        if action in ("find", "semantic", "nl", "behavior") and isinstance(response, dict):
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
        return response

    except Exception as e:
        return handle_error(e)
