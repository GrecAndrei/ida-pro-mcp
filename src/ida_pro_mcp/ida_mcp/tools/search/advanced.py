"""SEARCH.ADVANCED - Vulnerable, constants, decompiled, and structured search."""

import time as _time

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# Import re after the wildcard import — the latter may shadow `re` with
# typing.re (Python 3.12+) which is a deprecated proxy that lacks
# re.compile().
import re as _stdlib_re

re = _stdlib_re

from .core import (  # noqa: E402
    _SEARCH_CACHE,
    SearchTimeout,
    _cache_get,
    _cache_key,
    _cache_set,
    build_response,
    clip_text,
    get_cached_constant_db,
    get_cached_imports,
    get_cached_strings,
    iter_segments,
    paginate_records,
    safe_generate_disasm_line,
)

_DECOMPILED_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_DECOMPILED_STOPWORDS = frozenset({
    "the", "and", "for", "with", "that", "this", "from", "into", "while",
    "void", "char", "int", "uint", "long", "short", "bool", "true", "false",
    "const", "struct", "class", "return", "case", "break", "default", "null",
})


def _iter_function_starts(range_start=None, range_end=None):
    """Yield function starts, respecting an optional address range."""
    if range_start is None or range_end is None:
        yield from idautils.Functions()
        return

    seen = set()
    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        for func_ea in idautils.Functions(seg_start, seg_end):
            if func_ea in seen:
                continue
            seen.add(func_ea)
            yield func_ea


def _function_in_range(func, range_start=None, range_end=None) -> bool:
    if range_start is None or range_end is None:
        return True
    return bool(func) and func.start_ea < range_end and func.end_ea > range_start


def _decompiled_query_tokens(pattern: str) -> list[str]:
    seen = set()
    tokens = []
    for tok in _DECOMPILED_TOKEN_RE.findall(pattern or ""):
        low = tok.lower()
        if low in seen or low in _DECOMPILED_STOPWORDS or low.isdigit():
            continue
        seen.add(low)
        tokens.append(low)
    tokens.sort(key=len, reverse=True)
    return tokens[:8]


def _blob_matches_tokens(blob: str, tokens: list[str]) -> bool:
    """Check if blob contains enough query tokens.

    Requires at least 2 tokens to match (or all tokens if fewer than 2).
    This prevents single common words like "key" or "data" from matching.
    """
    if not blob or not tokens:
        return False
    lowered = blob.lower()
    matches = sum(1 for t in tokens if t in lowered)
    required = min(2, len(tokens))
    return matches >= required


def _coerce_ea(value) -> int:
    try:
        return int(str(value), 0)
    except Exception:
        return idaapi.BADADDR


def _get_intelligence_index():
    try:
        from ida_pro_mcp.services import get_assembler
    except ImportError:
        try:
            from host.intelligence.context import get_assembler  # type: ignore
        except ImportError:
            return None, None, ""
    try:
        asm = get_assembler()
        idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        if not idb_path:
            return asm, None, ""
        return asm, asm._get_index(idb_path), idb_path
    except Exception:
        return None, None, ""


def _seed_decompiled_candidates(pattern, matcher, range_start, range_end, max_functions, timeout_ms):
    """Rank likely matching functions before falling back to broad sampling."""
    planning_budget_ms = min(2000, max(250, timeout_ms // 4))
    timer = SearchTimeout(planning_budget_ms)
    tokens = _decompiled_query_tokens(pattern)
    seed_cap = max(128, max_functions * 3)
    xref_cap = 64

    scores = {}
    reasons = {"cached": 0, "names": 0, "strings": 0, "imports": 0, "intelligence": 0, "behavior": 0}
    planning_timed_out = False
    intelligence_index_size = 0
    expansion_queries = []

    def add_candidate(ea: int, score: float, reason: str):
        if ea == idaapi.BADADDR:
            return
        func = idaapi.get_func(ea)
        if not func or not _function_in_range(func, range_start, range_end):
            return
        start_ea = func.start_ea
        if start_ea not in scores and len(scores) >= seed_cap:
            return
        if start_ea not in scores:
            reasons[reason] = reasons.get(reason, 0) + 1
            scores[start_ea] = float(score)
        else:
            scores[start_ea] = max(scores[start_ea], float(score)) + 1.0

    try:
        asm = None
        idx = None
        if pattern:
            asm, idx, _idb_path = _get_intelligence_index()
            intelligence_index_size = int(getattr(idx, "size", 0) or 0) if idx is not None else 0
            if idx is not None and intelligence_index_size > 0:
                try:
                    for hit in idx.search(pattern, top_k=max(seed_cap, 48), threshold=0.0):
                        try:
                            timer.check()
                        except TimeoutError:
                            planning_timed_out = True
                            break
                        fea = _coerce_ea(hit.get("ea"))
                        if fea == idaapi.BADADDR:
                            continue
                        sim = float(hit.get("similarity") or 0.0)
                        lex = float(hit.get("lexical_score") or hit.get("score") or 0.0)
                        add_candidate(fea, 210.0 + (sim * 35.0) + (lex * 12.0), "intelligence")
                    if asm is not None and not planning_timed_out:
                        classifier = asm._behavior_classifier()
                        q_hits = classifier.classify(pattern[:600], threshold=0.0, top_k=4, block=False)
                        expansion_queries = [
                            str(h.get("behavior") or "").strip().replace("_", " ")
                            for h in (q_hits or [])
                            if h.get("behavior")
                        ]
                        expansion_queries = [q for q in expansion_queries if q]
                        for extra_q in expansion_queries[:3]:
                            for hit in idx.search(extra_q, top_k=max(max_functions * 2, 24), threshold=0.0):
                                try:
                                    timer.check()
                                except TimeoutError:
                                    planning_timed_out = True
                                    break
                                fea = _coerce_ea(hit.get("ea"))
                                if fea == idaapi.BADADDR:
                                    continue
                                sim = float(hit.get("similarity") or 0.0)
                                lex = float(hit.get("lexical_score") or hit.get("score") or 0.0)
                                add_candidate(fea, 145.0 + (sim * 26.0) + (lex * 8.0), "behavior")
                            if planning_timed_out:
                                break
                except Exception:
                    pass

        for key, cached in list(_SEARCH_CACHE.items()):
            try:
                timer.check()
            except TimeoutError:
                planning_timed_out = True
                break
            if not key.startswith("decomp:") or not isinstance(cached, str):
                continue
            parts = key.split(":", 2)
            if len(parts) < 2:
                continue
            try:
                func_ea = int(parts[1])
            except Exception:
                continue
            if matcher(cached) or _blob_matches_tokens(cached, tokens):
                add_candidate(func_ea, 250.0, "cached")

        if not planning_timed_out:
            for func_ea in _iter_function_starts(range_start, range_end):
                try:
                    timer.check()
                except TimeoutError:
                    planning_timed_out = True
                    break
                func_name = idc.get_func_name(func_ea) or ""
                if func_name and (matcher(func_name) or _blob_matches_tokens(func_name, tokens)):
                    add_candidate(func_ea, 180.0, "names")

        if not planning_timed_out:
            for srec in get_cached_strings():
                try:
                    timer.check()
                except TimeoutError:
                    planning_timed_out = True
                    break
                sval = srec.get("string") or ""
                if not sval or not (matcher(sval) or _blob_matches_tokens(sval, tokens)):
                    continue
                for idx, xref in enumerate(idautils.XrefsTo(srec["ea"], 0)):
                    if idx >= xref_cap:
                        break
                    add_candidate(xref.frm, 130.0, "strings")
                    if len(scores) >= seed_cap:
                        break
                if len(scores) >= seed_cap:
                    break

        if not planning_timed_out:
            for irec in get_cached_imports():
                try:
                    timer.check()
                except TimeoutError:
                    planning_timed_out = True
                    break
                name = irec.get("name") or ""
                if not name or not (matcher(name) or _blob_matches_tokens(name, tokens)):
                    continue
                for idx, xref in enumerate(idautils.XrefsTo(irec["ea"], 0)):
                    if idx >= xref_cap:
                        break
                    add_candidate(xref.frm, 120.0, "imports")
                    if len(scores) >= seed_cap:
                        break
                if len(scores) >= seed_cap:
                    break
    except Exception:
        pass

    ranked = [ea for ea, _score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))]
    return ranked, {
        "tokens": tokens,
        "seeded_candidates": len(ranked),
        "seed_reasons": reasons,
        "planning_timed_out": planning_timed_out,
        "intelligence_index_size": intelligence_index_size,
        "expansion_queries": expansion_queries[:3],
    }


def _spread_sample_functions(all_funcs: list[int], seen: set[int], remaining: int) -> list[int]:
    if remaining <= 0:
        return []

    pool = [ea for ea in all_funcs if ea not in seen]
    if remaining >= len(pool):
        return pool

    out = []
    step = max(1, len(pool) // remaining)
    start = min(len(pool) - 1, step // 2)
    for idx in range(start, len(pool), step):
        ea = pool[idx]
        if ea in seen:
            continue
        out.append(ea)
        seen.add(ea)
        if len(out) >= remaining:
            return out

    for ea in pool:
        if ea in seen:
            continue
        out.append(ea)
        seen.add(ea)
        if len(out) >= remaining:
            break
    return out


def search_constants(pattern, range_start, range_end, include_context, offset, limit, include_items):
    """Search for magic/crypto constants in instruction immediates."""
    import ida_ua
    const_matcher = compile_smart_pattern(pattern, case_sensitive=False) if pattern else None
    KNOWN_CONSTANTS = get_cached_constant_db()

    found_rows = []

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        curr = seg_start
        while curr < seg_end:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, curr) > 0:
                for op in insn.ops:
                    if op.type != ida_ua.o_imm:
                        continue
                    const_name = KNOWN_CONSTANTS.get(op.value)
                    if not const_name:
                        # Pattern-based magic detection for large values
                        if op.value > 0xFFFF:
                            hex_str = hex(op.value)[2:]
                            if len(hex_str) >= 6:
                                chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                                if len(set(chunks)) <= 3:
                                    const_name = f"PATTERN_{hex(op.value)}"
                    if const_name:
                        func = idaapi.get_func(curr)
                        fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                        if const_matcher and not const_matcher(f"{const_name} {hex(op.value)} {fn_name}"):
                            continue
                        line = f"{hex(curr)}  {hex(op.value)}  {const_name}  in:{fn_name}"
                        if include_context:
                            disasm_line = safe_generate_disasm_line(curr)
                            line += f"  {clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else '')}"
                        found_rows.append({
                            "address_ea": curr, "address": hex(curr),
                            "value": hex(op.value), "name": const_name,
                            "function": fn_name, "line": line,
                        })
                        break
                curr += insn.size
            else:
                curr = idc.next_head(curr, seg_end)

    page, total, is_truncated = paginate_records(
        found_rows, offset, limit, sort_key=lambda r: r["address_ea"], reverse=False
    )
    result = build_response([r["line"] for r in page], offset, limit, total, is_truncated, total_found=total)
    if include_items:
        result["items"] = [{"address": r["address"], "value": r["value"], "name": r["name"], "function": r["function"]} for r in page]
    if pattern:
        result["query"] = pattern
    return result


def search_decompiled(pattern, case_sensitive, range_start, range_end, offset, limit, include_items, **kwargs):
    """Search decompiled pseudocode using the embedding index for ranking.

    Requires a prior intelligence(action='index_fast') or index_batch call.
    The index narrows the search to the most relevant functions before decompiling.
    """
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)

    if not hasattr(ida_hexrays, "init_hexrays_plugin") or not ida_hexrays.init_hexrays_plugin():
        return make_error(
            MCPError.DECOMPILER_UNAVAILABLE,
            "Hex-Rays decompiler not available",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_UNAVAILABLE),
        )

    # Check embedding index — optional accelerator, not required
    asm, idx, _idb_path = _get_intelligence_index()
    index_available = idx is not None and idx.size > 0

    scope_addr = kwargs.get("addr") or kwargs.get("func") or kwargs.get("function") or kwargs.get("scope")
    try:
        timeout_ms = max(250, min(int(kwargs.get("timeout_ms", 8000)), 120000))
    except (ValueError, TypeError):
        timeout_ms = 8000
    try:
        max_functions = max(1, min(int(kwargs.get("max_functions", kwargs.get("sample_max_funcs", 512))), 5000))
    except (ValueError, TypeError):
        max_functions = 512
    if not index_available:
        max_functions = min(max_functions, 128)
    sample = bool(kwargs.get("sample", False))

    preview_lines = max(0, min(int(kwargs.get("preview_lines", 0)), 10))

    target_funcs = []
    scope_func = None
    planning_meta = {
        "tokens": [],
        "seeded_candidates": 0,
        "seed_reasons": {"cached": 0, "names": 0, "strings": 0, "imports": 0, "intelligence": 0, "behavior": 0},
        "planning_timed_out": False,
        "intelligence_index_size": idx.size if idx else 0,
        "expansion_queries": [],
    }
    total_available = 0
    coverage_mode = "scope"
    if scope_addr:
        target_ea, err = validate_addr(str(scope_addr))
        if err:
            target_ea = idc.get_name_ea_simple(str(scope_addr))
        scope_func = idaapi.get_func(target_ea) if target_ea != idaapi.BADADDR else None
        if not scope_func:
            return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {scope_addr}")
        target_funcs = [scope_func.start_ea]
    else:
        all_funcs = list(_iter_function_starts(range_start, range_end))
        total_available = len(all_funcs)
        if index_available:
            seeded_funcs, planning_meta = _seed_decompiled_candidates(
                pattern, matcher, range_start, range_end, max_functions, timeout_ms
            )
        else:
            seeded_funcs = []
            planning_meta["tokens"] = _decompiled_query_tokens(pattern)
        seen = set()
        for func_ea in seeded_funcs:
            if func_ea in seen:
                continue
            seen.add(func_ea)
            target_funcs.append(func_ea)
            if len(target_funcs) >= max_functions:
                break

        remaining = max(0, max_functions - len(target_funcs))
        if remaining > 0:
            if sample or total_available > max_functions:
                target_funcs.extend(_spread_sample_functions(all_funcs, seen, remaining))
                coverage_mode = "seeded_sample" if seeded_funcs else "sample"
            else:
                for func_ea in all_funcs:
                    if func_ea in seen:
                        continue
                    target_funcs.append(func_ea)
                    if len(target_funcs) >= max_functions:
                        break
                coverage_mode = "seeded_full" if seeded_funcs else "full"
        else:
            coverage_mode = "seeded" if seeded_funcs else "sample"

    scan_truncated = (not scope_func) and (total_available > len(target_funcs))

    rows = []
    func_stats = {}
    scanned = 0
    timed_out = False
    decompiled = 0
    failures = 0
    failure_samples = []
    started_at = _time.time()
    target_rank = {ea: idx for idx, ea in enumerate(target_funcs)}
    intelligence_backfilled = 0
    try:
        intelligence_backfill_limit = max(0, min(int(kwargs.get("intelligence_backfill", 12)), 64))
    except (TypeError, ValueError):
        intelligence_backfill_limit = 12
    asm, intelligence_idx, _idb_path = (asm, idx, _idb_path) if index_available else (None, None, "")

    for func_ea in target_funcs:
        if (_time.time() - started_at) >= (timeout_ms / 1000.0):
            timed_out = True
            break
        scanned += 1

        cache_key = _cache_key("decomp", func_ea)
        # Invalidate cache when function has been modified (rename, retype, etc.)
        try:
            mod_ctr = ida_funcs.get_func(func_ea).flags if ida_funcs.get_func(func_ea) else 0
        except Exception:
            mod_ctr = 0
        cache_key = _cache_key("decomp", func_ea, mod_ctr)
        cached = _cache_get(cache_key)
        if cached is not None:
            pseudocode = cached
        else:
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    failures += 1
                    continue
                pseudocode = str(cfunc)
                _cache_set(cache_key, pseudocode)
            except Exception as e:
                failures += 1
                if len(failure_samples) < 5:
                    failure_samples.append(str(e))
                continue

        decompiled += 1
        func_name = idc.get_func_name(func_ea) or hex(func_ea)
        if (
            intelligence_idx is not None
            and intelligence_backfilled < intelligence_backfill_limit
            and hex(func_ea) not in getattr(intelligence_idx, "_cache", {})
        ):
            try:
                intelligence_idx.index_async(hex(func_ea), func_name, pseudocode)
                intelligence_backfilled += 1
            except Exception:
                pass
        pseudocode_lines = pseudocode.splitlines()
        func_total_lines = len(pseudocode_lines)
        func_matched_lines = 0
        for line_num, line in enumerate(pseudocode_lines, 1):
            if matcher(line):
                func_matched_lines += 1
                text = clip_text(line.strip(), 220)
                row = {
                    "address_ea": func_ea, "address": hex(func_ea),
                    "function": func_name, "line_num": line_num,
                    "target_rank": target_rank.get(func_ea, scanned),
                    "raw_line": line.strip(),
                    "line": f"{hex(func_ea)}  {func_name}  L{line_num}: {text}",
                }
                # Add preview context lines if requested
                if preview_lines > 0:
                    ctx_start = max(0, line_num - 1 - preview_lines)
                    ctx_end = min(len(pseudocode_lines), line_num + preview_lines)
                    context = pseudocode_lines[ctx_start:ctx_end]
                    row["context"] = "\n".join(
                        f"{'>>>' if ctx_start + i == line_num - 1 else '   '} {ln}"
                        for i, ln in enumerate(context)
                    )
                rows.append(row)
        # Track per-function stats for re-ranking
        if func_matched_lines > 0:
            func_stats[func_ea] = {
                "name": func_name, "matched": func_matched_lines,
                "total": func_total_lines, "seeding_rank": target_rank.get(func_ea, scanned),
            }

    # Re-rank by match density: functions with more matches relative to their
    # size rank higher. Seeding rank breaks ties.
    if func_stats:
        max_seeding = max(s["seeding_rank"] for s in func_stats.values()) or 1
        for _ea, info in func_stats.items():
            density = info["matched"] / max(1, info["total"])
            seeding_norm = 1.0 - (info["seeding_rank"] / (max_seeding + 1))
            info["rerank_score"] = (density * 0.6) + (seeding_norm * 0.4) + (info["matched"] * 0.01)
        # Sort rows by new function score, then by line_num within function
        func_order = {ea: i for i, ea in enumerate(sorted(func_stats, key=lambda e: -func_stats[e]["rerank_score"]))}
        rows.sort(key=lambda r: (func_order.get(r["address_ea"], 999), r["line_num"]))

    if scanned > 0 and decompiled == 0 and failures > 0:
        return make_error(
            MCPError.DECOMPILER_FAILED,
            "Decompiled search failed to decompile any function",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
            details={
                "scanned": scanned,
                "failures": failures,
                "sample_errors": failure_samples,
                "candidate_strategy": coverage_mode,
                "candidate_pool": total_available,
                "seeded_candidates": planning_meta.get("seeded_candidates", 0),
                "seed_reasons": planning_meta.get("seed_reasons", {}),
                "query_tokens": planning_meta.get("tokens", []),
                "intelligence_index_size": planning_meta.get("intelligence_index_size", 0),
                "expansion_queries": planning_meta.get("expansion_queries", []),
            },
        )

    # Rows are already re-ranked; paginate directly
    page, total, is_truncated = paginate_records(
        rows, offset, limit, sort_key=None, reverse=False
    )
    result = build_response(
        [r["line"] for r in page], offset, limit, total, is_truncated,
        pattern=pattern, scanned_functions=scanned, decompiled_functions=decompiled,
        decompile_failures=failures, scan_limit=max_functions if not scope_func else 1,
        timeout_ms=timeout_ms, timed_out=timed_out,
    )
    if not scope_func:
        result["candidate_strategy"] = coverage_mode
        result["candidate_pool"] = total_available
        result["seeded_candidates"] = planning_meta.get("seeded_candidates", 0)
        result["seed_reasons"] = planning_meta.get("seed_reasons", {})
        result["query_tokens"] = planning_meta.get("tokens", [])
        result["intelligence_index_size"] = planning_meta.get("intelligence_index_size", 0)
        result["expansion_queries"] = planning_meta.get("expansion_queries", [])
        result["intelligence_backfilled"] = intelligence_backfilled
        if planning_meta.get("planning_timed_out"):
            result["planning_timed_out"] = True
    if scope_func:
        result["scope"] = hex(scope_func.start_ea)
    if scan_truncated or timed_out:
        result["analysis_truncated"] = True
        result["hint"] = (
            "Increase timeout_ms or scope with addr to search one function."
            if timed_out
            else "Increase max_functions, narrow with range/addr, or use search.find/search.nl to seed a tighter area first."
        )
    if include_items:
        items = []
        seen_funcs = set()
        for r in page:
            item = {
                "addr": r["address"],
                "name": r["function"],
                "line_num": r["line_num"],
                "text": clip_text(r.get("raw_line", ""), 200),
            }
            if r.get("context"):
                item["context"] = r["context"]
            # Add function-level stats if available
            ea = r["address_ea"]
            if ea in func_stats and ea not in seen_funcs:
                seen_funcs.add(ea)
                item["matched_lines"] = func_stats[ea]["matched"]
                item["total_lines"] = func_stats[ea]["total"]
            items.append(item)
        result["items"] = items

    if not index_available:
        result["note"] = "No embedding index — used brute-force scan. Run intelligence(action='index_fast') for better ranking."

    return result


def search_structured(constraints, pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms=0):
    """Structured function search using the embedding index.

    Supports structural constraints (size, bb_count, loops, api_count, segment)
    and optional semantic query for ranking. Requires a prior
    intelligence(action='index_fast') or index_batch call.

    Constraint keys:
      min_size, max_size: function byte size
      min_bb, max_bb: basic block count
      has_loops: bool
      min_api, max_api: API call count
      min_strings, max_strings: string reference count
      segment: str (e.g. ".text")
      is_thunk: bool
      min_cyclomatic, max_cyclomatic: cyclomatic complexity
      apis: list[str] — functions calling these APIs
    """
    if not isinstance(constraints, dict):
        return make_error(MCPError.INVALID_ARGS, "constraints must be a dict")
    if not constraints and not pattern:
        return make_error(MCPError.INVALID_ARGS, "constraints or pattern required")

    # Map legacy constraint names to new format
    query_constraints = {}
    c = constraints
    if "min_size" in c or "size" in c:
        op_size = c.get("size", c.get("min_size"))
        if isinstance(op_size, tuple):
            op, val = op_size
            if op == ">=": query_constraints["min_size"] = val
            elif op == "<=": query_constraints["max_size"] = val
        else:
            query_constraints["min_size"] = op_size
    if "max_size" in c and "size" not in c:
        query_constraints["max_size"] = c["max_size"]
    if "min_bb" in c or "bb_count" in c:
        query_constraints["min_bb"] = c.get("min_bb", c.get("bb_count"))
    if "max_bb" in c:
        query_constraints["max_bb"] = c["max_bb"]
    if "has_loops" in c:
        query_constraints["has_loops"] = c["has_loops"]
    if "min_api" in c or "api_count" in c:
        query_constraints["min_api"] = c.get("min_api", c.get("api_count"))
    if "max_api" in c:
        query_constraints["max_api"] = c["max_api"]
    if "min_strings" in c or "string_count" in c:
        query_constraints["min_strings"] = c.get("min_strings", c.get("string_count"))
    if "max_strings" in c:
        query_constraints["max_strings"] = c["max_strings"]
    if "segment" in c:
        query_constraints["segment"] = c["segment"]
    if "is_thunk" in c:
        query_constraints["is_thunk"] = c["is_thunk"]
    if "min_cyclomatic" in c or "cyclomatic" in c:
        query_constraints["min_cyclomatic"] = c.get("min_cyclomatic", c.get("cyclomatic"))
    if "max_cyclomatic" in c:
        query_constraints["max_cyclomatic"] = c["max_cyclomatic"]
    if "apis" in c:
        query_constraints["apis"] = c["apis"]

    # Get embedding index
    asm, idx, _idb_path = _get_intelligence_index()
    if idx is None or idx.size == 0:
        return make_error(
            MCPError.NOT_FOUND,
            "No functions indexed yet.",
            hint="Index your functions first:\n"
                 "  index_fast:  seconds, disassembly-based (quick triage)\n"
                 "  index_batch: minutes, decompile-based (best quality embeddings)",
        )

    # Use embedding index structured search
    query = pattern if pattern else None
    rows = idx.search_structured(query_constraints, query=query, top_k=limit + offset)

    # Apply offset
    rows = rows[offset:offset + limit]

    results = []
    items = []
    for r in rows:
        line = f"{r['ea']}  {r['name']}  size={r['func_size']}  bb={r['bb_count']}  apis={r['api_count']}"
        if r.get("has_loops"):
            line += "  loops"
        if r.get("segment"):
            line += f"  seg={r['segment']}"
        results.append(line)
        items.append({
            "addr": str(r["ea"]),
            "name": r["name"],
            "func_size": r["func_size"],
            "bb_count": r["bb_count"],
            "has_loops": r["has_loops"],
            "api_count": r["api_count"],
            "string_count": r["string_count"],
            "segment": r["segment"],
            "is_thunk": r["is_thunk"],
            "cyclomatic": r["cyclomatic"],
        })

    return {
        "ok": True, "action": "structured", "constraints": constraints,
        "matches": "\n".join(results), "count": len(results),
        "items": items,
        "note": f"Structured search via embedding index ({'semantic ranking' if query else 'structural only'}).",
        "index_used": True,
    }
