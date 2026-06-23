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

from .core import (
    clip_text, paginate_records, build_response, iter_segments, _cache_get, _cache_set, _cache_key, _SEARCH_CACHE,
    get_cached_constant_db, get_cached_imports, get_cached_strings,
    _get_db_fingerprint, SearchTimeout, safe_generate_disasm_line,
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
    if not blob or not tokens:
        return False
    lowered = blob.lower()
    return any(tok in lowered for tok in tokens)


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


def search_vulnerable(pattern, include_context, offset, limit, include_items, include_breakdown, **kwargs):
    """Search for potentially vulnerable API call patterns."""
    rows = []
    max_xrefs = int(kwargs.get("max_xrefs", 100000))
    xref_count = 0
    for seg_start, seg_end in iter_segments(None, None, require_exec=True):
        for func_ea in idautils.Functions(seg_start, seg_end):
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref_count >= max_xrefs:
                        break
                    xref_count += 1
                    if xref.type not in (idaapi.fl_CN, idaapi.fl_CF):
                        continue
                    callee = idc.get_name(xref.to)
                    if not callee:
                        continue
                    if callee in DANGEROUS_APIS:
                        fn_name = idc.get_func_name(func_ea)
                        line = f"{hex(head)}  sev={DANGEROUS_APIS.get(callee, 'medium')}  {callee}  in:{fn_name}"
                        if include_context:
                            disasm_line = safe_generate_disasm_line(head)
                            line += f"  {clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else '')}"
                        rows.append({
                            "address": hex(head),
                            "function": fn_name,
                            "api": callee,
                            "vuln_type": DANGEROUS_APIS.get(callee, "unknown"),
                            "severity": DANGEROUS_APIS.get(callee, "medium"),
                            "score": 0,
                            "line": line,
                        })
                if xref_count >= max_xrefs:
                    break
            if xref_count >= max_xrefs:
                break
        if xref_count >= max_xrefs:
            break

    if pattern:
        matcher = compile_smart_pattern(pattern, case_sensitive=False)
        rows = [r for r in rows if matcher(r.get("api", "")) or matcher(r.get("function", ""))]

    page, total, is_truncated = paginate_records(
        rows, offset, limit, sort_key=lambda r: (r.get("score", 0), r["address"]), reverse=True
    )

    result = build_response([r["line"] for r in page], offset, limit, total, is_truncated, total_findings=total)
    if include_items:
        result["items"] = [
            {"address": r["address"], "function": r["function"], "type": r["vuln_type"], "severity": r["severity"], "api": r["api"], "score": r["score"]}
            for r in page
        ]
    if include_breakdown:
        by_type = {}
        for r in rows:
            by_type[r["vuln_type"]] = by_type.get(r["vuln_type"], 0) + 1
        result["type_totals"] = by_type
    if pattern:
        result["query"] = pattern
    return result


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
    """Search decompiled pseudocode with caching."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)

    if not hasattr(ida_hexrays, "init_hexrays_plugin") or not ida_hexrays.init_hexrays_plugin():
        return make_error(
            MCPError.DECOMPILER_UNAVAILABLE,
            "Hex-Rays decompiler not available",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_UNAVAILABLE),
        )

    scope_addr = kwargs.get("addr") or kwargs.get("func") or kwargs.get("function") or kwargs.get("scope")
    try:
        timeout_ms = max(250, min(int(kwargs.get("timeout_ms", 8000)), 120000))
    except (ValueError, TypeError):
        timeout_ms = 8000
    try:
        max_functions = max(1, min(int(kwargs.get("max_functions", kwargs.get("sample_max_funcs", 512))), 5000))
    except (ValueError, TypeError):
        max_functions = 512
    sample = bool(kwargs.get("sample", False))

    target_funcs = []
    scope_func = None
    planning_meta = {
        "tokens": [],
        "seeded_candidates": 0,
        "seed_reasons": {"cached": 0, "names": 0, "strings": 0, "imports": 0, "intelligence": 0, "behavior": 0},
        "planning_timed_out": False,
        "intelligence_index_size": 0,
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
        seeded_funcs, planning_meta = _seed_decompiled_candidates(
            pattern, matcher, range_start, range_end, max_functions, timeout_ms
        )
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
    asm, intelligence_idx, _idb_path = _get_intelligence_index() if not scope_func else (None, None, "")

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
        for line_num, line in enumerate(pseudocode.splitlines(), 1):
            if matcher(line):
                text = clip_text(line.strip(), 220)
                rows.append({
                    "address_ea": func_ea, "address": hex(func_ea),
                    "function": func_name, "line_num": line_num,
                    "target_rank": target_rank.get(func_ea, scanned),
                    "line": f"{hex(func_ea)}  {func_name}  L{line_num}: {text}",
                })

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

    page, total, is_truncated = paginate_records(
        rows, offset, limit, sort_key=lambda r: (r.get("target_rank", 0), r["address_ea"], r["line_num"]), reverse=False
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
        result["items"] = [{"address": r["address"], "function": r["function"], "line_num": r["line_num"]} for r in page]

    # Auto-write blackboard entries for unique matching functions
    if rows and not scope_func:
        try:
            from blackboard import BlackboardStore  # type: ignore
            store = BlackboardStore()
            seen_funcs = set()
            for r in rows[:10]:  # cap at 10 auto-writes
                fea = r["address"]
                if fea in seen_funcs:
                    continue
                seen_funcs.add(fea)
                existing = store.list(addr=fea, limit=1, include_resolved=False)
                if not existing:
                    store.write(
                        title=f"decompiled match: '{pattern[:40]}' in {r['function']}",
                        category="hypothesis",
                        addr=fea,
                        content=r["line"],
                        tags=["decompiled_search", "auto"],
                        confidence=0.6,
                        source="search_decompiled",
                        source_type="human",
                        embed=False,
                    )
        except Exception:
            pass

    return result


def _sql_filterable_keys() -> set:
    """Return set of constraint keys that can be filtered at the SQL level."""
    from ...support.hybrid_search import SQL_FILTERABLE_COLUMNS, JUNCTION_TABLES, LEGACY_RANGE_PREFIXES
    keys = set(SQL_FILTERABLE_COLUMNS.keys())
    keys.update(JUNCTION_TABLES.keys())
    keys.update(LEGACY_RANGE_PREFIXES.keys())
    keys.update({"has_crypto_constants", "constants_value"})
    return keys


def _split_constraints(constraints: dict) -> tuple[dict, dict]:
    """Split constraints into SQL-filterable and schema-only portions.
    
    SQL-filterable constraints go to the schemaboot DB pre-filter.
    Schema-only constraints (behavior_tags, dangerous_apis, etc.)
    require per-function schema induction.
    """
    sql_keys = _sql_filterable_keys()
    sql_filterable = {}
    schema_only = {}
    for k, v in constraints.items():
        if k in sql_keys:
            sql_filterable[k] = v
        else:
            schema_only[k] = v
    return sql_filterable, schema_only


def _schemaboot_db_path() -> str | None:
    """Get the schemaboot DB path for the current IDB, with read-only fallback support."""
    primary = None
    try:
        import ida_loader
        primary = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) + ".schemaboot.db"
    except Exception:
        try:
            import idc
            primary = idc.get_idb_path() + ".schemaboot.db"
        except Exception:
            pass
            
    if not primary:
        return None
        
    import os
    if os.path.exists(primary):
        return primary
        
    import hashlib
    try:
        from ida_pro_mcp.services import CACHE_DIR
    except ImportError:
        import sys
        if sys.platform == "win32":
            root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local")
            CACHE_DIR = os.path.realpath(os.path.join(root, "ida-pro-mcp"))
        elif sys.platform == "darwin":
            CACHE_DIR = os.path.realpath(os.path.join(os.path.expanduser("~"), "Library", "Application Support", "ida-pro-mcp"))
        else:
            xdg_state = os.environ.get("XDG_STATE_HOME")
            if xdg_state:
                CACHE_DIR = os.path.realpath(os.path.join(xdg_state, "ida-pro-mcp"))
            else:
                CACHE_DIR = os.path.realpath(os.path.join(os.path.expanduser("~"), ".local", "state", "ida-pro-mcp"))

    h = hashlib.sha256(os.path.abspath(primary).encode("utf-8")).hexdigest()[:16]
    fallback = os.path.join(CACHE_DIR, "fallback_indexes", f"{h}.schemaboot.db")
    if os.path.exists(fallback):
        return fallback
        
    return primary


def _sql_pre_filter_functions(
    sql_constraints: dict,
) -> tuple[list[int] | None, dict]:
    """Use HybridSearch to pre-filter function candidates via SQL.
    
    Returns:
        (candidate_eas, info_dict)
        candidate_eas is None if DB unavailable or no filterable constraints
    """
    if not sql_constraints:
        return None, {"note": "no_sql_constraints"}

    db_path = _schemaboot_db_path()
    if not db_path:
        return None, {"note": "no_db_path"}

    import os
    if not os.path.exists(db_path):
        return None, {"note": "db_not_found", "db_path": db_path}

    try:
        from ...support.hybrid_search import HybridSearchEngine
        engine = HybridSearchEngine(db_path)
        eas, elapsed_ms, meta = engine.pre_filter(sql_constraints)
        if eas is None:
            return None, {"note": "sql_error", "detail": meta.get("error", "")}
        return eas, {
            "note": "sql_pre_filter",
            "total_matches": meta.get("total", 0),
            "sql_ms": elapsed_ms,
        }
    except Exception as e:
        return None, {"note": "sql_exception", "error": str(e)}


def _verify_sql_coverage(
    constraints: dict,
    sql_candidates: list[int] | None,
    sql_info: dict,
) -> bool:
    """Check if SQL candidates cover all constraints.
    
    If SQL returned None (DB not available), we return False so caller
    falls through to full iteration.
    If SQL returned empty list, we return True (no results to process).
    """
    if sql_candidates is None:
        return False
    return True


def search_structured(constraints, pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms=0):
    """Schema-based structured semantic retrieval with SQL pre-filtering.
    
    Two-phase hybrid approach:
      Phase 0: SQL pre-filter via schemaboot DB (if filterable constraints exist)
      Phase 1: Schema induction + behavior matching on the reduced candidate pool
    
    Falls back to full iteration if schemaboot DB is unavailable.
    Supports both legacy constraints (min_size, apis, has_loops) and
    operator format ({"size": (">=", 100), "name": ("~", "pattern")}).
    """
    if not isinstance(constraints, dict):
        return make_error(MCPError.INVALID_ARGS, "constraints must be a dict")
    if not constraints and not pattern:
        return make_error(MCPError.INVALID_ARGS, "constraints or pattern required")

    try:
        from ..classify import _classify_func, _induce_function_schema
    except ImportError:
        from classify import _classify_func, _induce_function_schema  # type: ignore[import-not-found]
    try:
        from ..annotation import _DANGEROUS_APIS, _TAG_CATEGORIES
    except ImportError:
        from annotation import _DANGEROUS_APIS, _TAG_CATEGORIES  # type: ignore[import-not-found]

    def induce_schema(func_ea):
        db_fp = _get_db_fingerprint()
        cache_key = _cache_key("schema", db_fp, func_ea)
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        schema = {
            "addr": hex(func_ea),
            "behavior_tags": set(),
            "dangerous_apis": set(),
            "string_refs": set(),
            "vuln_class": set(),
            "compiler_hints": set(),
            "structural_features": set(),
        }
        fn = ida_funcs.get_func(func_ea)
        if not fn:
            _cache_set(cache_key, schema)
            return schema

        try:
            timer.check()
        except TimeoutError:
            return schema

        cat, matched_apis, all_callees = _classify_func(func_ea)
        if cat != "unknown":
            schema["behavior_tags"].add(cat)
        for c, apis in matched_apis.items():
            schema["behavior_tags"].add(c)
            for api in apis:
                if api in _DANGEROUS_APIS:
                    schema["dangerous_apis"].add(api)
                    schema["vuln_class"].add("dangerous_api")

        # Reuse the classifier-side schema induction so the structured search
        # and direct classify() path stay aligned.
        try:
            richer = _induce_function_schema(func_ea)
            if isinstance(richer, dict):
                for key in ("behavior_tags", "dangerous_apis", "string_refs", "vuln_class", "compiler_hints", "structural_features"):
                    values = richer.get(key, [])
                    if isinstance(values, (list, tuple, set)):
                        schema[key].update(values)
        except Exception:
            pass

        try:
            timer.check()
        except TimeoutError:
            _cache_set(cache_key, schema)
            return schema

        for callee_name in all_callees:
            base = callee_name
            for suffix in ("A", "W", "@plt", "@PLT"):
                if base.endswith(suffix):
                    base = base[:-len(suffix)]
                    break
            for tag, apis in _TAG_CATEGORIES.items():
                if any(api.lower() == base.lower() for api in apis):
                    schema["behavior_tags"].add(tag)

        try:
            timer.check()
        except TimeoutError:
            _cache_set(cache_key, schema)
            return schema

        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            for dref in idautils.DataRefsFrom(head):
                stype = idc.get_str_type(dref)
                if stype is not None and stype >= 0:
                    s = idc.get_strlit_contents(dref, -1, stype)
                    if s:
                        s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                        schema["string_refs"].add(s[:60])
                        if any(proto in s for proto in ("http://", "https://", "ftp://", "tcp://")):
                            schema["behavior_tags"].add("network")
                        if "HKEY_" in s or "Software\\" in s:
                            schema["behavior_tags"].add("registry")
                        if s.startswith("C:\\") or "/home/" in s or "/usr/" in s or "/etc/" in s:
                            schema["behavior_tags"].add("file_io")

        _cache_set(cache_key, schema)
        return schema

    def _norm_hex(v):
        try:
            s = str(v).strip().lower()
            if not s:
                return None
            if s.startswith("0x"):
                return s
            return hex(int(s, 0)).lower()
        except Exception:
            return None

    def schema_matches(schema, constraints):
        allow_addrs = constraints.get("addrs")
        if allow_addrs:
            allowed = set()
            seq = allow_addrs if isinstance(allow_addrs, (list, tuple, set)) else [allow_addrs]
            for a in seq:
                na = _norm_hex(a)
                if na:
                    allowed.add(na)
            fn_addr = _norm_hex(schema.get("addr", ""))
            if allowed and fn_addr not in allowed:
                return False
        for key, val in constraints.items():
            if key == "addrs":
                continue
            if key == "behavior_tags":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["behavior_tags"] for v in vals):
                    return False
            elif key == "dangerous_apis":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["dangerous_apis"] for v in vals):
                    return False
            elif key == "compiler_hints":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["compiler_hints"] for v in vals):
                    return False
            elif key == "vuln_class":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["vuln_class"] for v in vals):
                    return False
            elif key == "structural_features":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["structural_features"] for v in vals):
                    return False
            elif key == "string_refs":
                matcher = compile_smart_pattern(str(val), case_sensitive=False)
                if not any(matcher(s) for s in schema["string_refs"]):
                    return False
            else:
                all_vals = []
                for v in schema.values():
                    if isinstance(v, (list, tuple, set)):
                        all_vals.extend(str(item) for item in v)
                    elif v is not None:
                        all_vals.append(str(v))
                if str(val).lower() not in " ".join(all_vals).lower():
                    return False
        return True

    results = []
    schema_hits = {}
    matcher = compile_smart_pattern(pattern, case_sensitive=False) if pattern else None
    timer = SearchTimeout(timeout_ms)
    timed_out = False
    matches_seen = 0

    # ---- Phase 0: SQL pre-filter (if applicable) ----
    sql_constraints, schema_constraints = _split_constraints(constraints)
    sql_candidates, sql_info = _sql_pre_filter_functions(sql_constraints)
    sql_used = sql_candidates is not None
    pre_filter_note = ""

    if sql_used:
        if sql_candidates:
            pre_filter_note = (
                f"SQL pre-filter narrowed {sql_info.get('total_matches', 0)} candidates "
                f"in {sql_info.get('sql_ms', 0):.1f}ms"
            )
        else:
            pre_filter_note = "SQL pre-filter: no candidates matched"

    # Build function iterator: SQL candidates or full scan
    if sql_used and sql_candidates is not None:
        func_iter = sql_candidates
    else:
        func_iter = idautils.Functions()

    # ---- Phase 1: Schema induction + matching on candidate pool ----
    for func_ea in func_iter:
        try:
            timer.check()
        except TimeoutError:
            timed_out = True
            break

        schema = induce_schema(func_ea)

        # Apply schema-only constraints (behavior_tags, etc.)
        if not schema_matches(schema, schema_constraints if schema_constraints else constraints):
            continue

        fname = idc.get_func_name(func_ea) or f"sub_{func_ea:x}"
        tags = ", ".join(sorted(schema["behavior_tags"]))
        dangerous = ", ".join(sorted(schema["dangerous_apis"]))
        line = f"{hex(func_ea)}  {fname}  tags=[{tags}]"
        if dangerous:
            line += f"  dangerous=[{dangerous}]"
        if pattern and not matcher(line):
            continue
        matches_seen += 1
        if matches_seen <= offset:
            continue
        results.append(line)
        schema_hits[hex(func_ea)] = {
            "name": fname,
            "behavior_tags": sorted(schema["behavior_tags"]),
            "dangerous_apis": sorted(schema["dangerous_apis"]),
            "string_refs": sorted(schema["string_refs"])[:5],
            "compiler_hints": sorted(schema["compiler_hints"]),
            "structural_features": sorted(schema["structural_features"]),
        }
        if len(results) >= limit:
            break

    out = {
        "ok": True, "action": "structured", "constraints": constraints,
        "matches": "\n".join(results), "count": len(results),
        "schema_hits": schema_hits,
        "note": "Structured semantic retrieval pre-filters by induced function schema.",
    }
    if sql_used:
        out["sql_pre_filter"] = True
        out["sql_info"] = {
            "candidates": len(sql_candidates) if sql_candidates else 0,
            "total_matches": sql_info.get("total_matches", 0),
            "sql_ms": round(sql_info.get("sql_ms", 0), 2),
        }
        out["note"] += f" | {pre_filter_note}"
    if timed_out:
        out["timed_out"] = True
        out["hint"] = "Search timed out. Increase timeout_ms or tighten constraints."
    return out
