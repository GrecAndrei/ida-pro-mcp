"""SEARCH.UNIFIED - Smart unified find, callers, callees, and API usage."""

import heapq
import re

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ...support.semantic_matching import semantic_score
except ImportError:
    from support.semantic_matching import semantic_score  # type: ignore[import-not-found]

from .core import (
    _FIND_INSTRUCTION_CAP,
    _FIND_INSTRUCTION_LIMIT_MULTIPLIER,
    CALL_XREF_TYPES,
    SCORE_SUBSTRING,
    SearchTimeout,
    build_response,
    clip_text,
    get_cached_imports,
    get_cached_strings,
    iter_code,
    iter_segments,
    paginate_records,
    resolve_target,
    safe_generate_disasm_line,
    xref_count_limited,
)


def search_find(pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms=0):
    """Smart unified search with bounded memory."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    ranked_heap = []
    heap_cap = max(_FIND_INSTRUCTION_CAP, limit * _FIND_INSTRUCTION_LIMIT_MULTIPLIER)
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    def add_find(kind, ea, line, score):
        key = (float(score), int(ea))
        record = {"type": kind, "address": hex(ea), "address_ea": ea, "score": score, "line": line}
        if len(ranked_heap) < heap_cap:
            heapq.heappush(ranked_heap, (key, record))
        elif key > ranked_heap[0][0]:
            heapq.heapreplace(ranked_heap, (key, record))

    # 1. Xrefs for address patterns
    if looks_like_address(pattern):
        ea, addr_err = validate_addr(pattern)
        if addr_err:
            try:
                ea = int(pattern, 16)
            except Exception:
                ea = idaapi.BADADDR
        if ea != idaapi.BADADDR:
            for xref in idautils.XrefsTo(ea, 0):
                func = idaapi.get_func(xref.frm)
                fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                sem_name = semantic_score(pattern, fn_name, substring_bonus=SCORE_SUBSTRING) if fn_name else 0.0
                if xref.iscode:
                    add_find("code_ref", xref.frm, f"{hex(xref.frm)}  {fn_name}", max(1.0, sem_name))
                else:
                    add_find("data_ref", xref.frm, f"{hex(xref.frm)}  {fn_name}", max(1.0, sem_name))

    seen_eas = set()

    # 2. Names
    for ea, name in idautils.Names():
        if ea in seen_eas:
            continue
        if matcher(name):
            kind = "func" if idaapi.get_func(ea) else "data"
            xref_count = xref_count_limited(ea)
            score = semantic_score(pattern, name, substring_bonus=SCORE_SUBSTRING)
            add_find("names", ea, f"{hex(ea)}  {kind}  {name}  xrefs={xref_count}", score)
            seen_eas.add(ea)

    # 3. Strings (cached)
    for srec in get_cached_strings():
        ea = srec["ea"]
        if ea in seen_eas:
            continue
        s = srec["string"]
        if matcher(s):
            xref_count = xref_count_limited(ea)
            score = semantic_score(pattern, s, substring_bonus=SCORE_SUBSTRING)
            add_find("strings", ea, f"{hex(ea)}  xrefs={xref_count}  {clip_text(s, 180)}", score)
            seen_eas.add(ea)

    # 4. Imports (cached)
    for irec in get_cached_imports():
        ea = irec["ea"]
        if ea in seen_eas:
            continue
        name = irec["name"]
        mod_name = irec["module"]
        if name and matcher(name):
            xref_count = xref_count_limited(ea)
            score = semantic_score(pattern, name, substring_bonus=SCORE_SUBSTRING)
            add_find("imports", ea, f"{hex(ea)}  {mod_name}  {name}  xrefs={xref_count}", score)
            seen_eas.add(ea)

    # 5. Instructions (bounded)
    instruction_hits = 0
    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        if instruction_hits >= _FIND_INSTRUCTION_CAP or timed_out:
            break
        for ea in iter_code(seg_start, seg_end):
            if instruction_hits >= _FIND_INSTRUCTION_CAP:
                break
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            line = safe_generate_disasm_line(ea)
            if not line:
                continue
            line_clean = ida_lines.tag_remove(line) or ""
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            semantic_blob = f"{mnem} {line_clean}"
            sem = min(semantic_score(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING), 160.0)
            if matcher(semantic_blob) or sem > 0.0:
                add_find("instructions", ea, f"{hex(ea)}  {mnem}  {clip_text(line_clean, 180)}", sem)
                instruction_hits += 1

    ranked = [item[1] for item in ranked_heap]
    page, total, is_truncated = paginate_records(
        ranked, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )

    by_type = {"names": [], "strings": [], "imports": [], "instructions": [], "code_refs": [], "data_refs": []}
    type_to_key = {
        "names": "names", "strings": "strings", "imports": "imports",
        "instructions": "instructions", "code_ref": "code_refs", "data_ref": "data_refs",
    }
    for row in page:
        key = type_to_key.get(row["type"])
        if key:
            by_type[key].append(row["line"])

    result = build_response([r["line"] for r in page], offset, limit, total, is_truncated, query=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    if include_items:
        result["items"] = [{"type": r["type"], "address": r["address"], "score": r["score"], "text": r["line"]} for r in page]
    if include_breakdown:
        result["type_totals"] = {
            "names": sum(1 for r in ranked if r["type"] == "names"),
            "strings": sum(1 for r in ranked if r["type"] == "strings"),
            "imports": sum(1 for r in ranked if r["type"] == "imports"),
            "instructions": sum(1 for r in ranked if r["type"] == "instructions"),
            "code_refs": sum(1 for r in ranked if r["type"] == "code_ref"),
            "data_refs": sum(1 for r in ranked if r["type"] == "data_ref"),
        }
        for key in by_type:
            result[key] = "\n".join(by_type[key])
    return result


def search_semantic(pattern, include_context, range_start, range_end, offset, limit, include_items, timeout_ms=0):
    """Natural-language semantic search using the embedding index.

    Requires a prior intelligence(action='index_fast') or index_batch call.
    Falls back to heuristic search only if the index is unavailable.
    """
    query = (pattern or "").strip()
    if not query:
        return make_error(MCPError.INVALID_ARGS, "pattern or query required")

    # Try embedding-index search first (proper semantic search)
    try:
        from ida_pro_mcp.services import get_assembler
        asm = get_assembler()
        idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        if idb_path:
            idx = asm._get_index(idb_path)
            if idx and idx.size > 0:
                hits = idx.search(query, top_k=max(limit * 3, 48), threshold=0.0)
                rows = []
                seen_eas = set()
                for hit in hits:
                    ea_str = hit.get("ea", "")
                    if not ea_str or ea_str in seen_eas:
                        continue
                    try:
                        ea_int = int(ea_str, 16)
                    except Exception:
                        continue
                    # range filter
                    if range_start is not None and range_end is not None:
                        if not (range_start <= ea_int < range_end):
                            continue
                    seen_eas.add(ea_str)
                    name = hit.get("name", ea_str)
                    sim = float(hit.get("similarity") or 0.0)
                    func = idaapi.get_func(ea_int)
                    kind = "func" if func else "symbol"
                    xr = xref_count_limited(ea_int, 64)
                    line = f"{hex(ea_int)}  {kind}  {name}  sim={sim:.2f}  xrefs={xr}"
                    rows.append({"type": kind, "address": hex(ea_int), "address_ea": ea_int,
                                 "score": sim, "feature": "embedding", "line": line})
                page, total, is_truncated = paginate_records(
                    rows, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"]),
                )
                result = build_response(
                    [r["line"] for r in page],
                    offset, limit, total, is_truncated,
                    pattern=query, search_mode="semantic_embedding",
                )
                result["backend"] = asm._embedder.backend if hasattr(asm, "_embedder") else "bge"
                if include_items:
                    result["items"] = [{"address": r["address"], "name": r.get("name", ""),
                                        "similarity": r["score"]} for r in page]
                return result
    except Exception:
        pass

    # Index not available — tell the user to index first
    return make_error(
        MCPError.NOT_FOUND,
        "No functions indexed yet. Run intelligence(action='index_fast') first.",
        hint="index_fast builds an index from disassembly in seconds (no decompile needed). "
             "Then search(action='semantic') uses proper embedding-based similarity.",
    )

    # --- fallback heuristic (only if explicitly requested via _fallback=true) ---
    ranked_heap = []
    heap_cap = max(_FIND_INSTRUCTION_CAP, limit * _FIND_INSTRUCTION_LIMIT_MULTIPLIER)
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    def add_hit(kind, ea, line, score, feature):
        if score <= 0:
            return
        key = (float(score), int(ea))
        record = {
            "type": kind,
            "address": hex(ea),
            "address_ea": ea,
            "score": round(float(score), 2),
            "feature": feature,
            "line": line,
        }
        if len(ranked_heap) < heap_cap:
            heapq.heappush(ranked_heap, (key, record))
        elif key > ranked_heap[0][0]:
            heapq.heapreplace(ranked_heap, (key, record))

    # Symbols/functions
    for ea, name in idautils.Names():
        if not name:
            continue
        score = semantic_score(query, name, substring_bonus=SCORE_SUBSTRING)
        if score > 0.0:
            kind = "func" if idaapi.get_func(ea) else "symbol"
            xr = xref_count_limited(ea, 64)
            line = f"{hex(ea)}  {kind}  {name}  xrefs={xr}"
            add_hit("name", ea, line, score, "symbol_name")

    # Imports/API names
    for irec in get_cached_imports():
        name = irec.get("name") or ""
        if not name:
            continue
        score = semantic_score(query, name, substring_bonus=SCORE_SUBSTRING)
        if score > 0.0:
            ea = irec["ea"]
            module = irec.get("module") or "unknown"
            xr = xref_count_limited(ea, 64)
            line = f"{hex(ea)}  import  {module}!{name}  xrefs={xr}"
            add_hit("import", ea, line, score, "import_name")

    # String literals
    for srec in get_cached_strings():
        s = srec.get("string") or ""
        if not s:
            continue
        score = semantic_score(query, s, substring_bonus=SCORE_SUBSTRING)
        if score > 0.0:
            ea = srec["ea"]
            xr = xref_count_limited(ea, 64)
            line = f"{hex(ea)}  string  xrefs={xr}  {clip_text(s, 180)}"
            add_hit("string", ea, line, score, "string_literal")

    # Disassembly semantics
    insn_hits = 0
    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        if insn_hits >= _FIND_INSTRUCTION_CAP or timed_out:
            break
        for ea in iter_code(seg_start, seg_end):
            if insn_hits >= _FIND_INSTRUCTION_CAP:
                break
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            line = safe_generate_disasm_line(ea)
            if not line:
                continue
            line_clean = ida_lines.tag_remove(line) or ""
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            semantic_blob = f"{mnem} {line_clean}"
            score = semantic_score(query, semantic_blob, substring_bonus=SCORE_SUBSTRING)
            if score > 0.0:
                out_line = f"{hex(ea)}  insn  {mnem}  {clip_text(line_clean, 180)}"
                add_hit("instruction", ea, out_line, 60.0 + min(score, 120.0), "instruction_text")
                insn_hits += 1

    ranked = [item[1] for item in ranked_heap]
    page, total, is_truncated = paginate_records(
        ranked,
        offset,
        limit,
        sort_key=lambda r: (r["score"], r["address_ea"]),
    )

    result = build_response(
        [r["line"] for r in page],
    offset,
        limit,
        total,
        is_truncated,
        query=query,
        search_mode="semantic",
    )
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Semantic scan timed out. Narrow with range or increase timeout_ms."
    if include_items:
        result["items"] = [
            {
                "type": r["type"],
                "address": r["address"],
                "score": r["score"],
                "feature": r["feature"],
                "text": r["line"],
            }
            for r in page
        ]
    return result


def _build_call_graph_rows(func, get_relations):
    """Build a {func_start_ea -> row} map of callers/callees for `func`.

    `get_relations(func)` is a callable that yields (other_ea, site_ea) pairs:
      - (caller_ea, call_site) for callers
      - (callee_ea, call_site) for callees
    The pair represents one cross-reference edge.

    Returns dict keyed by other_ea with shape:
        {address_ea, address, name, call_sites: [site_ea, ...]}
    """
    rows = {}
    for other_ea, site_ea in get_relations(func):
        other_func = idaapi.get_func(other_ea)
        if not other_func:
            continue
        key = other_func.start_ea
        if key not in rows:
            rows[key] = {
                "address_ea": key, "address": hex(key),
                "name": ida_funcs.get_func_name(key), "call_sites": [],
            }
        rows[key]["call_sites"].append(site_ea)
    return rows


def _format_call_graph_response(
    rows, func, target_ea, sem_meta,
    *, include_context, offset, limit, include_items, empty_note,
):
    """Rank, format, paginate, and return a call-graph response payload.

    `rows` is the {func_ea -> {address_ea, address, name, call_sites}} dict
    produced by `_build_call_graph_rows`. `empty_note` is the response
    `note` shown when the graph is empty.
    """
    if not rows:
        return build_response(
            [], offset, limit, 0, False,
            target=idc.get_name(target_ea) or hex(target_ea),
            target_addr=hex(func.start_ea),
            note=empty_note,
        )

    ranked = []
    for row in rows.values():
        call_sites = sorted(set(row["call_sites"]))
        first_site = call_sites[0] if call_sites else row["address_ea"]
        line = f"{row['address']}  {row['name']}  calls={len(call_sites)}  first@{hex(first_site)}"
        if include_context and call_sites:
            disasm_line = safe_generate_disasm_line(first_site)
            line += f"  {clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else '')}"
        row["line"] = line
        row["score"] = len(call_sites)
        row["first_site"] = hex(first_site)
        ranked.append(row)

    page, total, is_truncated = paginate_records(
        ranked, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )
    result = build_response(
        [r["line"] for r in page], offset, limit, total, is_truncated,
        target=idc.get_name(target_ea) or hex(target_ea), target_addr=hex(func.start_ea)
    )
    result.update(sem_meta)
    if include_items:
        result["items"] = [
            {"address": r["address"], "name": r["name"], "call_count": r["score"], "first_call_site": r["first_site"]}
            for r in page
        ]
    return result


def search_callers(pattern, include_context, offset, limit, semantic_min_score, include_alternatives, include_items):
    """Find functions calling target."""
    target_ea, error, sem_meta = resolve_target(
        pattern, require_function=True, include_imports=False,
        semantic_min_score=semantic_min_score, include_alternatives=include_alternatives
    )
    if error:
        return build_response(
            [],
            offset,
            limit,
            0,
            False,
            target=str(pattern),
            note="Target is not a function address/name. Returning empty callers list.",
        )

    func = idaapi.get_func(target_ea)
    if not func:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

    def _iter_caller_edges(target_func):
        for xref in idautils.XrefsTo(target_func.start_ea, 0):
            if not xref.iscode:
                continue
            yield (xref.frm, xref.frm)

    rows = _build_call_graph_rows(func, _iter_caller_edges)
    return _format_call_graph_response(
        rows, func, target_ea, sem_meta,
        include_context=include_context,
        offset=offset, limit=limit, include_items=include_items,
        empty_note="Target has no callers.",
    )


def search_callees(pattern, include_context, offset, limit, semantic_min_score, include_alternatives, include_items):
    """Find functions called by target."""
    target_ea, error, sem_meta = resolve_target(
        pattern, require_function=True, include_imports=False,
        semantic_min_score=semantic_min_score, include_alternatives=include_alternatives
    )
    if error:
        return build_response(
            [],
            offset,
            limit,
            0,
            False,
            target=str(pattern),
            note="Target is not a function address/name. Returning empty callees list.",
        )

    func = idaapi.get_func(target_ea)
    if not func:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

    def _iter_callee_edges(target_func):
        for item in idautils.FuncItems(target_func.start_ea):
            for xref in idautils.XrefsFrom(item, 0):
                if xref.type not in CALL_XREF_TYPES:
                    continue
                yield (xref.to, item)

    rows = _build_call_graph_rows(func, _iter_callee_edges)
    return _format_call_graph_response(
        rows, func, target_ea, sem_meta,
        include_context=include_context,
        offset=offset, limit=limit, include_items=include_items,
        empty_note="Target calls no functions.",
    )


def search_api(pattern, include_context, offset, limit, include_items, include_breakdown):
    """Find API usages."""
    matcher = compile_smart_pattern(pattern, case_sensitive=False)
    matched_apis = []

    for irec in get_cached_imports():
        name = irec["name"]
        if name and matcher(name):
            ea = irec["ea"]
            matched_apis.append({
                "ea": ea, "name": name, "module": irec["module"],
                "score": semantic_score(pattern, name),
            })

    if not matched_apis:
        target_ea, sem_err, sem_meta = resolve_target(pattern, require_function=False, include_imports=True)
        if not sem_err and target_ea != idaapi.BADADDR:
            target_name = idc.get_name(target_ea) or sem_meta.get("semantic_target") or pattern
            mod_name = sem_meta.get("semantic_module") or "unknown"
            matched_apis.append({
                "ea": target_ea, "name": target_name, "module": mod_name,
                "score": sem_meta.get("semantic_score", 0),
            })

    if not matched_apis:
        return make_error(MCPError.NO_RESULTS, f"API {pattern} not found")

    matched_apis.sort(key=lambda r: (r.get("score", 0), r["ea"]), reverse=True)

    usage_rows = []
    for api_row in matched_apis:
        ea = api_row["ea"]
        name = api_row["name"]
        mod_name = api_row["module"]
        xrefs = [xr for xr in idautils.XrefsTo(ea, 0) if xr.iscode]
        call_total = len(xrefs)
        for xr in xrefs:
            func = idaapi.get_func(xr.frm)
            fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
            line = f"{hex(xr.frm)}  {fn_name}  -> {name} ({mod_name})  calls={call_total}"
            if include_context:
                disasm_line = safe_generate_disasm_line(xr.frm)
                line += f"  {clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else '')}"
            usage_rows.append({
                "api": name, "module": mod_name, "api_ea": ea,
                "address_ea": xr.frm, "address": hex(xr.frm),
                "function": fn_name, "score": call_total, "line": line,
            })

    page, total, is_truncated = paginate_records(
        usage_rows, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )
    api_summary = sorted(
        [{"api": r["name"], "module": r["module"], "address": hex(r["ea"]), "xref_count": xref_count_limited(r["ea"])} for r in matched_apis],
        key=lambda x: x["xref_count"], reverse=True,
    )

    result = build_response(
        [r["line"] for r in page], offset, limit, total, is_truncated,
        api=api_summary[0]["api"], api_addr=api_summary[0]["address"]
    )
    if include_items:
        result["items"] = [
            {"address": r["address"], "function": r["function"], "api": r["api"], "module": r["module"], "api_addr": hex(r["api_ea"]), "api_xref_count": r["score"]}
            for r in page
        ]
    if include_breakdown:
        result["matched_apis"] = api_summary
        result["total_calls"] = total
    return result


# ---------------------------------------------------------------------------
# Symbol demangle — expose idc.demangle_name as a standalone action
# ---------------------------------------------------------------------------

def search_demangle(pattern, limit=50, offset=0):
    """Demangle one or more C++ symbol names (comma or newline separated)."""
    raw = (pattern or "").strip()
    if not raw:
        return make_error(MCPError.INVALID_ARGS, "pattern required: mangled name(s) to demangle")

    names = [n.strip() for n in re.split(r"[,\n]", raw) if n.strip()]
    names = names[offset:offset + limit] if offset else names[:limit]

    try:
        typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
    except Exception:
        typeinf = 0
    try:
        typeinf_long = idc.get_inf_attr(idc.INF_LONG_DN)
    except Exception:
        typeinf_long = 0
    rows = []
    for mangled in names:
        short = idc.demangle_name(mangled, typeinf)
        long_ = idc.demangle_name(mangled, typeinf_long)
        rows.append({
            "mangled": mangled,
            "short": short or mangled,
            "long": long_ or short or mangled,
            "is_mangled": short is not None,
        })

    lines = [f"{r['mangled']}  ->  {r['short']}" for r in rows]
    return {
        "ok": True,
        "action": "demangle",
        "results": "\n".join(lines),
        "count": len(rows),
        "items": rows,
        "note": "short uses INF_SHORT_DN, long uses INF_LONG_DN. Unmangled names pass through as-is.",
    }


# ---------------------------------------------------------------------------
# symbol — find_symbol_by_name (exact match with fallback to fuzzy)
# ---------------------------------------------------------------------------

def search_symbol(pattern, include_alternatives=True, offset=0, limit=20):
    """Resolve a symbol by name. Exact first, then substring/pattern fallback."""
    raw = (pattern or "").strip()
    if not raw:
        return make_error(MCPError.INVALID_ARGS, "pattern required: symbol name or address")

    # --- Fast path 1: address literal ---
    if looks_like_address(raw):
        ea, err = validate_addr(raw)
        if not err and ea != idaapi.BADADDR:
            name = idc.get_name(ea) or ""
            func = idaapi.get_func(ea)
            seg = idaapi.getseg(ea)
            typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
            demangled = idc.demangle_name(name, typeinf) or name
            return {
                "ok": True,
                "action": "symbol",
                "match": "address",
                "addr": hex(ea),
                "name": name,
                "demangled": demangled,
                "is_function": func is not None,
                "type": "function" if func else ("data" if idc.is_data(idc.get_full_flags(ea)) else "code" if idc.is_code(idc.get_full_flags(ea)) else "unknown"),
                "segment": seg.getName() if seg else "",
                "xrefs_to": xref_count_limited(ea, 512),
                "alternatives": [],
            }

    # --- Fast path 2: exact name ---
    ea = idc.get_name_ea_simple(raw)
    if ea != idaapi.BADADDR:
        func = idaapi.get_func(ea)
        seg = idaapi.getseg(ea)
        typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
        demangled = idc.demangle_name(raw, typeinf) or raw
        return {
            "ok": True,
            "action": "symbol",
            "match": "exact_name",
            "addr": hex(ea),
            "name": raw,
            "demangled": demangled,
            "is_function": func is not None,
            "type": "function" if func else ("data" if idc.is_data(idc.get_full_flags(ea)) else "code" if idc.is_code(idc.get_full_flags(ea)) else "unknown"),
            "segment": seg.getName() if seg else "",
            "xrefs_to": xref_count_limited(ea, 512),
            "alternatives": _alternatives_for_name(raw, exclude_ea=ea, limit=5) if include_alternatives else [],
        }

    # --- Slow path: substring + semantic ---
    matcher = compile_smart_pattern(raw, case_sensitive=False)
    candidates = []
    for cand_ea, cand_name in idautils.Names():
        if not cand_name or not matcher(cand_name):
            continue
        is_func = bool(idaapi.get_func(cand_ea))
        score = SCORE_SUBSTRING if raw.lower() in cand_name.lower() else 0.0
        candidates.append({
            "addr": hex(cand_ea),
            "name": cand_name,
            "type": "function" if is_func else "symbol",
            "xrefs_to": xref_count_limited(cand_ea, 256),
            "exact": cand_name.lower() == raw.lower(),
            "_score": score,
        })

    if not candidates:
        return make_error(MCPError.NO_RESULTS, f"No symbol matching '{raw}' found")

    candidates.sort(key=lambda c: (c["_score"], c["xrefs_to"]), reverse=True)
    best = candidates[0]
    typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
    best_demangled = idc.demangle_name(best["name"], typeinf) or best["name"]
    page, total, truncated = paginate_records(candidates, offset, limit, sort_key=None)
    for p in page:
        p.pop("_score", None)
    return {
        "ok": True,
        "action": "symbol",
        "match": "fuzzy" if not best.get("exact") else "exact_case_insensitive",
        "query": raw,
        "addr": best["addr"],
        "name": best["name"],
        "demangled": best_demangled,
        "type": best["type"],
        "xrefs_to": best["xrefs_to"],
        "total_candidates": total,
        "truncated": truncated,
        "alternatives": page[1:] if include_alternatives else [],
    }


def _alternatives_for_name(query, exclude_ea=None, limit=5):
    """Return substring-similar names (excluding exact match at exclude_ea)."""
    matcher = compile_smart_pattern(query, case_sensitive=False)
    alts = []
    for cand_ea, cand_name in idautils.Names():
        if not cand_name or not matcher(cand_name):
            continue
        if exclude_ea is not None and cand_ea == exclude_ea:
            continue
        alts.append({"addr": hex(cand_ea), "name": cand_name,
                     "type": "function" if idaapi.get_func(cand_ea) else "symbol"})
        if len(alts) >= limit:
            break
    return alts


# ---------------------------------------------------------------------------
# symbol_info — rich symbol inspector
# ---------------------------------------------------------------------------

def search_symbol_info(pattern, include_xrefs=False):
    """Return detailed info for a single symbol: type, size, xrefs, segment, flags, demangled, prototype."""
    raw = (pattern or "").strip()
    if not raw:
        return make_error(MCPError.INVALID_ARGS, "pattern required: symbol name or address")

    # Resolve to address — try name first, then address literal
    ea = idc.get_name_ea_simple(raw)
    if ea == idaapi.BADADDR:
        # Fallback: try parsing as address literal
        try:
            parsed = int(raw, 0)
            if parsed != idaapi.BADADDR:
                ea = parsed
                name = idc.get_name(ea) or raw
            else:
                return make_error(MCPError.NO_RESULTS, f"Symbol '{raw}' not found")
        except (ValueError, TypeError):
            return make_error(MCPError.NO_RESULTS, f"Symbol '{raw}' not found")
    else:
        name = raw or idc.get_name(ea)

    containing_func = idaapi.get_func(ea)
    seg = idaapi.getseg(ea)
    flags = idc.get_full_flags(ea)
    typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idc.demangle_name(name, typeinf) if name else ""

    info = {
        "ok": True,
        "action": "symbol_info",
        "addr": hex(ea),
        "name": name,
        "demangled": demangled or name,
        "segment": seg.getName() if seg else "",
        "segment_perms": _perm_str(seg) if seg else "",
        "is_function": containing_func is not None,
    }

    if containing_func:
        info["function"] = {
            "start": hex(containing_func.start_ea),
            "end": hex(containing_func.end_ea),
            "size": containing_func.end_ea - containing_func.start_ea,
            "flags": _func_flags(containing_func),
        }
        try:
            proto = idc.get_type(containing_func.start_ea)
            if proto:
                info["function"]["prototype"] = proto
        except Exception:
            pass
    elif idc.is_data(flags):
        info["data"] = {
            "size": idc.get_item_size(ea),
            "flags": _data_flags(flags),
        }
    elif idc.is_code(flags):
        info["code"] = {
            "size": idc.get_item_size(ea),
        }

    info["xrefs_to_count"] = xref_count_limited(ea, 1024)
    info["xrefs_from_count"] = _count_xrefs_from_limited(ea, 1024)

    if include_xrefs:
        xrefs_to = []
        for xr in idautils.XrefsTo(ea, 0):
            src_func = idaapi.get_func(xr.frm)
            xrefs_to.append({
                "from": hex(xr.frm),
                "type": "code" if xr.iscode else "data",
                "function": ida_funcs.get_func_name(src_func.start_ea) if src_func else "",
            })
            if len(xrefs_to) >= 64:
                break
        info["xrefs_to_samples"] = xrefs_to

    return info


def _count_xrefs_from_limited(ea, max_count):
    """Count xrefs FROM ea, up to max_count. For code addresses, walk the function."""
    count = 0
    flags_src = idc.get_full_flags(ea)
    if idc.is_code(flags_src):
        end = idc.find_func_end(ea)
        if end == idaapi.BADADDR:
            end = idc.next_head(ea, ea + 256)
        cur = ea
        while cur < end and cur != idaapi.BADADDR:
            for _ in idautils.XrefsFrom(cur, 0):
                count += 1
                if count >= max_count:
                    return count
            cur = idc.next_head(cur, end)
            if cur == idaapi.BADADDR:
                break
    else:
        for _ in idautils.XrefsFrom(ea, 0):
            count += 1
            if count >= max_count:
                break
    return count


def _perm_str(seg):
    perms = []
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms.append("R")
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms.append("W")
    if seg.perm & idaapi.SEGPERM_READ:
        perms.append("X")
    return "".join(perms)


def _func_flags(func):
    out = []
    if func.flags & idaapi.FUNC_NORET:
        out.append("noreturn")
    if func.flags & idaapi.FUNC_LIB:
        out.append("library")
    if func.flags & idaapi.FUNC_THUNK:
        out.append("thunk")
    if func.flags & idaapi.FUNC_STATIC:
        out.append("static")
    if func.flags & idaapi.FUNC_FRAME:
        out.append("frame")
    return out


def _data_flags(flags):
    out = []
    if idc.is_byte(flags):
        out.append("byte")
    elif idc.is_word(flags):
        out.append("word")
    elif idc.is_dword(flags):
        out.append("dword")
    elif idc.is_qword(flags):
        out.append("qword")
    elif idc.is_strlit(flags):
        out.append("string")
    elif idc.is_struct(flags):
        out.append("struct")
    elif idc.is_align(flags):
        out.append("align")
    if idc.is_comm(flags):
        out.append("has_comment")
    return out if out else ["unknown"]


# ---------------------------------------------------------------------------
# xrefs_to_string — find all functions referencing a string literal
# ---------------------------------------------------------------------------

def search_xrefs_to_string(pattern, include_context=False, offset=0, limit=100, timeout_ms=0):
    """Find all functions referencing a string literal (by value or address)."""
    raw = (pattern or "").strip()
    if not raw:
        return make_error(MCPError.INVALID_ARGS, "pattern required: string value or address to find xrefs for")

    timer = SearchTimeout(timeout_ms)
    timed_out = False

    # Try address literal first (direct xref lookup on a known string address)
    target_eas = []
    if looks_like_address(raw):
        ea, err = validate_addr(raw)
        if not err and ea != idaapi.BADADDR:
            target_eas = [ea]

    # If not an address, search string cache for matches
    if not target_eas:
        matcher = compile_smart_pattern(raw, case_sensitive=False)
        for srec in get_cached_strings():
            s = srec.get("string") or ""
            if matcher(s):
                target_eas.append(srec["ea"])

    if not target_eas:
        return make_error(MCPError.NO_RESULTS, f"No string matching '{raw}' found")

    merged = {}  # string_ea -> {string, value, xrefs: [{addr, function}]}
    for te_a in target_eas:
        try:
            timer.check()
        except TimeoutError:
            timed_out = True
            break
        s_value = idc.get_strlit_contents(te_a)
        if s_value:
            try:
                s_value = s_value.decode("utf-8", errors="replace")
            except Exception:
                s_value = str(s_value)
        else:
            s_value = ""
        refs = []
        ref_funcs = set()
        for xr in idautils.XrefsTo(te_a, 0):
            if not xr.iscode:
                continue
            src_func = idaapi.get_func(xr.frm)
            fn_name = ida_funcs.get_func_name(src_func.start_ea) if src_func else ""
            ref_addr = hex(src_func.start_ea) if src_func else ""
            if ref_addr not in ref_funcs:
                ref_funcs.add(ref_addr)
                entry = {"addr": ref_addr, "call_site": hex(xr.frm), "function": fn_name}
                if include_context:
                    disasm_line = safe_generate_disasm_line(xr.frm)
                    entry["context"] = clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else "", 160)
                refs.append(entry)
        merged[te_a] = {"string_ea": hex(te_a), "value": clip_text(s_value, 200), "xref_count": len(refs), "xrefs": refs}

    if not merged:
        return {"ok": True, "query": raw, "results": "", "count": 0, "items": [],
                "note": "String(s) found but no code xrefs to them."}

    rows = sorted(merged.values(), key=lambda r: r["xref_count"], reverse=True)
    page, total, truncated = paginate_records(rows, offset, limit)

    lines = [f"{r['string_ea']}  xrefs={r['xref_count']}  {r['value']}" for r in page]
    return {
        "ok": True,
        "action": "xrefs_to_string",
        "query": raw,
        "results": "\n".join(lines),
        "count": total,
        "total": total,
        "truncated": truncated or timed_out,
        "items": page,
        "note": "Functions referencing each matching string. Sorted by xref count desc.",
        **({"note": "Functions referencing each matching string. Sorted by xref count desc. TIMED OUT — results may be partial."} if timed_out else {}),
    }
