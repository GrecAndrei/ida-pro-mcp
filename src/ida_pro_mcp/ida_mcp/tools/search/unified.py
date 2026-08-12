"""SEARCH.UNIFIED - Smart unified find, callers, callees, and API usage."""

import heapq
import re

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from ... import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

try:
    from ...support.semantic_matching import (
        DEFAULT_RESCORE_TOP_N,
        semantic_score_cheap,
        semantic_scores,
    )
except ImportError:
    from support.semantic_matching import (  # type: ignore[import-not-found]
        DEFAULT_RESCORE_TOP_N,
        semantic_score_cheap,
        semantic_scores,
    )

from .core import (
    _FIND_INSTRUCTION_CAP,
    _FIND_INSTRUCTION_LIMIT_MULTIPLIER,
    CALL_XREF_TYPES,
    SCORE_SUBSTRING,
    SearchTimeout,
    build_response,
    clip_text,
    demangle_safe,
    get_cached_imports,
    get_cached_strings,
    iter_code,
    looks_like_identifier,
    make_item,
    paginate_records,
    resolve_scan_segments,
    resolve_target,
    safe_generate_disasm_line,
    safe_get_strlit_contents,
    xref_count_limited,
)

# kind= filter for find: alias → canonical category.  Each canonical category
# gates one scan section of search_find (names / strings / imports / comments /
# instructions / refs), so ``search(action='find', pattern=..., kind='strings')``
# is a dedicated string-literal search and ``kind='names'`` a symbol-only search.
_FIND_KIND_ALIASES = {
    "names": "names", "name": "names", "symbols": "names", "symbol": "names",
    "strings": "strings", "string": "strings", "str": "strings",
    "literal": "strings", "literals": "strings",
    "imports": "imports", "import": "imports", "api": "imports", "apis": "imports",
    "comments": "comments", "comment": "comments",
    "instructions": "instructions", "instruction": "instructions",
    "insn": "instructions", "insns": "instructions",
    "mnemonic": "instructions", "mnemonics": "instructions",
    "refs": "refs", "ref": "refs", "xref": "refs", "xrefs": "refs",
    "code_ref": "refs", "data_ref": "refs", "code_refs": "refs", "data_refs": "refs",
}


def normalize_find_kind(kind):
    """Map a user-supplied kind to (wanted, note).

    ``wanted`` is None (all categories) or a frozenset of the canonical
    categories to restrict to.  Unrecognized kinds degrade to all categories
    with a note instead of erroring — the tool is meant to be hard to misuse.
    """
    if kind is None:
        return None, None
    s = str(kind).strip().lower()
    if s in ("", "all", "auto", "*"):
        return None, None
    got = _FIND_KIND_ALIASES.get(s)
    if got is None:
        return None, f"Unrecognized kind {kind!r}; searched all categories."
    return frozenset({got}), None


def search_find(pattern, case_sensitive, range_start, range_end, include_context, include_items, include_breakdown, offset, limit, timeout_ms=0, kind=None):
    """Smart unified search: names (incl. demangled), strings, imports, comments, xrefs, instructions.

    ``kind`` restricts the search to one category (e.g. ``kind='strings'`` for
    a dedicated string-literal search, ``kind='names'`` for symbol-only).
    Identifier-like queries skip the expensive instruction scan when enough
    high-quality symbol/string/import hits already fill the page.
    """
    wanted, kind_note = normalize_find_kind(kind)
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    ranked_heap = []
    heap_cap = max(_FIND_INSTRUCTION_CAP, limit * _FIND_INSTRUCTION_LIMIT_MULTIPLIER)
    heap_seq = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False
    name_hits = 0

    def add_find(kind, ea, line, score, name="", sem_text=None, bonus=0.0, cap=None):
        nonlocal name_hits, heap_seq
        heap_seq += 1
        key = (float(score), int(ea))
        record = {
            "type": kind,
            "address": hex(ea),
            "address_ea": ea,
            "score": float(score),
            "line": line,
            "name": name or "",
            "_sem": sem_text or line or name or "",
            "_bonus": float(bonus or 0.0),
            "_cap": cap,
        }
        if kind in ("names", "imports", "strings"):
            name_hits += 1
        # The monotonic heap_seq makes (key, seq, record) tuples unique even
        # when two hits share the same (score, ea), so heapq never falls
        # through to comparing the dict records (TypeError on duplicates).
        if len(ranked_heap) < heap_cap:
            heapq.heappush(ranked_heap, (key, heap_seq, record))
        elif key > ranked_heap[0][0]:
            heapq.heapreplace(ranked_heap, (key, heap_seq, record))

    # 1. Xrefs for address patterns
    if (not wanted or "refs" in wanted) and looks_like_address(pattern):
        ea, addr_err = validate_addr(pattern)
        if addr_err:
            try:
                ea = int(pattern, 16)
            except Exception:
                ea = idaapi.BADADDR
        if ea != idaapi.BADADDR:
            for xref in idautils.XrefsTo(ea, 0):
                func = _compat.get_func_start(xref.frm)
                fn_name = ida_funcs.get_func_name(func) if func is not None else ""
                dem = demangle_safe(fn_name) if fn_name else ""
                display = dem if dem and dem != fn_name else fn_name
                sem_name = semantic_score_cheap(pattern, fn_name, substring_bonus=SCORE_SUBSTRING) if fn_name else 0.0
                kind = "code_ref" if xref.iscode else "data_ref"
                add_find(kind, xref.frm, f"{hex(xref.frm)}  {display}", max(1.0, sem_name), display)

    seen_eas = set()

    # 2. Names (+ demangled)
    if not wanted or "names" in wanted:
        for ea, name in idautils.Names():
            if ea in seen_eas or not name:
                continue
            dem = demangle_safe(name)
            hit = matcher(name) or (dem and dem != name and matcher(dem))
            if not hit:
                continue
            kind = "func" if _compat.get_func_start(ea) is not None else "data"
            xref_count = xref_count_limited(ea)
            display = dem if dem and dem != name else name
            score = max(
                semantic_score_cheap(pattern, name, substring_bonus=SCORE_SUBSTRING),
                semantic_score_cheap(pattern, dem, substring_bonus=SCORE_SUBSTRING) if dem else 0.0,
            )
            if dem and dem != name:
                line = f"{hex(ea)}  {kind}  {name}  ({clip_text(dem, 80)})  xrefs={xref_count}"
            else:
                line = f"{hex(ea)}  {kind}  {name}  xrefs={xref_count}"
            add_find("names", ea, line, score, display, sem_text=display)
            seen_eas.add(ea)

    # 3. Strings (cached)
    if not wanted or "strings" in wanted:
        for srec in get_cached_strings():
            ea = srec["ea"]
            if ea in seen_eas:
                continue
            s = srec["string"]
            if matcher(s):
                xref_count = xref_count_limited(ea)
                score = semantic_score_cheap(pattern, s, substring_bonus=SCORE_SUBSTRING)
                add_find("strings", ea, f"{hex(ea)}  xrefs={xref_count}  {clip_text(s, 180)}", score, clip_text(s, 80), sem_text=s)
                seen_eas.add(ea)

    # 4. Imports (cached)
    if not wanted or "imports" in wanted:
        for irec in get_cached_imports():
            ea = irec["ea"]
            if ea in seen_eas:
                continue
            name = irec["name"]
            mod_name = irec["module"]
            if name and matcher(name):
                xref_count = xref_count_limited(ea)
                score = semantic_score_cheap(pattern, name, substring_bonus=SCORE_SUBSTRING)
                add_find("imports", ea, f"{hex(ea)}  {mod_name}!{name}  xrefs={xref_count}", score, name, sem_text=name, bonus=15.0)
                seen_eas.add(ea)

    # 5. Comments (high signal for agents; bounded)
    comment_hits = 0
    comment_cap = max(200, limit * 4)
    if not wanted or "comments" in wanted:
        for seg_ea in idautils.Segments():
            if comment_hits >= comment_cap or timed_out:
                break
            seg_end = idc.get_segm_end(seg_ea)
            for head in idautils.Heads(seg_ea, seg_end):
                if comment_hits >= comment_cap:
                    break
                try:
                    timer.check()
                except TimeoutError:
                    timed_out = True
                    break
                c0 = idc.get_cmt(head, 0) or ""
                c1 = idc.get_cmt(head, 1) or ""
                blob = f"{c0} {c1}".strip()
                if not blob or not matcher(blob):
                    continue
                score = semantic_score_cheap(pattern, blob, substring_bonus=SCORE_SUBSTRING)
                fn = _compat.get_func_start(head)
                fn_name = ida_funcs.get_func_name(fn) if fn is not None else ""
                line = f"{hex(head)}  comment  {fn_name}  {clip_text(blob, 160)}"
                add_find("comments", head, line, score, fn_name, sem_text=blob)
                comment_hits += 1

    # 6. Instructions (bounded) — skip for identifier-like queries with enough symbol hits
    insns_wanted = wanted is None or "instructions" in wanted
    skip_insns = (not insns_wanted) or (
        looks_like_identifier(pattern) and name_hits >= max(limit, 8)
    )
    instruction_hits = 0
    pattern_lower = pattern.lower() if not case_sensitive else pattern
    find_segs, find_seg_note, find_seg_error = (
        resolve_scan_segments(range_start, range_end, require_exec=True)
        if (insns_wanted and not skip_insns)
        else ([], "", "")
    )
    if insns_wanted and not skip_insns and find_seg_error:
        return make_error(MCPError.NOT_FOUND, find_seg_error)
    if insns_wanted and not skip_insns:
        for seg_start, seg_end in find_segs:
            if instruction_hits >= _FIND_INSTRUCTION_CAP or timed_out:
                break
            for ea in iter_code(seg_start, seg_end, force=bool(find_seg_note)):
                if instruction_hits >= _FIND_INSTRUCTION_CAP:
                    break
                try:
                    timer.check()
                except TimeoutError:
                    timed_out = True
                    break
                mnem = idc.print_insn_mnem(ea)
                if not mnem:
                    continue
                quick_blob = mnem.lower()
                op0 = idc.print_operand(ea, 0)
                if op0:
                    quick_blob += " " + op0.lower()
                op1 = idc.print_operand(ea, 1)
                if op1:
                    quick_blob += " " + op1.lower()
                if not case_sensitive:
                    needle = pattern_lower
                    hay = quick_blob
                else:
                    needle = pattern
                    hay = f"{mnem} {op0 or ''} {op1 or ''}"
                if needle not in hay and not matcher(hay):
                    continue
                line = safe_generate_disasm_line(ea)
                if not line:
                    continue
                line_clean = ida_lines.tag_remove(line) or ""
                semantic_blob = f"{mnem.lower()} {line_clean}"
                sem = semantic_score_cheap(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING)
                if matcher(semantic_blob) or sem > 0.0:
                    add_find(
                        "instructions",
                        ea,
                        f"{hex(ea)}  {mnem}  {clip_text(line_clean, 180)}",
                        sem,
                        sem_text=semantic_blob,
                        cap=160.0,
                    )
                    instruction_hits += 1

    ranked = [item[2] for item in ranked_heap]
    _rescore_find_ranked(ranked, pattern)
    page, total, is_truncated = paginate_records(
        ranked, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )

    by_type = {
        "names": [], "strings": [], "imports": [], "instructions": [],
        "code_refs": [], "data_refs": [], "comments": [],
    }
    type_to_key = {
        "names": "names", "strings": "strings", "imports": "imports",
        "instructions": "instructions", "code_ref": "code_refs", "data_ref": "data_refs",
        "comments": "comments",
    }
    for row in page:
        key = type_to_key.get(row["type"])
        if key:
            by_type[key].append(row["line"])

    result = build_response(
        [r["line"] for r in page], offset, limit, total, is_truncated, query=pattern, action="find",
    )
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    if wanted:
        result["kind"] = next(iter(wanted))
    if kind_note:
        result["kind_note"] = kind_note
    if skip_insns and insns_wanted:
        result["insn_scan"] = "skipped"
        result["note"] = (
            "Instruction scan skipped (identifier-like query with enough symbol hits). "
            "Use action='instruction' or action='text' to force disassembly search."
        )
    elif find_seg_note:
        result["note"] = find_seg_note
    # Always attach structured items — agents need addr/name without parsing text
    result["items"] = [
        make_item(
            addr=r["address_ea"],
            name=r.get("name") or "",
            type=r["type"],
            score=r["score"],
            snippet=r["line"],
        )
        for r in page
    ]
    if not include_items:
        # keep items; flag that compact text is primary
        result["items_always"] = True
    if include_breakdown:
        result["type_totals"] = {
            "names": sum(1 for r in ranked if r["type"] == "names"),
            "strings": sum(1 for r in ranked if r["type"] == "strings"),
            "imports": sum(1 for r in ranked if r["type"] == "imports"),
            "instructions": sum(1 for r in ranked if r["type"] == "instructions"),
            "comments": sum(1 for r in ranked if r["type"] == "comments"),
            "code_refs": sum(1 for r in ranked if r["type"] == "code_ref"),
            "data_refs": sum(1 for r in ranked if r["type"] == "data_ref"),
        }
        for key in by_type:
            result[key] = "\n".join(by_type[key])
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
        other_func = _compat.get_func_start(other_ea)
        if other_func is None:
            continue
        key = other_func
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
            target_addr=hex(func),
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
        target=idc.get_name(target_ea) or hex(target_ea), target_addr=hex(func)
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
        return make_error(
            MCPError.NOT_FOUND,
            str(error),
            hint="Pass a hex address or exact function name. Try search(action='find') first.",
        )

    func = _compat.get_func_start(target_ea)
    if func is None:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

    def _iter_caller_edges(target_func):
        for xref in idautils.XrefsTo(target_func, 0):
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
        return make_error(
            MCPError.NOT_FOUND,
            str(error),
            hint="Pass a hex address or exact function name. Try search(action='find') first.",
        )

    func = _compat.get_func_start(target_ea)
    if func is None:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

    def _iter_callee_edges(target_func):
        for item in idautils.FuncItems(target_func):
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

    api_rows = []
    for irec in get_cached_imports():
        name = irec["name"]
        if name and matcher(name):
            api_rows.append({"ea": irec["ea"], "name": name, "module": irec["module"]})
    if api_rows:
        scores = semantic_scores(
            pattern, [row["name"] for row in api_rows], top_n=48
        )
        matched_apis = [
            {"ea": row["ea"], "name": row["name"], "module": row["module"], "score": score}
            for row, score in zip(api_rows, scores, strict=False)
        ]

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
            func = _compat.get_func_start(xr.frm)
            fn_name = ida_funcs.get_func_name(func) if func is not None else "unknown"
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
        api=api_summary[0]["api"], api_addr=api_summary[0]["address"], action="api",
    )
    result["items"] = [
        make_item(
            addr=r["address_ea"],
            name=r["function"],
            type="call_site",
            score=r["score"],
            api=r["api"],
            module=r["module"],
            api_addr=hex(r["api_ea"]),
            snippet=r["line"],
        )
        for r in page
    ]
    if include_breakdown:
        result["matched_apis"] = api_summary
        result["total_calls"] = total
    return result


def _rescore_find_ranked(ranked, pattern):
    """Batch-embed the top-ranked pool, then compose per-kind bonuses/caps.

    Phase 1 (the loops) scores every match deterministically; this phase
    re-embeds a bounded slice of the pool in one batched call.  For
    phrase-like queries the cheap lexical pass over instruction text is
    weaker, so a wider pool (closer to ``DEFAULT_RESCORE_TOP_N``) is
    re-embedded to give the cross-attention model real candidates to rank;
    identifier queries keep the tighter 24-candidate budget.
    """
    if not ranked:
        return
    phrase_like = bool(
        " " in (pattern or "").strip() or len((pattern or "").strip()) >= 24
    )
    if phrase_like:
        rescore_top = min(DEFAULT_RESCORE_TOP_N, len(ranked))
    else:
        rescore_top = min(24, len(ranked))
    pool = [r.get("_sem") or r.get("line") or "" for r in ranked]
    scores = semantic_scores(
        pattern, pool, top_n=max(8, rescore_top), substring_bonus=SCORE_SUBSTRING
    )
    for record, score in zip(ranked, scores, strict=False):
        final = float(score) + float(record.get("_bonus") or 0.0)
        cap = record.get("_cap")
        if cap is not None:
            final = min(final, float(cap))
        record["score"] = final
        record.pop("_sem", None)
        record.pop("_bonus", None)
        record.pop("_cap", None)


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
            func = _compat.get_func_start(ea)
            seg = _compat.get_segment(ea)
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
                "type": "function" if func is not None else ("data" if idc.is_data(idc.get_full_flags(ea)) else "code" if idc.is_code(idc.get_full_flags(ea)) else "unknown"),
                "segment": _compat.get_segment_name(ea) if seg else "",
                "xrefs_to": xref_count_limited(ea, 512),
                "alternatives": [],
            }

    # --- Fast path 2: exact name ---
    ea = idc.get_name_ea_simple(raw)
    if ea != idaapi.BADADDR:
        func = _compat.get_func_start(ea)
        seg = _compat.get_segment(ea)
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
            "type": "function" if func is not None else ("data" if idc.is_data(idc.get_full_flags(ea)) else "code" if idc.is_code(idc.get_full_flags(ea)) else "unknown"),
            "segment": _compat.get_segment_name(ea) if seg else "",
            "xrefs_to": xref_count_limited(ea, 512),
            "alternatives": _alternatives_for_name(raw, exclude_ea=ea, limit=5) if include_alternatives else [],
        }

    # --- Slow path: substring + demangled + pattern ---
    matcher = compile_smart_pattern(raw, case_sensitive=False)
    candidates = []
    raw_l = raw.lower()
    for cand_ea, cand_name in idautils.Names():
        if not cand_name:
            continue
        dem = demangle_safe(cand_name)
        if not matcher(cand_name) and not (dem and dem != cand_name and matcher(dem)):
            continue
        is_func = _compat.get_func_start(cand_ea) is not None
        score = 0.0
        if cand_name.lower() == raw_l or (dem and dem.lower() == raw_l):
            score = 200.0
        elif raw_l in cand_name.lower() or (dem and raw_l in dem.lower()):
            score = SCORE_SUBSTRING + 20.0
        else:
            score = SCORE_SUBSTRING
        candidates.append({
            "addr": hex(cand_ea),
            "name": cand_name,
            "demangled": dem if dem != cand_name else "",
            "type": "function" if is_func else "symbol",
            "xrefs_to": xref_count_limited(cand_ea, 256),
            "exact": cand_name.lower() == raw_l or (dem and dem.lower() == raw_l),
            "_score": score,
        })

    if not candidates:
        return make_error(
            MCPError.NO_RESULTS,
            f"No symbol matching '{raw}' found",
            "Try search(action='find', pattern=...) or demangle first.",
        )

    candidates.sort(key=lambda c: (c["_score"], c["xrefs_to"]), reverse=True)
    best = candidates[0]
    best_demangled = best.get("demangled") or demangle_safe(best["name"]) or best["name"]
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
        "items": [
            make_item(
                addr=c["addr"],
                name=c["name"],
                type=c["type"],
                demangled=c.get("demangled") or None,
                xrefs_to=c.get("xrefs_to"),
            )
            for c in page
        ],
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
                     "type": "function" if _compat.get_func_start(cand_ea) is not None else "symbol"})
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

    containing_func = _compat.get_func_info(ea)
    seg = _compat.get_segment(ea)
    flags = idc.get_full_flags(ea)
    typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idc.demangle_name(name, typeinf) if name else ""

    info = {
        "ok": True,
        "action": "symbol_info",
        "addr": hex(ea),
        "name": name,
        "demangled": demangled or name,
        "segment": _compat.get_segment_name(ea) if seg else "",
        "segment_perms": _perm_str(ea) if seg else "",
        "is_function": containing_func is not None,
    }

    if containing_func:
        info["function"] = {
            "start": hex(containing_func.start_ea),
            "end": hex(containing_func.end_ea),
            "size": containing_func.end_ea - containing_func.start_ea,
            "flags": _func_flags(_compat.get_func_flags(ea)),
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
            "flags": _data_flags(flags, ea),
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
            src_func = _compat.get_func_start(xr.frm)
            xrefs_to.append({
                "from": hex(xr.frm),
                "type": "code" if xr.iscode else "data",
                "function": ida_funcs.get_func_name(src_func) if src_func is not None else "",
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


def _perm_str(ea):
    perm = _compat.get_segment_perm(ea)
    if perm is None:
        return ""
    perms = []
    if perm & idaapi.SEGPERM_READ:
        perms.append("R")
    if perm & idaapi.SEGPERM_WRITE:
        perms.append("W")
    if perm & idaapi.SEGPERM_EXEC:
        perms.append("X")
    return "".join(perms)


def _func_flags(func_flags):
    out = []
    if not func_flags:
        return out
    if func_flags & idaapi.FUNC_NORET:
        out.append("noreturn")
    if func_flags & idaapi.FUNC_LIB:
        out.append("library")
    if func_flags & idaapi.FUNC_THUNK:
        out.append("thunk")
    _static_flag = getattr(idaapi, "FUNC_STATIC", getattr(idaapi, "FUNC_STATICDEF", 0))
    if _static_flag and (func_flags & _static_flag):
        out.append("static")
    if func_flags & idaapi.FUNC_FRAME:
        out.append("frame")
    return out


def _data_flags(flags, ea=None):
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
    # is_comm() tests the COMMON (uninitialized) storage flag, not comments;
    # a real comment check needs the ea. ida_bytes.has_cmt handles both
    # regular (repeatable=0) and repeatable (repeatable=1) comments.
    if ea is not None:
        try:
            if ida_bytes.has_cmt(ea, 0) or ida_bytes.has_cmt(ea, 1):
                out.append("has_comment")
        except Exception:
            pass
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
        # Use the safe wrapper: it reads the item's own string type and falls
        # back to the plain call, so wide/UTF-16 literals are not mis-decoded
        # as UTF-8 (the plain call defaults to STRTYPE_C and returns raw bytes).
        s_value = safe_get_strlit_contents(te_a) or ""
        refs = []
        ref_funcs = set()
        for xr in idautils.XrefsTo(te_a, 0):
            if not xr.iscode:
                continue
            src_func = _compat.get_func_start(xr.frm)
            fn_name = ida_funcs.get_func_name(src_func) if src_func is not None else ""
            ref_addr = hex(src_func) if src_func is not None else ""
            if ref_addr not in ref_funcs:
                ref_funcs.add(ref_addr)
                entry = {"addr": ref_addr, "call_site": hex(xr.frm), "function": fn_name}
                if include_context:
                    disasm_line = safe_generate_disasm_line(xr.frm)
                    entry["context"] = clip_text(ida_lines.tag_remove(disasm_line) if disasm_line else "", 160)
                refs.append(entry)
        merged[te_a] = {"string_ea": hex(te_a), "value": clip_text(s_value, 200), "xref_count": len(refs), "xrefs": refs}

    # merged is keyed by every element of target_eas (guaranteed non-empty
    # above), so it is always populated by the time we reach this point.
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
