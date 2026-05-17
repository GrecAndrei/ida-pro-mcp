"""SEARCH.UNIFIED - Smart unified find, callers, callees, and API usage."""

import heapq

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ..semantic_matching import semantic_score
except ImportError:
    from semantic_matching import semantic_score  # type: ignore[import-not-found]

from .core import (
    clip_text, paginate_records, build_response, resolve_target,
    iter_segments, iter_code, xref_count_limited,
    _FIND_INSTRUCTION_CAP, _FIND_INSTRUCTION_LIMIT_MULTIPLIER,
    SCORE_SUBSTRING, get_cached_imports, get_cached_strings, SearchTimeout,
    CALL_XREF_TYPES, safe_generate_disasm_line,
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
    """Natural-language semantic search across symbols, imports, strings, and code lines."""
    query = (pattern or "").strip()
    if not query:
        return make_error(MCPError.INVALID_ARGS, "pattern or query required")

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

    callers = {}
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if not xref.iscode:
            continue
        caller_func = idaapi.get_func(xref.frm)
        if not caller_func:
            continue
        key = caller_func.start_ea
        if key not in callers:
            callers[key] = {
                "address_ea": key, "address": hex(key),
                "name": ida_funcs.get_func_name(key), "call_sites": [],
            }
        callers[key]["call_sites"].append(xref.frm)

    ranked = []
    for row in callers.values():
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

    callees = {}
    for item in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item, 0):
            if xref.type not in CALL_XREF_TYPES:
                continue
            callee_func = idaapi.get_func(xref.to)
            if not callee_func:
                continue
            key = callee_func.start_ea
            if key not in callees:
                callees[key] = {
                    "address_ea": key, "address": hex(key),
                    "name": ida_funcs.get_func_name(key), "call_sites": [],
                }
            callees[key]["call_sites"].append(item)

    ranked = []
    for row in callees.values():
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
