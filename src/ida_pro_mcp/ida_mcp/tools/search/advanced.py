"""SEARCH.ADVANCED - Vulnerable, constants, decompiled, and structured search."""

import time as _time

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    clip_text, paginate_records, build_response, resolve_target,
    iter_segments, iter_code, _cache_get, _cache_set, _cache_key,
    MAX_LIMIT, derive_vuln_type, get_cached_constant_db,
    _get_db_fingerprint, SearchTimeout, safe_generate_disasm_line,
)


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
        max_functions = max(1, min(int(kwargs.get("max_functions", kwargs.get("sample_max_funcs", 180))), 5000))
    except (ValueError, TypeError):
        max_functions = 180
    sample = bool(kwargs.get("sample", False))

    target_funcs = []
    scope_func = None
    if scope_addr:
        target_ea, err = validate_addr(str(scope_addr))
        if err:
            target_ea = idc.get_name_ea_simple(str(scope_addr))
        scope_func = idaapi.get_func(target_ea) if target_ea != idaapi.BADADDR else None
        if not scope_func:
            return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {scope_addr}")
        target_funcs = [scope_func.start_ea]
    else:
        all_funcs = list(idautils.Functions())
        if sample and len(all_funcs) > max_functions:
            step = max(1, len(all_funcs) // max_functions)
            target_funcs = all_funcs[::step][:max_functions]
        else:
            target_funcs = all_funcs[:max_functions]

    scan_truncated = (not scope_func) and (len(target_funcs) >= max_functions)

    rows = []
    scanned = 0
    timed_out = False
    decompiled = 0
    failures = 0
    failure_samples = []
    started_at = _time.time()

    for func_ea in target_funcs:
        if (_time.time() - started_at) >= (timeout_ms / 1000.0):
            timed_out = True
            break
        scanned += 1

        cache_key = _cache_key("decomp", func_ea)
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
        for line_num, line in enumerate(pseudocode.splitlines(), 1):
            if matcher(line):
                text = clip_text(line.strip(), 220)
                rows.append({
                    "address_ea": func_ea, "address": hex(func_ea),
                    "function": func_name, "line_num": line_num,
                    "line": f"{hex(func_ea)}  {func_name}  L{line_num}: {text}",
                })

    if scanned > 0 and decompiled == 0 and failures > 0:
        return make_error(
            MCPError.DECOMPILER_FAILED,
            "Decompiled search failed to decompile any function",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
            details={"scanned": scanned, "failures": failures, "sample_errors": failure_samples},
        )

    page, total, is_truncated = paginate_records(
        rows, offset, limit, sort_key=lambda r: (r["address_ea"], r["line_num"]), reverse=False
    )
    result = build_response(
        [r["line"] for r in page], offset, limit, total, is_truncated,
        pattern=pattern, scanned_functions=scanned, decompiled_functions=decompiled,
        decompile_failures=failures, scan_limit=max_functions if not scope_func else 1,
        timeout_ms=timeout_ms, timed_out=timed_out,
    )
    if scope_func:
        result["scope"] = hex(scope_func.start_ea)
    if scan_truncated or timed_out:
        result["analysis_truncated"] = True
        result["hint"] = "Increase timeout_ms or scope with addr to search one function." if timed_out else "Increase max_functions or set sample=false for broader coverage."
    if include_items:
        result["items"] = [{"address": r["address"], "function": r["function"], "line_num": r["line_num"]} for r in page]
    return result


def search_structured(constraints, pattern, range_start, range_end, include_context, offset, limit, include_items, timeout_ms=0):
    """Schema-based structured semantic retrieval with caching."""
    if not isinstance(constraints, dict):
        return make_error(MCPError.INVALID_ARGS, "constraints must be a dict")
    if not constraints and not pattern:
        return make_error(MCPError.INVALID_ARGS, "constraints or pattern required")

    try:
        from ..classify import _CATEGORY_APIS, _classify_func
    except ImportError:
        from classify import _CATEGORY_APIS, _classify_func  # type: ignore[import-not-found]
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

        schema = {"behavior_tags": set(), "dangerous_apis": set(), "string_refs": set(), "vuln_class": set()}
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

    def schema_matches(schema, constraints):
        for key, val in constraints.items():
            if key == "behavior_tags":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["behavior_tags"] for v in vals):
                    return False
            elif key == "dangerous_apis":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["dangerous_apis"] for v in vals):
                    return False
            elif key == "vuln_class":
                vals = val if isinstance(val, (list, set, tuple)) else [val]
                if not any(v in schema["vuln_class"] for v in vals):
                    return False
            elif key == "string_refs":
                matcher = compile_smart_pattern(str(val), case_sensitive=False)
                if not any(matcher(s) for s in schema["string_refs"]):
                    return False
            else:
                all_vals = set()
                for v in schema.values():
                    all_vals.update(v)
                if str(val).lower() not in " ".join(all_vals).lower():
                    return False
        return True

    results = []
    schema_hits = {}
    matcher = compile_smart_pattern(pattern, case_sensitive=False) if pattern else None
    timer = SearchTimeout(timeout_ms)
    timed_out = False
    matches_seen = 0

    for func_ea in idautils.Functions():
        try:
            timer.check()
        except TimeoutError:
            timed_out = True
            break
        schema = induce_schema(func_ea)
        if not schema_matches(schema, constraints):
            continue
        matches_seen += 1
        if matches_seen <= offset:
            continue
        fname = idc.get_func_name(func_ea) or f"sub_{func_ea:x}"
        tags = ", ".join(sorted(schema["behavior_tags"]))
        dangerous = ", ".join(sorted(schema["dangerous_apis"]))
        line = f"{hex(func_ea)}  {fname}  tags=[{tags}]"
        if dangerous:
            line += f"  dangerous=[{dangerous}]"
        if pattern and not matcher(line):
            continue
        results.append(line)
        schema_hits[hex(func_ea)] = {
            "name": fname,
            "behavior_tags": sorted(schema["behavior_tags"]),
            "dangerous_apis": sorted(schema["dangerous_apis"]),
            "string_refs": sorted(schema["string_refs"])[:5],
        }
        if len(results) >= limit:
            break

    out = {
        "ok": True, "action": "structured", "constraints": constraints,
        "matches": "\n".join(results), "count": len(results),
        "schema_hits": schema_hits,
        "note": "Structured semantic retrieval pre-filters by induced function schema.",
    }
    if timed_out:
        out["timed_out"] = True
        out["hint"] = "Search timed out. Increase timeout_ms or tighten constraints."
    return out
