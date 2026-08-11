"""SEARCH.REFS - Data/code references, regex, and function signature filtering."""

import re as re_module

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    CALL_XREF_TYPES,
    SearchTimeout,
    _match_size_rule,
    build_response,
    iter_code,
    resolve_scan_segments,
    resolve_target,
    safe_generate_disasm_line,
)


def search_data_ref(pattern, include_context, offset, limit, semantic_min_score, include_alternatives):
    """Find data references to target."""
    target_ea, error, sem_meta = resolve_target(
        pattern, require_function=False, include_imports=True,
        semantic_min_score=semantic_min_score, include_alternatives=include_alternatives
    )
    if error:
        return make_error(MCPError.INVALID_ARGS, error)

    results = []
    truncated = False
    matches_seen = 0

    for xref in idautils.XrefsTo(target_ea, 0):
        if truncated:
            break
        if not xref.iscode:
            matches_seen += 1
            if matches_seen > offset:
                line = f"{hex(xref.frm)} -> {hex(xref.to)}  data"
                if include_context:
                    from_name = idc.get_name(xref.frm)
                    if from_name:
                        line += f"  {from_name}"
                results.append(line)
                if len(results) >= limit:
                    truncated = True
                    break

    return build_response(results, offset, limit, matches_seen, truncated, target=pattern, target_addr=hex(target_ea), **sem_meta)


def search_code_ref(pattern, include_context, offset, limit, semantic_min_score, include_alternatives):
    """Find code references to target."""
    target_ea, error, sem_meta = resolve_target(
        pattern, require_function=False, include_imports=True,
        semantic_min_score=semantic_min_score, include_alternatives=include_alternatives
    )
    if error:
        return make_error(MCPError.INVALID_ARGS, error)

    results = []
    truncated = False
    matches_seen = 0

    for xref in idautils.XrefsTo(target_ea, 0):
        if truncated:
            break
        if xref.iscode:
            func = idaapi.get_func(xref.frm)
            fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
            matches_seen += 1
            if matches_seen > offset:
                line = f"{hex(xref.frm)} -> {hex(xref.to)}  code  {fn_name}"
                if include_context:
                    disasm_line = safe_generate_disasm_line(xref.frm)
                    line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                results.append(line)
                if len(results) >= limit:
                    truncated = True
                    break

    return build_response(results, offset, limit, matches_seen, truncated, target=pattern, target_addr=hex(target_ea), **sem_meta)


def _is_dangerous_regex(pattern: str) -> bool:
    """Reject regex patterns known to cause catastrophic backtracking (ReDoS)."""
    if len(pattern) > 256:
        return True
    # Nested quantifiers inside groups are the main ReDoS vectors
    if re_module.search(r'\([^)]*[*+{}][^)]*\)[*+{}]', pattern):
        return True
    # Alternation inside quantified groups
    if re_module.search(r'\([^)]*\|[^)]*\)[*+{}?]', pattern):
        return True
    # Deeply nested groups (exponential state explosion)
    if pattern.count('(') > 20:
        return True
    # Excessive backslash escaping that can blow up
    return pattern.count('\\') > 50


def search_regex(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Regex search in disassembly."""
    if _is_dangerous_regex(pattern):
        return make_error(MCPError.INVALID_ARGS, "Regex pattern rejected: too long or contains dangerous nested quantifiers (ReDoS risk)")
    try:
        regex = re_module.compile(pattern, 0 if case_sensitive else re_module.IGNORECASE)
    except re_module.error as e:
        return make_error(MCPError.INVALID_ARGS, f"Invalid regex: {e}")

    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    segs, seg_note, seg_error = resolve_scan_segments(range_start, range_end, require_exec=True)
    if seg_error:
        return make_error(MCPError.NOT_FOUND, seg_error)
    for seg_start, seg_end in segs:
        if timed_out:
            break
        for ea in iter_code(seg_start, seg_end, force=bool(seg_note)):
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            line = safe_generate_disasm_line(ea)
            if line:
                line_clean = ida_lines.tag_remove(line) if line else ""
                # Truncate to bound ReDoS search space (disassembly lines rarely exceed 256 chars)
                if len(line_clean) > 512:
                    line_clean = line_clean[:512]
                if regex.search(line_clean):
                    matches_seen += 1
                    if matches_seen > offset:
                        result_line = f"{hex(ea)}  {line_clean}"
                        if include_context:
                            func = idaapi.get_func(ea)
                            if func:
                                result_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                        results.append(result_line)
                        if len(results) >= limit:
                            truncated = True
                            break
            if truncated:
                break

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if seg_note:
        result["note"] = seg_note
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result


def search_func_by_sig(pattern, offset, limit, timeout_ms=0):
    """Filter functions by characteristics.

    Supports structural filters in pattern:
    - size:>N / size:<N / size:N-M  — function size in bytes
    - calls:NAME  — calls a specific function
    - args:N / args:N+  — argument count
    - leaf  — no outgoing calls (leaf functions)
    - no_callers  — no incoming calls (potential entry points / dead code)
    - entry_point  — exported or has no callers
    - no_callees  — alias for leaf
    """
    criteria = pattern.lower()
    filter_matcher = compile_smart_pattern(pattern, case_sensitive=False)
    size_rules = []
    call_pattern = None
    args_rule = None
    # Word-boundary anchoring keeps bare structural keywords (leaf, no_callers,
    # calls:NAME, ...) from firing on ordinary names that merely contain them
    # (e.g. 'calloc', 'leaflet', 'find_leaf_node').
    want_leaf = bool(re_module.search(r"\bleaf\b", criteria)) or bool(re_module.search(r"\bno_callees?\b", criteria))
    want_no_callers = bool(re_module.search(r"\bno_callers?\b", criteria)) or bool(re_module.search(r"\bentry_?points?\b", criteria))

    for m in re_module.finditer(r"size\s*[:=]\s*([<>]?)(\d+)(?:\s*-\s*(\d+))?", criteria):
        op, val1, val2 = m.groups()
        size_rules.append((op or "=", int(val1), int(val2) if val2 else None))
    for m in re_module.finditer(r"(?:larger|greater|bigger)\s+than\s+(\d+)", criteria):
        size_rules.append((">", int(m.group(1)), None))
    for m in re_module.finditer(r"(?:smaller|less)\s+than\s+(\d+)", criteria):
        size_rules.append(("<", int(m.group(1)), None))

    m_calls = re_module.search(r"\b(?:calls?|invoke(?:s|d)?|callee)\b\s*[:=]?\s*([^\s,;]+)", criteria)
    if m_calls:
        call_pattern = m_calls.group(1).strip()

    m_args = re_module.search(r"(?:args?|arguments?|params?)\s*[:=]?\s*(\d+)\s*(\+|or\s+more)?", criteria)
    if m_args:
        args_rule = (int(m_args.group(1)), bool(m_args.group(2)))

    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    # Determine which filters are active to enforce AND logic
    active_filters = []
    if size_rules:
        active_filters.append("size")
    if call_pattern:
        active_filters.append("calls")
    if args_rule:
        active_filters.append("args")
    if want_leaf:
        active_filters.append("leaf")
    if want_no_callers:
        active_filters.append("no_callers")

    for ea in idautils.Functions():
        if truncated or timed_out:
            break
        try:
            timer.check()
        except TimeoutError:
            timed_out = True
            break
        func = idaapi.get_func(ea)
        if not func:
            continue

        name = ida_funcs.get_func_name(ea)
        size = func.end_ea - func.start_ea
        matched = False
        reason = []

        if not active_filters:
            # Fallback to name search if no structural filters are active
            if filter_matcher(name):
                matched = True
                reason.append("semantic:name")
        else:
            # All active filters must be satisfied (AND logic)
            matched = True
            if "size" in active_filters:
                # All size rules must hold (AND logic); a range bound never
                # silences a comparator on the same rule.
                size_ok = True
                for op, val1, val2 in size_rules:
                    if not _match_size_rule(size, op, val1, val2):
                        size_ok = False
                        break
                    if val2 is not None:
                        reason.append(f"size={size} in [{val1},{val2}]")
                    elif op == ">":
                        reason.append(f"size={size}>{val1}")
                    elif op == "<":
                        reason.append(f"size={size}<{val1}")
                    else:
                        reason.append(f"size={size}")
                if not size_ok:
                    matched = False

            if matched and "calls" in active_filters:
                calls_ok = False
                call_matcher = compile_smart_pattern(call_pattern, case_sensitive=False)
                for xref in idautils.XrefsFrom(ea):
                    if xref.type in CALL_XREF_TYPES:
                        callee_name = idc.get_name(xref.to) or ""
                        if call_matcher(callee_name):
                            calls_ok = True
                            reason.append(f"calls:{callee_name}")
                            break
                if not calls_ok:
                    matched = False

            if matched and "args" in active_filters:
                args_ok = False
                arg_count, plus = args_rule
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, ea):
                    func_data = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(func_data):
                        actual_args = func_data.size()
                        if plus and actual_args >= arg_count:
                            args_ok = True
                            reason.append(f"args={actual_args}>={arg_count}")
                        elif not plus and actual_args == arg_count:
                            args_ok = True
                            reason.append(f"args={actual_args}")
                if not args_ok:
                    matched = False

            if matched and "leaf" in active_filters:
                has_calls = any(xr.type in CALL_XREF_TYPES for xr in idautils.XrefsFrom(ea))
                if not has_calls:
                    reason.append("leaf")
                else:
                    matched = False

            if matched and "no_callers" in active_filters:
                has_callers = any(xr.iscode for xr in idautils.XrefsTo(ea, 0))
                if not has_callers:
                    reason.append("no_callers")
                else:
                    matched = False

        if matched:
            matches_seen += 1
            if matches_seen > offset:
                n_callers = sum(1 for xr in idautils.XrefsTo(ea, 0) if xr.iscode)
                results.append(f"{hex(ea)}  {name}  size={size}  callers={n_callers}  {', '.join(reason)}")
                if len(results) >= limit:
                    truncated = True
                    break

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result
