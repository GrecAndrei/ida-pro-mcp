"""SEARCH.BASIC - Byte, string, immediate, and name searches."""

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    SearchTimeout,
    build_response,
    iter_segments,
    resolve_target,
    safe_generate_disasm_line,
    safe_get_strlist_items,
    safe_get_strlit_contents,
    xref_count_limited,
)


def search_bytes(pattern, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Byte pattern search with wildcards."""
    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    def maybe_add(line):
        nonlocal matches_seen, truncated
        matches_seen += 1
        if matches_seen <= offset:
            return False
        results.append(line)
        if len(results) >= limit:
            truncated = True
            return True
        return False

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=False):
        if hasattr(ida_bytes, "compiled_binpat_vec_t"):
            pt = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
            if err:
                return make_error(MCPError.INVALID_ARGS, f"Invalid pattern: {err}")
            ea, _ = ida_bytes.bin_search(seg_start, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
            while ea != idaapi.BADADDR:
                line = hex(ea)
                if include_context:
                    match_bytes = ida_bytes.get_bytes(ea, min(32, seg_end - ea))
                    if match_bytes:
                        line += f"  {match_bytes.hex()}"
                    disasm_line = safe_generate_disasm_line(ea)
                    line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                if maybe_add(line):
                    break
                ea, _ = ida_bytes.bin_search(ea + 1, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
        else:
            try:
                import ida_search
                if hasattr(ida_search, "find_binary"):
                    flags = getattr(ida_search, "SEARCH_DOWN", 0)
                    ea = ida_search.find_binary(seg_start, seg_end, pattern, 16, flags)
                    while ea != idaapi.BADADDR:
                        line = hex(ea)
                        if include_context:
                            match_bytes = ida_bytes.get_bytes(ea, min(32, seg_end - ea))
                            if match_bytes:
                                line += f"  {match_bytes.hex()}"
                            disasm_line = safe_generate_disasm_line(ea)
                            line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                        if maybe_add(line):
                            break
                        ea = ida_search.find_binary(ea + 1, seg_end, pattern, 16, flags)
                else:
                    def _parse_tokens(text):
                        toks = [t.strip() for t in text.split() if t.strip()]
                        parsed = []
                        for tok in toks:
                            tok = tok.upper()
                            if tok in ("?", "??"):
                                parsed.append(None)
                                continue
                            if len(tok) != 2 or any(c not in "0123456789ABCDEF?" for c in tok):
                                raise ValueError(f"Invalid byte token: {tok}")
                            hi = None if tok[0] == "?" else int(tok[0], 16)
                            lo = None if tok[1] == "?" else int(tok[1], 16)
                            parsed.append((hi, lo))
                        return parsed

                    def _match(byte_val, spec):
                        if spec is None:
                            return True
                        hi, lo = spec
                        if hi is not None and ((byte_val >> 4) & 0xF) != hi:
                            return False
                        return not (lo is not None and byte_val & 15 != lo)

                    pat_specs = _parse_tokens(pattern)
                    if not pat_specs:
                        return make_error(MCPError.INVALID_ARGS, "Empty byte pattern")
                    plen = len(pat_specs)
                    chunk_size = 256 * 1024  # 256KB chunks to avoid memory bombs
                    curr = seg_start
                    while curr < seg_end and not truncated and not timed_out:
                        try:
                            timer.check()
                        except TimeoutError:
                            timed_out = True
                            break
                        chunk_end = min(curr + chunk_size + plen - 1, seg_end)
                        chunk_bytes = ida_bytes.get_bytes(curr, max(0, chunk_end - curr)) or b""
                        if len(chunk_bytes) >= plen:
                                for i in range(0, len(chunk_bytes) - plen + 1):
                                    ok = all(_match(chunk_bytes[i + j], spec) for j, spec in enumerate(pat_specs))
                                    if ok:
                                        ea = curr + i
                                        line = hex(ea)
                                        if include_context:
                                            match_bytes = chunk_bytes[i:i + min(32, len(chunk_bytes) - i)]
                                            if match_bytes:
                                                line += f"  {match_bytes.hex()}"
                                            disasm_line = safe_generate_disasm_line(ea)
                                            line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                                        if maybe_add(line):
                                            truncated = True
                                            break
                        curr += chunk_size
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Byte search fallback failed: {e}")

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result


def search_string(pattern, case_sensitive, include_context, offset, limit, timeout_ms=0):
    """Search string literals."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    for sc in safe_get_strlist_items():
        if truncated or timed_out:
            break
        try:
            timer.check()
        except TimeoutError:
            timed_out = True
            break
        try:
            s = safe_get_strlit_contents(sc.ea)
            if s is not None and matcher(s):
                matches_seen += 1
                if matches_seen > offset:
                    xref_count = len(list(idautils.XrefsTo(sc.ea)))
                    line = f"{hex(sc.ea)}  xrefs={xref_count}  {s[:500]}"
                    if include_context:
                        func = idaapi.get_func(sc.ea)
                        if func:
                            line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                    results.append(line)
                    if len(results) >= limit:
                        truncated = True
                        break
        except Exception:
            pass

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result


def search_immediate(pattern, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Search for immediate values in instructions."""
    semantic_meta = {}
    try:
        value = int(pattern, 0)
    except Exception:
        resolved_ea, sem_err, sem_meta = resolve_target(pattern, require_function=False, include_imports=False)
        if sem_err:
            return make_error(MCPError.INVALID_ARGS, f"Invalid immediate value: {sem_err}")
        value = resolved_ea
        semantic_meta = sem_meta

    import ida_ua
    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        if timed_out:
            break
        curr = seg_start
        while curr < seg_end:
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, curr) > 0:
                for op in insn.ops:
                    if op.type == ida_ua.o_imm and op.value == value:
                        matches_seen += 1
                        if matches_seen > offset:
                            line = f"{hex(curr)}  {hex(value)}"
                            if include_context:
                                disasm_line = safe_generate_disasm_line(curr)
                                line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                                func = idaapi.get_func(curr)
                                if func:
                                    line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            results.append(line)
                            if len(results) >= limit:
                                truncated = True
                                break
                            break
                if truncated:
                    break
                curr += insn.size
            else:
                curr = idc.next_head(curr, seg_end)
            if truncated:
                break

    result = build_response(results, offset, limit, matches_seen, truncated, value=hex(value), **semantic_meta)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result


def search_name(pattern, case_sensitive, offset, limit):
    """Search symbol names."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0

    for ea, name in idautils.Names():
        if truncated:
            break
        if matcher(name):
            matches_seen += 1
            if matches_seen > offset:
                kind = "func" if idaapi.get_func(ea) else ("data" if ida_bytes.is_data(ida_bytes.get_flags(ea)) else "label")
                xr = xref_count_limited(ea, 256)
                results.append(f"{hex(ea)}  {kind}  xrefs={xr}  {name}")
                if len(results) >= limit:
                    truncated = True
                    break

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
