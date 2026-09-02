"""SEARCH.CODE - Instruction sequence, text, operand, and comment searches."""

from .._common import (
    MCPError,
    compile_smart_pattern,
    ida_bytes,
    ida_funcs,
    ida_lines,
    idaapi,
    idc,
    make_error
)

from .core import (
    SearchTimeout,
    build_response,
    iter_code,
    iter_segments,
    resolve_scan_segments,
    safe_generate_disasm_line,
)

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from ... import compat as _compat


def search_insns(pattern, range_start, range_end, include_context, offset, limit):
    """Search instruction sequences."""
    mnemonics = [m.strip().lower() for m in pattern.split(",")]
    results = []
    truncated = False
    matches_seen = 0

    segs, seg_note, seg_error = resolve_scan_segments(range_start, range_end, require_exec=True)
    if seg_error:
        return make_error(MCPError.NOT_FOUND, seg_error)
    relaxed = bool(seg_note)
    for seg_start, seg_end in segs:
        ea = seg_start
        while ea < seg_end and not truncated:
            if relaxed or ida_bytes.is_code(ida_bytes.get_flags(ea)):
                match = True
                check_ea = ea
                sequence = []
                for mnem in mnemonics:
                    raw_mnem = idc.print_insn_mnem(check_ea)
                    curr_mnem = raw_mnem.lower() if raw_mnem else ""
                    if mnem not in ("*", curr_mnem):
                        match = False
                        break
                    sequence.append(curr_mnem)
                    check_ea = idc.next_head(check_ea, seg_end)
                    if check_ea == idaapi.BADADDR:
                        match = False
                        break
                if match:
                    matches_seen += 1
                    if matches_seen > offset:
                        line = hex(ea)
                        if include_context:
                            line += f"  [{','.join(sequence)}]"
                            func = _compat.get_func_start(ea)
                            if func is not None:
                                line += f"  in:{ida_funcs.get_func_name(func)}"
                        results.append(line)
                        if len(results) >= limit:
                            truncated = True
                            break
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if seg_note:
        result["note"] = seg_note
    return result


def search_text(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Search disassembly text."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
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
                if matcher(line_clean):
                    matches_seen += 1
                    if matches_seen > offset:
                        result_line = f"{hex(ea)}  {line_clean}"
                        if include_context:
                            func = _compat.get_func_start(ea)
                            if func is not None:
                                result_line += f"  in:{ida_funcs.get_func_name(func)}"
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


def search_operand(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Search operands."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
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
            ops = []
            for i in range(8):
                if idc.get_operand_type(ea, i) == getattr(idaapi, "o_void", getattr(idc, "o_void", 0)):
                    break
                ops.append(idc.print_operand(ea, i) or "")
            op_text = ", ".join(ops)
            if op_text and matcher(op_text):
                matches_seen += 1
                if matches_seen > offset:
                    line = f"{hex(ea)}  {idc.print_insn_mnem(ea)}  {op_text}"
                    if include_context:
                        disasm_line = safe_generate_disasm_line(ea)
                        line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                    results.append(line)
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


def search_comment(pattern, case_sensitive, range_start, range_end, offset, limit, timeout_ms=0):
    """Search comments."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=False):
        if timed_out:
            break
        ea = seg_start
        while ea < seg_end and not truncated:
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            cmt = idc.get_cmt(ea, 0)
            cmt_type = "regular"
            if not cmt:
                cmt = idc.get_cmt(ea, 1)
                cmt_type = "repeatable"
            if cmt and matcher(cmt):
                matches_seen += 1
                if matches_seen > offset:
                    results.append(f"{hex(ea)}  {cmt_type}  {cmt}")
                    if len(results) >= limit:
                        truncated = True
                        break
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result
