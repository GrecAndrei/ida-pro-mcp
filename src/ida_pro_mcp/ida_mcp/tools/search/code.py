"""SEARCH.CODE - Instruction sequence, text, operand, and comment searches."""

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    SearchTimeout,
    build_response,
    iter_code,
    iter_segments,
    safe_generate_disasm_line,
)


def search_insns(pattern, range_start, range_end, include_context, offset, limit):
    """Search instruction sequences."""
    mnemonics = [m.strip().lower() for m in pattern.split(",")]
    results = []
    truncated = False
    matches_seen = 0

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        ea = seg_start
        while ea < seg_end and not truncated:
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
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
                            func = idaapi.get_func(ea)
                            if func:
                                line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                        results.append(line)
                        if len(results) >= limit:
                            truncated = True
                            break
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)


def search_text(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, timeout_ms=0):
    """Search disassembly text."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0
    timer = SearchTimeout(timeout_ms)
    timed_out = False

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        if timed_out:
            break
        for ea in iter_code(seg_start, seg_end):
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

    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        if timed_out:
            break
        for ea in iter_code(seg_start, seg_end):
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            ops = []
            for i in range(8):
                if idc.get_operand_type(ea, i) == idaapi.o_void:
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
