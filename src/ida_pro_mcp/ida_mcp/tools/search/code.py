"""SEARCH.CODE - Mnemonic, instruction, text, operand, and comment searches."""

import heapq

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ...support.semantic_matching import semantic_score, semantic_tokens
except ImportError:
    from support.semantic_matching import semantic_score, semantic_tokens  # type: ignore[import-not-found]

from .core import (
    _FIND_INSTRUCTION_CAP,
    _FIND_INSTRUCTION_LIMIT_MULTIPLIER,
    INSTRUCTION_BASE_SCORE,
    INSTRUCTION_CAP,
    INSTRUCTION_TOKEN_WEIGHT,
    MNEMONIC_BASE_SCORE,
    MNEMONIC_CAP,
    MNEMONIC_GROUP_SCORE,
    MNEMONIC_GROUPS,
    MNEMONIC_TOKEN_WEIGHT,
    SCORE_SUBSTRING,
    SearchTimeout,
    build_response,
    clip_text,
    iter_code,
    iter_segments,
    paginate_records,
    safe_generate_disasm_line,
)


def _adaptive_score_cutoff(scores, keep_ratio: float = 0.35) -> float:
    """
    Adaptive deterministic cutoff from observed score distribution.
    Keeps top keep_ratio fraction; avoids hard-coded heuristic thresholds.
    """
    vals = [float(s) for s in scores if s is not None]
    if not vals:
        return 0.0
    vals.sort(reverse=True)
    idx = max(0, min(len(vals) - 1, int(len(vals) * max(0.05, min(0.95, keep_ratio))) - 1))
    return vals[idx]


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

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)


def search_mnemonic(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, include_items, include_breakdown, timeout_ms=0):
    """Semantic mnemonic search with ranking."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    query_tokens = set(semantic_tokens(pattern))
    semantic_prefixes = {pref for token in query_tokens for pref in MNEMONIC_GROUPS.get(token, ())}

    ranked_heap = []
    all_scores = []
    ranked_cap = max(_FIND_INSTRUCTION_CAP, (offset + limit) * _FIND_INSTRUCTION_LIMIT_MULTIPLIER)
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
            mnem = (idc.print_insn_mnem(ea) or "").strip().lower()
            if not mnem:
                continue
            raw_disasm = safe_generate_disasm_line(ea)
            disasm = ida_lines.tag_remove(raw_disasm) if raw_disasm else ""
            semantic_blob = f"{mnem} {disasm}"
            score = 0.0
            matched = False

            if matcher(mnem) or matcher(semantic_blob):
                matched = True
                score += MNEMONIC_BASE_SCORE
            if semantic_prefixes and any(mnem.startswith(pref) for pref in semantic_prefixes):
                matched = True
                score += MNEMONIC_GROUP_SCORE
            if query_tokens:
                overlap = len(query_tokens.intersection(set(semantic_tokens(semantic_blob))))
                score += overlap * MNEMONIC_TOKEN_WEIGHT
            score += min(semantic_score(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING), MNEMONIC_CAP)

            all_scores.append(score)
            if matched:
                record = {
                    "address_ea": ea,
                    "address": hex(ea),
                    "mnemonic": mnem,
                    "score": round(score, 2),
                    "line": f"{hex(ea)}  {mnem}" + (f"  {clip_text(disasm)}" if include_context else ""),
                }
                key = (float(record["score"]), int(record["address_ea"]))
                if len(ranked_heap) < ranked_cap:
                    heapq.heappush(ranked_heap, (key, record))
                elif key > ranked_heap[0][0]:
                    heapq.heapreplace(ranked_heap, (key, record))

    # Add additional semantic hits above adaptive cutoff.
    cutoff = _adaptive_score_cutoff(all_scores, keep_ratio=0.30)
    if cutoff > 0:
        for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
            if timed_out:
                break
            for ea in iter_code(seg_start, seg_end):
                try:
                    timer.check()
                except TimeoutError:
                    timed_out = True
                    break
                mnem = (idc.print_insn_mnem(ea) or "").strip().lower()
                if not mnem:
                    continue
                raw_disasm = safe_generate_disasm_line(ea)
                disasm = ida_lines.tag_remove(raw_disasm) if raw_disasm else ""
                semantic_blob = f"{mnem} {disasm}"
                score = min(semantic_score(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING), MNEMONIC_CAP)
                if score < cutoff:
                    continue
                record = {
                    "address_ea": ea,
                    "address": hex(ea),
                    "mnemonic": mnem,
                    "score": round(score, 2),
                    "line": f"{hex(ea)}  {mnem}" + (f"  {clip_text(disasm)}" if include_context else ""),
                }
                key = (float(record["score"]), int(record["address_ea"]))
                if len(ranked_heap) < ranked_cap:
                    heapq.heappush(ranked_heap, (key, record))
                elif key > ranked_heap[0][0]:
                    heapq.heapreplace(ranked_heap, (key, record))

    ranked = [item[1] for item in ranked_heap]
    page, total, is_truncated = paginate_records(
        ranked, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )

    out = build_response([r["line"] for r in page], offset, limit, total, is_truncated, query=pattern)
    if timed_out:
        out["timed_out"] = True
        out["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    if include_items:
        out["items"] = [{"address": r["address"], "mnemonic": r["mnemonic"], "score": r["score"]} for r in page]
    if include_breakdown:
        out["semantic_groups"] = sorted(token for token in query_tokens if token in MNEMONIC_GROUPS)
    return out


def search_instruction(pattern, case_sensitive, range_start, range_end, include_context, offset, limit, include_items, timeout_ms=0):
    """Semantic full-instruction search."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    query_tokens = set(semantic_tokens(pattern))
    ranked_heap = []
    all_scores = []
    ranked_cap = max(_FIND_INSTRUCTION_CAP, (offset + limit) * _FIND_INSTRUCTION_LIMIT_MULTIPLIER)
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
            if not line:
                continue
            line_clean = ida_lines.tag_remove(line) if line else ""
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            semantic_blob = f"{mnem} {line_clean}"
            matched = matcher(line_clean) or matcher(semantic_blob)
            overlap = len(query_tokens.intersection(set(semantic_tokens(semantic_blob)))) if query_tokens else 0
            score = min(semantic_score(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING), INSTRUCTION_CAP) + (overlap * INSTRUCTION_TOKEN_WEIGHT)
            if matched:
                score += INSTRUCTION_BASE_SCORE
            all_scores.append(score)
            if matched:
                out_line = f"{hex(ea)}  {line_clean}"
                if include_context:
                    func = idaapi.get_func(ea)
                    if func:
                        out_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                record = {
                    "address_ea": ea,
                    "address": hex(ea),
                    "score": round(score, 2),
                    "line": clip_text(out_line, 360),
                }
                key = (float(record["score"]), int(record["address_ea"]))
                if len(ranked_heap) < ranked_cap:
                    heapq.heappush(ranked_heap, (key, record))
                elif key > ranked_heap[0][0]:
                    heapq.heapreplace(ranked_heap, (key, record))

    cutoff = _adaptive_score_cutoff(all_scores, keep_ratio=0.30)
    if cutoff > 0:
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
                if not line:
                    continue
                line_clean = ida_lines.tag_remove(line) if line else ""
                mnem = (idc.print_insn_mnem(ea) or "").lower()
                semantic_blob = f"{mnem} {line_clean}"
                score = min(semantic_score(pattern, semantic_blob, substring_bonus=SCORE_SUBSTRING), INSTRUCTION_CAP)
                if score < cutoff:
                    continue
                out_line = f"{hex(ea)}  {line_clean}"
                if include_context:
                    func = idaapi.get_func(ea)
                    if func:
                        out_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                record = {
                    "address_ea": ea,
                    "address": hex(ea),
                    "score": round(score, 2),
                    "line": clip_text(out_line, 360),
                }
                key = (float(record["score"]), int(record["address_ea"]))
                if len(ranked_heap) < ranked_cap:
                    heapq.heappush(ranked_heap, (key, record))
                elif key > ranked_heap[0][0]:
                    heapq.heapreplace(ranked_heap, (key, record))

    ranked = [item[1] for item in ranked_heap]
    page, total, is_truncated = paginate_records(
        ranked, offset, limit, sort_key=lambda r: (r["score"], r["address_ea"])
    )

    out = build_response([r["line"] for r in page], offset, limit, total, is_truncated, query=pattern)
    if timed_out:
        out["timed_out"] = True
        out["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    if include_items:
        out["items"] = [{"address": r["address"], "score": r["score"], "text": r["line"]} for r in page]
    return out


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

    result = build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result
