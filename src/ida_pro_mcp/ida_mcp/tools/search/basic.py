"""SEARCH.BASIC - Byte, string, immediate, name, and raw-data-word searches."""

import re as _re  # keep stdlib re out of the wildcard namespace
import struct as _struct

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

from .core import (
    SearchTimeout,
    build_response,
    iter_segments,
    resolve_scan_segments,
    resolve_target,
    riscv_lui_addi_pair,
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
        if truncated or timed_out:
            break
        if hasattr(ida_bytes, "compiled_binpat_vec_t"):
            pt = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
            if err:
                return make_error(MCPError.INVALID_ARGS, f"Invalid pattern: {err}")
            ea, _ = ida_bytes.bin_search(seg_start, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
            while ea != idaapi.BADADDR:
                if truncated or timed_out:
                    break
                try:
                    timer.check()
                except TimeoutError:
                    timed_out = True
                    break
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
                                for i in range(len(chunk_bytes) - plen + 1):
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


def search_string(pattern, case_sensitive, include_context, offset, limit, timeout_ms=0, range_start=None, range_end=None):
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
        if range_start is not None and range_end is not None and not (range_start <= sc.ea < range_end):
            continue
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
                        func = _compat.get_func_start(sc.ea)
                        if func is not None:
                            line += f"  in:{ida_funcs.get_func_name(func)}"
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

    segs, seg_note, seg_error = resolve_scan_segments(range_start, range_end, require_exec=True)
    if seg_error:
        return make_error(MCPError.NOT_FOUND, seg_error)
    for seg_start, seg_end in segs:
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
                direct_matched = False
                for op in insn.ops:
                    if op.type == ida_ua.o_imm and op.value == value:
                        direct_matched = True
                        matches_seen += 1
                        if matches_seen > offset:
                            line = f"{hex(curr)}  {hex(value)}"
                            if include_context:
                                disasm_line = safe_generate_disasm_line(curr)
                                line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                                func = _compat.get_func_start(curr)
                                if func is not None:
                                    line += f"  in:{ida_funcs.get_func_name(func)}"
                            results.append(line)
                            if len(results) >= limit:
                                truncated = True
                                break
                        break
                if not direct_matched and not truncated:
                    # RISC-V materializes many 32-bit constants as an adjacent
                    # lui+addi/addiw pair whose halves never appear alone as
                    # ``value``.  Reconstruct the full constant and match on it.
                    next_ea = curr + getattr(insn, "size", 0)
                    if next_ea > curr and next_ea < seg_end:
                        try:
                            next_insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(next_insn, next_ea) > 0:
                                pair = riscv_lui_addi_pair(insn, next_insn)
                                if pair and pair[0] == value:
                                    matches_seen += 1
                                    if matches_seen > offset:
                                        addi_ea = pair[1]
                                        line = (
                                            f"{hex(curr)}  {hex(value)}  "
                                            f"(lui+addi@{hex(addi_ea)} -> {hex(value)})"
                                        )
                                        if include_context:
                                            disasm_line = safe_generate_disasm_line(curr)
                                            line += f"  {ida_lines.tag_remove(disasm_line) if disasm_line else ''}"
                                            func = _compat.get_func_start(curr)
                                            if func is not None:
                                                line += f"  in:{ida_funcs.get_func_name(func)}"
                                        results.append(line)
                                        if len(results) >= limit:
                                            truncated = True
                        except Exception:
                            pass
                if truncated:
                    break
                curr += insn.size
            else:
                curr = idc.next_head(curr, seg_end)
                if curr == idaapi.BADADDR:
                    break
            if truncated:
                break

    result = build_response(results, offset, limit, matches_seen, truncated, value=hex(value), **semantic_meta)
    if seg_note:
        result["note"] = seg_note
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
                kind = "func" if _compat.get_func_start(ea) is not None else ("data" if ida_bytes.is_data(ida_bytes.get_flags(ea)) else "label")
                xr = xref_count_limited(ea, 256)
                results.append(f"{hex(ea)}  {kind}  xrefs={xr}  {name}")
                if len(results) >= limit:
                    truncated = True
                    break

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)


# ---------------------------------------------------------------------------
# data_value — raw pointer-word scan (closes the /v gap natively)
# ---------------------------------------------------------------------------
# IDA rarely builds data xrefs for dispatch/vector tables and function-pointer
# arrays, so ``search(action='data_ref')`` silently misses them.  This action
# scans the *mapped bytes* directly and unpacks LE/BE pointer-width words,
# reporting every location whose raw word equals the target address regardless
# of whether IDA created an xref.

_DATA_VALUE_CHUNK = 256 * 1024  # bytes read per ida_bytes.get_bytes call


def _data_value_kind(ea: int) -> str:
    """Classify a location as code/data/unknown from its item flags."""
    try:
        flags = ida_bytes.get_flags(ea)
        if idc.is_code(flags):
            return "code"
        if idc.is_data(flags):
            return "data"
    except Exception:
        pass
    return "unknown"


def _resolve_data_value_region(region: str, word_size: int):
    """Resolve a scan-region string to ``(start, end)`` or ``None``.

    Accepts ``0x1000-0x2000`` / ``0x1000:0x2000`` ranges, a segment name, or a
    single address (scanned as one ``word_size``-byte word).
    """
    if not region:
        return None
    m = _re.fullmatch(r"\s*(0x[0-9a-fA-F]+)\s*[-:]\s*(0x[0-9a-fA-F]+)\s*", region)
    if m:
        return int(m.group(1), 16), int(m.group(2), 16)
    try:
        seg_ea = _compat.get_segment_ea_by_name(region)
        if seg_ea is not None:
            seg = _compat.get_segment(seg_ea)
            return seg.start_ea, seg.end_ea
    except Exception:
        pass
    if looks_like_address(region):
        try:
            ea = int(region, 0) if region.lower().startswith("0x") else int(region, 16)
            return ea, ea + word_size
        except ValueError:
            return None
    return None


def search_data_value(
    value,
    range_start=None,
    range_end=None,
    endian="both",
    word_size="auto",
    offset=0,
    limit=100,
    timeout_ms=0,
    region=None,
):
    """Find every raw pointer-sized word equal to a target address.

    Closes the /v gap natively on an analyzed IDB.  IDA rarely creates data
    xrefs for dispatch/vector tables and function-pointer arrays, so
    ``search(action='data_ref')`` misses them.  This action scans the mapped
    bytes directly and unpacks LE/BE pointer-width words with struct, finding
    every location whose raw word equals ``value`` regardless of whether IDA
    created an xref.

    Args:
        value: target address (hex string or int) or symbol name to look for
            as a raw pointer word.
        range_start/range_end: optional explicit scan range.
        region: optional ``0x1000-0x2000`` / ``0x1000:0x2000`` range, a
            segment name, or a single address; takes precedence over
            start/end.
        endian: ``"both"`` (default), ``"le"``, or ``"be"``.
        word_size: ``"auto"`` (pointer width of the IDB), ``"u32"``, or
            ``"u64"``.
        offset/limit: pagination.
        timeout_ms: bounded scan budget (0 = no limit).

    Returns the standard search envelope with ``items[]`` each carrying
    ``{address, value, endian, kind}`` where ``kind`` is code/data/unknown
    from the item flags.
    """
    # Resolve the target value to an integer address.
    if isinstance(value, int):
        target = value
    else:
        text = str(value).strip()
        try:
            target = int(text, 0)
        except ValueError:
            if looks_like_address(text):
                try:
                    target = int(text, 16)
                except ValueError:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid data_value target: {value!r}")
            else:
                target_ea, err, _sem_meta = resolve_target(
                    text, require_function=False, include_imports=False
                )
                if err:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid data_value target: {err}")
                target = target_ea

    # Resolve the word size ('auto' = pointer width of the IDB).
    ws_raw = str(word_size or "auto").lower().strip()
    if ws_raw in ("u32", "32", "4", "dword"):
        ws = 4
    elif ws_raw in ("u64", "64", "8", "qword"):
        ws = 8
    else:
        ws = _inf_ptr_size()
        if ws not in (4, 8):
            ws = 4

    # Resolve the endian mode.
    end_raw = str(endian or "both").lower().strip()
    if end_raw in ("le", "little", "little_endian", "little-endian"):
        end_mode = "le"
    elif end_raw in ("be", "big", "big_endian", "big-endian"):
        end_mode = "be"
    elif end_raw in ("both", "auto", ""):
        end_mode = "both"
    else:
        return make_error(MCPError.INVALID_ARGS, f"Invalid endian: {endian!r} (use 'both', 'le', or 'be')")

    # Resolve the scan region.
    scan_start = scan_end = None
    if range_start is not None or range_end is not None:
        if range_start is None or range_end is None:
            return make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
        scan_start, scan_end = range_start, range_end
    elif region:
        resolved = _resolve_data_value_region(str(region).strip(), ws)
        if resolved is None:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Invalid region: {region!r} (use 'start-end', 'start:end', a segment name, or a single address)",
            )
        scan_start, scan_end = resolved

    le_fmt = {4: "<I", 8: "<Q"}[ws]
    be_fmt = {4: ">I", 8: ">Q"}[ws]
    timer = SearchTimeout(timeout_ms)
    timed_out = False
    truncated = False
    matches_seen = 0
    results = []

    for seg_start, seg_end in iter_segments(scan_start, scan_end, require_exec=False):
        if timed_out or truncated:
            break
        curr = seg_start
        while curr < seg_end:
            try:
                timer.check()
            except TimeoutError:
                timed_out = True
                break
            # Read one chunk plus a word_size-1 byte lookahead so a pointer
            # word straddling the chunk boundary is still seen.  Offsets in the
            # lookahead region are left to the next chunk (they are that
            # chunk's primary addresses), which dedupes boundary hits.
            #
            # Words are scanned at word-size alignment (step = ws, anchored to
            # the segment start; _DATA_VALUE_CHUNK is a multiple of 4 and 8 so
            # chunk boundaries stay on that lattice).  Stepping by one byte
            # would fabricate shifted false positives: the BE encoding of a
            # target contains byte subsequences that LE-decode back to the
            # target at a neighbouring offset.
            read_len = min(_DATA_VALUE_CHUNK + ws - 1, seg_end - curr)
            data = ida_bytes.get_bytes(curr, read_len) or b""
            chunk_start = curr
            for off in range(0, len(data) - ws + 1, ws):
                ea = chunk_start + off
                if ea >= chunk_start + _DATA_VALUE_CHUNK:
                    break  # lookahead region — the next chunk scans it
                word = data[off:off + ws]
                hit_endian = None
                if end_mode in ("both", "le") and _struct.unpack(le_fmt, word)[0] == target:
                    hit_endian = "le"
                elif end_mode in ("both", "be") and _struct.unpack(be_fmt, word)[0] == target:
                    hit_endian = "be"
                if hit_endian is None:
                    continue
                matches_seen += 1
                if matches_seen <= offset:
                    continue
                kind = _data_value_kind(ea)
                line = f"{hex(ea)}  {hex(target)}  {hit_endian}  {kind}"
                results.append({
                    "address": hex(ea), "addr": hex(ea),
                    "value": hex(target), "endian": hit_endian,
                    "kind": kind, "line": line,
                })
                if len(results) >= limit:
                    truncated = True
                    break
            if truncated:
                break
            curr += _DATA_VALUE_CHUNK

    result = build_response(
        [r["line"] for r in results],
        offset, limit, matches_seen, truncated,
        value=hex(target), endian=end_mode, word_size=f"u{ws * 8}",
    )
    result["items"] = [
        {"address": r["address"], "addr": r["addr"], "value": r["value"],
         "endian": r["endian"], "kind": r["kind"]}
        for r in results
    ]
    if scan_start is not None:
        result["note"] = f"Scanned {hex(scan_start)}-{hex(scan_end)}"
    if timed_out:
        result["timed_out"] = True
        result["hint"] = "Search timed out. Narrow with range or increase timeout_ms."
    return result
