
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re
from collections import Counter

MAX_HEXDUMP_SIZE = 4096


# ============================================================================
# MEMORY - Read/Write/Search/Analyze operations
# ============================================================================

from .string_ops import shannon_entropy as _shannon_entropy


def _extract_strings(data, min_len=4):
    """Extract ASCII and UTF-16 strings from raw bytes."""
    strings = []
    i = 0
    n = len(data)
    # ASCII
    while i < n:
        j = i
        while j < n and 32 <= data[j] <= 126:
            j += 1
        if j - i >= min_len:
            strings.append((i, data[i:j].decode("ascii"), "ascii"))
        i = j + 1 if j == i else j
    # UTF-16-LE
    i = 0
    while i < n - 1:
        j = i
        while j < n - 1 and 32 <= data[j] <= 126 and data[j+1] == 0:
            j += 2
        if j - i >= min_len * 2:
            strings.append((i, data[i:j].decode("utf-16-le", errors="replace"), "utf-16-le"))
        i = j + 2 if j == i else j
    return strings


def _is_be():
    return _inf_is_be()


def _find_pointers(data, start_ea):
    """Find all valid pointers in a byte sequence."""
    is_64 = _inf_bitness() == 64
    ptr_size = 8 if is_64 else 4
    endian = ">" if _is_be() else "<"
    fmt = f"{endian}Q" if is_64 else f"{endian}I"
    import struct
    pointers = []
    for i in range(0, len(data) - ptr_size + 1, ptr_size):
        val = struct.unpack_from(fmt, data, i)[0]
        if val != 0 and ida_bytes.is_loaded(val):
            pointers.append((start_ea + i, hex(val), idc.get_name(val) or ""))
    return pointers


@tool
@idawrite
def memory(
    action: Annotated[Literal[
        "read", "write", "hexdump", "search", "compare", "pointers", "find_pointers",
        "entropy", "strings", "struct_walk", "histogram"
    ], "Action: read|write|hexdump|search|compare|pointers|find_pointers|entropy|strings|struct_walk|histogram"],
    addr: Annotated[Optional[str], "Address (required for most actions; optional for search with start/end)"] = None,
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"],
                    "Data type (for read). Default 'bytes' — returns hex dump of size bytes"] = "bytes",
    size: Annotated[int, "Size in bytes (for type=bytes or hexdump)"] = 16,
    data: Annotated[Optional[str], "Hex data to write (for write) or pattern to search (for search)"] = None,
    end_addr: Annotated[Optional[str], "End address for compare/search/pointers/entropy/strings"] = None,
    depth: Annotated[int, "Recursion depth for struct_walk"] = 2,
    **kwargs
) -> dict:
    """
    Read, write, search, and analyze raw memory in the database (or debugger memory if running).

    Actions:
    - read: Read values from `addr`. Returns hex or native value.
    - write: Patch bytes at `addr`.
    - hexdump: Formatted hex dump with ASCII sidebar (like xxd).
    - search: Search for a byte pattern, string, or regex within a region.
    - compare: Compare two memory regions and show differences (addr + end_addr).
    - pointers: Find all valid pointers within a region.
    - entropy: Calculate Shannon entropy of a region.
    - strings: Extract strings from a region.
    - struct_walk: Follow pointers recursively starting from `addr` (up to `depth` levels).
    - histogram: Byte frequency histogram for a region.

    Arguments:
    - addr: Address to read/write/search.
    - type: Data type for read (u8/u16/u32/u64, s8/s16/s32/s64, f32/f64, ptr, bytes, string). Default 'u32'.
    - size: Number of bytes to read (only for type='bytes' or action='hexdump'). Default 16.
    - data: Hex string to write (e.g. "90 90 90") REQUIRED for write; search pattern for search.
    - end_addr: End address for region-based actions (search, compare, pointers, entropy, strings, histogram).
    - depth: Max recursion depth for struct_walk.
    """
    result = _memory_impl(action, addr, type, size, data, end_addr, depth, **kwargs)
    return result


def _memory_impl(action, addr, type, size, data, end_addr, depth, **kwargs) -> dict:
    try:
        ea = None
        if addr is not None and str(addr).strip() != "":
            ea, error = validate_addr(str(addr))
            if error:
                return error

        if action != "search" and ea is None:
            return make_error(MCPError.INVALID_ARGS, "addr required")

        if action == "read":
            if size > 1024 * 1024:
                return make_error(MCPError.SIZE_LIMIT_EXCEEDED, f"Read size too large ({size} bytes)", "Limit reads to 1MB or use paging")

            if type == "bytes":
                raw = ida_bytes.get_bytes(ea, size)
                if raw:
                    value = " ".join(f"{x:02x}" for x in raw)
                else:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read {size} bytes from {hex(ea)}")
            elif type == "u8":
                value = ida_bytes.get_wide_byte(ea)
            elif type == "u16":
                value = ida_bytes.get_wide_word(ea)
            elif type == "u32":
                value = ida_bytes.get_wide_dword(ea)
            elif type == "u64":
                value = ida_bytes.get_qword(ea)
            elif type == "s8":
                value = ida_bytes.get_wide_byte(ea)
                value = value - 0x100 if value & 0x80 else value
            elif type == "s16":
                value = ida_bytes.get_wide_word(ea)
                value = value - 0x10000 if value & 0x8000 else value
            elif type == "s32":
                value = ida_bytes.get_wide_dword(ea)
                value = value - 0x100000000 if value & 0x80000000 else value
            elif type == "s64":
                value = ida_bytes.get_qword(ea)
                value = value - 0x10000000000000000 if value & 0x8000000000000000 else value
            elif type == "f32":
                raw = ida_bytes.get_bytes(ea, 4)
                if not raw:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read 4 bytes from {hex(ea)}")
                import struct
                endian = ">" if _is_be() else "<"
                value = struct.unpack(f"{endian}f", raw)[0]
            elif type == "f64":
                raw = ida_bytes.get_bytes(ea, 8)
                if not raw:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read 8 bytes from {hex(ea)}")
                import struct
                endian = ">" if _is_be() else "<"
                value = struct.unpack(f"{endian}d", raw)[0]
            elif type == "ptr":
                is_64 = _inf_bitness() == 64
                value = ida_bytes.get_qword(ea) if is_64 else ida_bytes.get_wide_dword(ea)
            elif type == "string":
                s = idc.get_strlit_contents(ea, -1, 0)
                if s:
                    if isinstance(s, bytes):
                        if len(s) > 65536:
                            s = s[:65536]
                        value = s.decode("utf-8", errors="replace")
                    else:
                        value = s[:65536] if len(s) > 65536 else s
                else:
                    value = None
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown type: {type}")
            resp = {"ok": True, "addr": addr, "type": type, "value": value}
            if type == "bytes":
                resp["size"] = size
            elif type in ("u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "ptr"):
                resp["value_hex"] = hex(value)
            elif type == "string":
                resp["length"] = len(value) if value is not None else 0
            return resp

        elif action == "write":
            if not data:
                return make_error(MCPError.INVALID_ARGS, "data required for write")
            try:
                bytes_data = bytes.fromhex(data.replace(" ", ""))
            except ValueError:
                return make_error(MCPError.INVALID_ARGS, "Invalid hex data")
            ida_bytes.patch_bytes(ea, bytes_data)
            return {
                "ok": True,
                "addr": addr,
                "size": len(bytes_data),
                "data": data,
                "note": "This patched the IDA database, not live process memory. Use debug(action='write_mem') for debugger memory writes.",
            }

        elif action == "hexdump":
            if size > MAX_HEXDUMP_SIZE:
                return make_error(MCPError.SIZE_LIMIT_EXCEEDED, f"hexdump limited to {MAX_HEXDUMP_SIZE} bytes",
                                hint="Use smaller size or action=read with type=bytes")
            raw = ida_bytes.get_bytes(ea, size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read {size} bytes from {hex(ea)}")
            lines = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                hex_part = hex_part.ljust(48)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{hex(ea + i)}  {hex_part}  |{ascii_part}|")
            return {
                "ok": True,
                "addr": hex(ea),
                "size": len(raw),
                "hexdump": "\n".join(lines),
            }

        elif action == "search":
            pattern = str(kwargs.get("pattern") or data or "").strip()
            if not pattern:
                return make_error(MCPError.INVALID_ARGS, "data/pattern required for search")
            if ea is None:
                if end_addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required when end_addr is provided")
                min_ea = _inf_min_ea()
                if min_ea in (None, idaapi.BADADDR):
                    return make_error(MCPError.INVALID_ARGS, "addr required for search when IDB min address is unavailable")
                ea = int(min_ea)
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            if end_ea <= ea:
                end_ea = ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            # Determine search mode: hex-with-wildcards, regex on ascii, or integer literal.
            pattern_bytes = None
            wildcard_mask = None
            regex_mode = bool(kwargs.get("regex", False))
            int_mode = False
            try:
                if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", pattern):
                    int_mode = True
                    v = int(pattern, 0)
                    width = int(kwargs.get("int_width", 4) or 4)
                    endian = "big" if _is_be() else "little"
                    pattern_bytes = int(v).to_bytes(width, endian, signed=False)
                elif re.search(r"\?\?|[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F?]{2})+", pattern):
                    toks = pattern.split()
                    pb = []
                    pm = []
                    for t in toks:
                        if "?" in t:
                            pb.append(0)
                            pm.append(False)
                        else:
                            pb.append(int(t, 16))
                            pm.append(True)
                    pattern_bytes = bytes(pb)
                    wildcard_mask = pm
                else:
                    pattern_bytes = pattern.encode("utf-8", errors="replace")
            except Exception:
                pattern_bytes = pattern.encode("utf-8", errors="replace")
            hits = []
            if regex_mode:
                try:
                    rgx = re.compile(pattern.encode("utf-8"), re.IGNORECASE)
                    for m in rgx.finditer(raw):
                        hits.append(hex(ea + m.start()))
                        if len(hits) >= 256:
                            break
                except Exception:
                    return make_error(MCPError.INVALID_ARGS, "invalid regex pattern")
            elif wildcard_mask is not None:
                plen = len(pattern_bytes)
                for i in range(0, max(0, len(raw) - plen + 1)):
                    ok = True
                    for j in range(plen):
                        if wildcard_mask[j] and raw[i + j] != pattern_bytes[j]:
                            ok = False
                            break
                    if ok:
                        hits.append(hex(ea + i))
                        if len(hits) >= 256:
                            break
            else:
                idx = raw.find(pattern_bytes)
                while idx != -1:
                    hits.append(hex(ea + idx))
                    if len(hits) >= 256:
                        break
                    idx = raw.find(pattern_bytes, idx + 1)
            return {"ok": True, "pattern": pattern, "hits": hits, "count": len(hits), "region": f"{hex(ea)}-{hex(ea + region_size)}", "mode": ("regex" if regex_mode else ("integer" if int_mode else ("hex_wildcard" if wildcard_mask is not None else "bytes")))}

        elif action == "compare":
            addr1 = str(kwargs.get("addr1") or addr or "").strip()
            addr2 = str(kwargs.get("addr2") or end_addr or "").strip()
            if not addr1 or not addr2:
                return make_error(MCPError.INVALID_ARGS, "addr1/addr2 (or addr/end_addr) required for compare")
            ea1, err1 = validate_addr(addr1)
            if err1:
                return err1
            ea2, err2 = validate_addr(addr2)
            if err2:
                return err2
            cmp_size = int(kwargs.get("size") or size or 16)
            if cmp_size <= 0:
                return make_error(MCPError.INVALID_ARGS, "size must be > 0")
            max_cmp = 8192
            if cmp_size > max_cmp:
                cmp_size = max_cmp
            raw_a = ida_bytes.get_bytes(ea1, cmp_size)
            raw_b = ida_bytes.get_bytes(ea2, cmp_size)
            if not raw_a or not raw_b:
                return make_error(MCPError.IDA_ERROR, "Could not read one or both regions")
            min_len = min(len(raw_a), len(raw_b))
            diffs = []
            for i in range(min_len):
                if raw_a[i] != raw_b[i]:
                    diffs.append({"offset": i, "byte1": f"{raw_a[i]:02x}", "byte2": f"{raw_b[i]:02x}", "addr1": hex(ea1 + i), "addr2": hex(ea2 + i)})
            if len(raw_a) != len(raw_b):
                diffs.append({"offset": min_len, "size_diff": f"A={len(raw_a)} B={len(raw_b)}"})
            # Bounded Levenshtein-like edit distance for bytes.
            if len(raw_a) * len(raw_b) > 4_000_000:
                # Fallback for large compares: approximate with positional hamming + size delta.
                edit_distance = sum(1 for i in range(min_len) if raw_a[i] != raw_b[i]) + abs(len(raw_a) - len(raw_b))
            else:
                dp = list(range(len(raw_b) + 1))
                for i in range(1, len(raw_a) + 1):
                    prev = dp[0]
                    dp[0] = i
                    for j in range(1, len(raw_b) + 1):
                        cur = dp[j]
                        cost = 0 if raw_a[i - 1] == raw_b[j - 1] else 1
                        dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
                        prev = cur
                edit_distance = dp[-1]
            similarity = round(100.0 * (1.0 - (edit_distance / max(1, max(len(raw_a), len(raw_b))))), 2)
            return {"ok": True, "addr1": hex(ea1), "addr2": hex(ea2), "size": cmp_size, "diff_count": len(diffs), "diffs": diffs[:256], "edit_distance": int(edit_distance), "similarity_pct": similarity, "size_capped": cmp_size == max_cmp}

        elif action in ("pointers", "find_pointers"):
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            ptrs = _find_pointers(raw, ea)
            lines = [{"offset": int(addr - ea), "target_addr": target, "target_name": name} for addr, target, name in ptrs[:256]]
            return {"ok": True, "pointers": lines, "count": len(ptrs), "region": f"{hex(ea)}-{hex(ea + region_size)}"}

        elif action == "entropy":
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            ent = _shannon_entropy(raw)
            null_ratio = round(raw.count(0) / len(raw), 4) if raw else 0.0
            return {"ok": True, "addr": hex(ea), "size": len(raw), "entropy": ent, "null_ratio": null_ratio}

        elif action == "strings":
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            strings = _extract_strings(raw, min_len=4)
            lines = [f"{hex(ea + offset)}  [{enc}]  {text}" for offset, text, enc in strings[:100]]
            return {"ok": True, "strings": lines, "count": len(strings), "region": f"{hex(ea)}-{hex(ea + region_size)}"}

        elif action == "struct_walk":
            is_64 = _inf_bitness() == 64
            ptr_size = 8 if is_64 else 4
            endian = ">" if _is_be() else "<"
            fmt = f"{endian}Q" if is_64 else f"{endian}I"
            import struct
            visited = set()
            nodes = []
            queue = [(ea, 0)]
            while queue:
                cur_ea, level = queue.pop(0)
                if cur_ea in visited or level > depth:
                    continue
                visited.add(cur_ea)
                raw = ida_bytes.get_bytes(cur_ea, ptr_size)
                if not raw:
                    continue
                val = struct.unpack(fmt, raw)[0]
                name = idc.get_name(val) or ""
                nodes.append({"level": level, "addr": hex(cur_ea), "points_to": hex(val), "name": name})
                if val != 0 and ida_bytes.is_loaded(val) and level < depth:
                    queue.append((val, level + 1))
            return {"ok": True, "nodes": nodes, "depth": depth}

        elif action == "histogram":
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            counts = Counter(raw)
            top = counts.most_common(16)
            lines = [f"0x{b:02x}={c} ({round(c/len(raw)*100,2)}%)" for b, c in top]
            # Entropy per 256-byte block + simple sparkline.
            blocks = []
            spark = []
            for i in range(0, len(raw), 256):
                blk = raw[i:i + 256]
                ent = _shannon_entropy(blk)
                blocks.append({"block_index": i // 256, "addr": hex(ea + i), "entropy": ent})
                lvl = min(7, max(0, int(round((ent / 8.0) * 7))))
                spark.append("▁▂▃▄▅▆▇█"[lvl])
            null_density = round(raw.count(0) / max(1, len(raw)), 4)
            return {"ok": True, "histogram": lines, "total_bytes": len(raw), "top5": lines[:5], "entropy_blocks": blocks[:512], "entropy_sparkline": "".join(spark[:512]), "null_density": null_density}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
