
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import math
import re
from collections import Counter

MAX_HEXDUMP_SIZE = 4096


# ============================================================================
# MEMORY - Read/Write/Search/Analyze operations
# ============================================================================

def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


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
    try:
        import ida_ida as _ida_ida
        if hasattr(_ida_ida, "inf_is_be"):
            return _ida_ida.inf_is_be()
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure()
        return inf.is_be() if hasattr(inf, "is_be") else False
    except Exception:
        return False


def _find_pointers(data, start_ea):
    """Find all valid pointers in a byte sequence."""
    is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100)
    ptr_size = 8 if is_64 else 4
    endian = ">" if _is_be() else "<"
    fmt = f"{endian}Q" if is_64 else f"{endian}I"
    import struct
    pointers = []
    for i in range(0, len(data) - ptr_size + 1, ptr_size):
        val = struct.unpack_from(fmt, data, i)[0]
        if val != 0 and idaapi.is_loaded(val):
            pointers.append((start_ea + i, hex(val), idc.get_name(val) or ""))
    return pointers


@tool
@idawrite
def memory(
    action: Annotated[Literal[
        "read", "write", "hexdump", "search", "compare", "pointers",
        "entropy", "strings", "struct_walk", "histogram"
    ], "Action: read|write|hexdump|search|compare|pointers|entropy|strings|struct_walk|histogram"],
    addr: Annotated[str, "Address"],
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"],
                    "Data type (for read)"] = "u32",
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
    try:
        ea, error = validate_addr(addr)
        if error:
            return error

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
                is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100)
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
            if not data:
                return make_error(MCPError.INVALID_ARGS, "data (pattern) required for search")
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            if end_ea <= ea:
                end_ea = ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            # Determine search mode
            pattern_bytes = None
            try:
                pattern_bytes = bytes.fromhex(data.replace(" ", ""))
            except ValueError:
                pass
            if pattern_bytes is None:
                pattern_bytes = data.encode("utf-8", errors="replace")
            hits = []
            idx = raw.find(pattern_bytes)
            while idx != -1:
                hits.append(hex(ea + idx))
                if len(hits) >= 100:
                    break
                idx = raw.find(pattern_bytes, idx + 1)
            return {"ok": True, "pattern": data, "hits": hits, "count": len(hits), "region": f"{hex(ea)}-{hex(ea + region_size)}"}

        elif action == "compare":
            if not end_addr:
                return make_error(MCPError.INVALID_ARGS, "end_addr required for compare")
            end_ea, err = validate_addr(end_addr)
            if err:
                return err
            size_a = size
            size_b = kwargs.get("size_b", size)
            raw_a = ida_bytes.get_bytes(ea, size_a)
            raw_b = ida_bytes.get_bytes(end_ea, size_b)
            if not raw_a or not raw_b:
                return make_error(MCPError.IDA_ERROR, "Could not read one or both regions")
            min_len = min(len(raw_a), len(raw_b))
            diffs = []
            for i in range(min_len):
                if raw_a[i] != raw_b[i]:
                    diffs.append(f"offset={i}  {hex(ea+i)}={raw_a[i]:02x}  {hex(end_ea+i)}={raw_b[i]:02x}")
            if len(raw_a) != len(raw_b):
                diffs.append(f"size_diff: A={len(raw_a)} B={len(raw_b)}")
            return {"ok": True, "diff_count": len(diffs), "diffs": diffs[:50], "same_prefix": raw_a[:min_len] == raw_b[:min_len]}

        elif action == "pointers":
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            ptrs = _find_pointers(raw, ea)
            lines = [f"{hex(addr)} -> {target}  {name}" for addr, target, name in ptrs[:100]]
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
            is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100)
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
                if val != 0 and idaapi.is_loaded(val) and level < depth:
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
            return {"ok": True, "histogram": lines, "total_bytes": len(raw)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
