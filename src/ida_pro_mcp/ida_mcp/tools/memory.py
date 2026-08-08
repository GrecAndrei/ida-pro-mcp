
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .governance_engine import evaluate_operation
except ImportError:
    from governance_engine import evaluate_operation  # type: ignore[import-not-found]

import re
from collections import Counter

MAX_HEXDUMP_SIZE = 4096

# ----------------------------------------------------------------------------
# Relocation (fixup) introspection
# ----------------------------------------------------------------------------

_FIXUP_MODULE_NAMES = None


def _fixup_name_map():
    """Reverse-map ida_fixup.FIXUP_* constants to names, cached per load.

    Builds the map from the live ida_fixup module so any IDA version's
    constants are covered without hardcoding an enum table here.
    """
    global _FIXUP_MODULE_NAMES
    if _FIXUP_MODULE_NAMES is None:
        names = {}
        try:
            for key in dir(ida_fixup):
                if not key.startswith("FIXUP_"):
                    continue
                value = getattr(ida_fixup, key)
                if isinstance(value, int):
                    names[value] = key
        except Exception:
            names = {}
        _FIXUP_MODULE_NAMES = names
    return _FIXUP_MODULE_NAMES


def _fixup_type_name(fixup_type):
    """Human-readable name for a fixup type, e.g. FIXUP_OFF32, FIXUP_REL32."""
    if not isinstance(fixup_type, int):
        return None
    name = _fixup_name_map().get(fixup_type)
    if name:
        return name
    # Coarse fallback for constants the running IDA build does not expose.
    if 0x00 <= fixup_type <= 0x0E:
        return "FIXUP_OFF_OR_PTR"
    if fixup_type == 0x42:
        return "FIXUP_REL32"
    return f"FIXUP_0x{fixup_type:x}"


def _fixup_info(ea):
    """Return relocation info for *ea* or None when no fixup exists there."""
    try:
        fdata = ida_fixup.fixup_data_t()
        if not ida_fixup.get_fixup(fdata, ea):
            return None
        info: dict[str, Any] = {"relocation": True}
        ftype = getattr(fdata, "type", None)
        if isinstance(ftype, int):
            info["fixup_type"] = ftype
            info["fixup_name"] = _fixup_type_name(ftype)
        for attr in ("base", "off", "displacement"):
            value = getattr(fdata, attr, None)
            if isinstance(value, int) and value:
                info[f"fixup_{attr}"] = value
        return info
    except Exception:
        return None


# ============================================================================
# MEMORY - Read/Write/Search/Analyze operations
# ============================================================================

try:
    from ._common import shannon_entropy as _shannon_entropy
except ImportError:
    from _common import shannon_entropy as _shannon_entropy  # type: ignore[import-not-found]


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


def _find_pointers(data, start_ea):
    """Find all valid pointers in a byte sequence."""
    is_64 = _inf_bitness() == 64
    ptr_size = 8 if is_64 else 4
    endian = ">" if _inf_is_be() else "<"
    fmt = f"{endian}Q" if is_64 else f"{endian}I"
    import struct
    pointers = []
    for i in range(0, len(data) - ptr_size + 1, ptr_size):
        val = struct.unpack_from(fmt, data, i)[0]
        if val != 0 and ida_bytes.is_loaded(val):
            entry = {"offset": i, "target_addr": hex(val), "target_name": idc.get_name(val) or ""}
            # The slot itself may be a relocation (fixup): the value stored
            # here is what the loader will patch at runtime, not a real
            # address — flag it so downstream analysis does not trust it.
            fixup = _fixup_info(start_ea + i)
            if fixup:
                entry["relocation"] = True
                entry["fixup_name"] = fixup.get("fixup_name")
            pointers.append(entry)
    return pointers


def _write_governance_metadata(ea):
    """Gather section metadata so memory(write) honors the same deterministic
    patch governance that modify(patch_bytes) runs by default.

    Mirrors modify.py's patch branch: executable/code sections are flagged as
    control-flow modifications and import sections are tagged for the
    import-table guard.
    """
    metadata = {}
    seg = ida_segment.getseg(ea)
    if seg:
        sname = ida_segment.get_segm_name(seg)
        metadata["section_type"] = sname or ""
        metadata["is_import_addr"] = sname in (".idata", ".plt", ".edata", ".iat")
        executable = (getattr(seg, "perm", 0) & getattr(ida_segment, "SEGPERM_X", 1)) != 0
        if executable or sname in (".text", ".code"):
            metadata["modifies_control_flow"] = True
    return metadata


@tool
@idawrite
def memory(
    action: Annotated[Literal[
        "read", "write", "hexdump", "search", "compare", "pointers",
        "entropy", "strings", "struct_walk", "histogram"
    ], "Action: read|write|hexdump|search|compare|pointers|entropy|strings|struct_walk|histogram"],
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
    - addr: Address to read/write/search. For search with no addr, auto-fills from IDB minimum address with a 64KB window.
    - type: Data type for read (u8/u16/u32/u64, s8/s16/s32/s64, f32/f64, ptr, bytes, string). Default 'bytes'.
    - size: Number of bytes to read (only for type='bytes' or action='hexdump'). Default 16.
    - data: Hex string to write (e.g. "90 90 90") REQUIRED for write; search pattern for search.
    - end_addr: End address for region-based actions (search, compare, pointers, entropy, strings, histogram).
    - depth: Max recursion depth for struct_walk.
    - **kwargs: search supports regex (bool), literal (bool — bypass integer detection), int_width (int, default 4);
      write supports governed (bool, default True — run deterministic governance pre-check on patch).
    """
    result = _memory_impl(action, addr, type, size, data, end_addr, depth, **kwargs)
    return result


def _memory_impl(action, addr, type, size, data, end_addr, depth, **kwargs) -> dict:
    try:
        # Coerce numeric params that may arrive as strings from JSON-RPC
        try:
            size = int(size)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, f"size must be an integer, got {type(size).__name__}",
                              hint="Provide size as an integer, e.g. size=16")
        try:
            depth = int(depth)
        except (TypeError, ValueError):
            depth = 2

        ea = None
        if addr is not None and str(addr).strip() != "":
            ea, error = validate_addr(str(addr))
            if error:
                return error

        # compare is the one non-search action that can legitimately run without
        # a single `addr` (it takes addr1/addr2 instead); let its own branch
        # validate the region endpoints.
        if action not in ("search", "compare") and ea is None:
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
                endian = ">" if _inf_is_be() else "<"
                value = struct.unpack(f"{endian}f", raw)[0]
            elif type == "f64":
                raw = ida_bytes.get_bytes(ea, 8)
                if not raw:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read 8 bytes from {hex(ea)}")
                import struct
                endian = ">" if _inf_is_be() else "<"
                value = struct.unpack(f"{endian}d", raw)[0]
            elif type == "ptr":
                is_64 = _inf_bitness() == 64
                value = ida_bytes.get_qword(ea) if is_64 else ida_bytes.get_wide_dword(ea)
            elif type == "string":
                try:
                    s = idc.get_strlit_contents(ea, -1, 0)
                except TypeError:
                    # Signature varies across IDA 7.x–9.x; fall back to the
                    # single-argument form like data.py's strings action.
                    s = idc.get_strlit_contents(ea)
                if s:
                    if isinstance(s, bytes):
                        if len(s) > 65536:
                            s = s[:65536]
                        value = s.decode("utf-8", errors="replace")
                    else:
                        value = s[:65536] if len(s) > 65536 else s
                else:
                    return make_error(MCPError.ADDRESS_INVALID, f"No string found at {hex(ea)}")
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
            # Deterministic governance pre-check — the same layer modify(patch_bytes)
            # runs by default. Without it memory(write) could silently patch an
            # executable/import section that the sibling tool would block.
            if kwargs.get("governed", True):
                gov_result = evaluate_operation(
                    operation_type="patch",
                    addr=ea,
                    proposed_value=data,
                    context={"tool": "memory", "action": "write"},
                    metadata=_write_governance_metadata(ea),
                )
                if not gov_result["approved"]:
                    return make_error(
                        MCPError.GOVERNANCE_BLOCKED,
                        f"Governance blocked write: {gov_result['verdict']}",
                        details={
                            "violations": gov_result["violations"],
                            "ontology_class": gov_result.get("ontology_class"),
                            "axiom_score": gov_result.get("axiom_score"),
                        },
                    )
            # patch_bytes returns the count of bytes actually patched (0 on a
            # failed/read-only byte); surface a partial write instead of
            # reporting the requested size as success.
            written = ida_bytes.patch_bytes(ea, bytes_data)
            if written != len(bytes_data):
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Patch failed at {hex(ea)}: wrote {written} of {len(bytes_data)} byte(s)",
                    details={"requested": len(bytes_data), "written": written},
                )
            return {
                "ok": True,
                "addr": addr,
                "size": written,
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
            region_capped = (end_ea - ea) > 1024 * 1024
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            # Determine search mode: hex-with-wildcards, regex on ascii, or integer literal.
            pattern_bytes = None
            wildcard_mask = None
            regex_mode = bool(kwargs.get("regex", False))
            literal_mode = bool(kwargs.get("literal", False))
            int_mode = False
            try:
                if not literal_mode and re.fullmatch(r"0x[0-9a-fA-F]+|\d+", pattern):
                    int_mode = True
                    v = int(pattern, 0)
                    width = int(kwargs.get("int_width", 4) or 4)
                    if width <= 0:
                        return make_error(MCPError.INVALID_ARGS, "int_width must be positive")
                    endian = "big" if _inf_is_be() else "little"
                    try:
                        pattern_bytes = int(v).to_bytes(width, endian, signed=False)
                    except OverflowError:
                        # Value wider than the requested width (the common case
                        # is a 64-bit pointer with default int_width=4). Widen
                        # to the pointer size when it fits there so a full-width
                        # pointer search matches; otherwise reject loudly instead
                        # of silently degrading to a UTF-8 text search that
                        # reports a wrong 0-hit result.
                        ptr_width = max(1, _inf_bitness() // 8)
                        if width < ptr_width and v < (1 << (8 * ptr_width)):
                            width = ptr_width
                            pattern_bytes = int(v).to_bytes(width, endian, signed=False)
                        else:
                            return make_error(
                                MCPError.INVALID_ARGS,
                                f"Integer search value {pattern} does not fit in {width} byte(s)",
                                hint=f"Pass int_width={ptr_width} to search full-width ({ptr_width}-byte) values, or use a hex byte pattern",
                            )
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
                # Use IDA's native bin_search for hex patterns with wildcards
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    try:
                        pt = ida_bytes.compiled_binpat_vec_t()
                        # Convert pattern to IDA format: "4D 5A ?? 00"
                        ida_pat = " ".join(
                            "??" if not wildcard_mask[i] else f"{pattern_bytes[i]:02x}"
                            for i in range(len(pattern_bytes))
                        )
                        err = ida_bytes.parse_binpat_str(pt, ea, ida_pat, 16)
                        if not err:
                            search_ea = ea
                            while search_ea < ea + region_size:
                                found_ea, _ = ida_bytes.bin_search(search_ea, ea + region_size, pt, ida_bytes.BIN_SEARCH_FORWARD)
                                if found_ea == idaapi.BADADDR:
                                    break
                                hits.append(hex(found_ea))
                                if len(hits) >= 256:
                                    break
                                search_ea = found_ea + 1
                        else:
                            # Fallback to Python loop
                            plen = len(pattern_bytes)
                            for i in range(max(0, len(raw) - plen + 1)):
                                ok = True
                                for j in range(plen):
                                    if wildcard_mask[j] and raw[i + j] != pattern_bytes[j]:
                                        ok = False
                                        break
                                if ok:
                                    hits.append(hex(ea + i))
                                    if len(hits) >= 256:
                                        break
                    except Exception:
                        # Fallback to Python loop
                        plen = len(pattern_bytes)
                        for i in range(max(0, len(raw) - plen + 1)):
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
                    plen = len(pattern_bytes)
                    for i in range(max(0, len(raw) - plen + 1)):
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
            return {"ok": True, "pattern": pattern, "hits": hits, "count": len(hits), "region": f"{hex(ea)}-{hex(ea + region_size)}", "region_capped": region_capped, "hits_capped": len(hits) >= 256, "mode": ("regex" if regex_mode else ("integer" if int_mode else ("hex_wildcard" if wildcard_mask is not None else "bytes")))}

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
            cmp_size = min(cmp_size, max_cmp)
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
            # Hamming distance fallback for large compares (true Levenshtein is O(n*m)).
            if len(raw_a) * len(raw_b) > 4_000_000:
                hamming = sum(1 for i in range(min_len) if raw_a[i] != raw_b[i]) + abs(len(raw_a) - len(raw_b))
                similarity = round(100.0 * (1.0 - (hamming / max(1, len(raw_a), len(raw_b)))), 2)
                return {"ok": True, "addr1": hex(ea1), "addr2": hex(ea2), "size": cmp_size, "diff_count": len(diffs), "diffs": diffs[:256], "hamming_distance": int(hamming), "similarity_pct": similarity, "size_capped": cmp_size == max_cmp, "note": "Large compare: hamming distance used (exact Levenshtein is O(n*m))."}
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
                similarity = round(100.0 * (1.0 - (edit_distance / max(1, len(raw_a), len(raw_b)))), 2)
                return {"ok": True, "addr1": hex(ea1), "addr2": hex(ea2), "size": cmp_size, "diff_count": len(diffs), "diffs": diffs[:256], "edit_distance": int(edit_distance), "similarity_pct": similarity, "size_capped": cmp_size == max_cmp}

        elif action == "pointers":
            end_ea = parse_address(end_addr) if end_addr else ea + 0x10000
            region_size = min(end_ea - ea, 1024 * 1024)
            raw = ida_bytes.get_bytes(ea, region_size)
            if not raw:
                return make_error(MCPError.IDA_ERROR, f"Could not read region starting at {hex(ea)}")
            ptrs = _find_pointers(raw, ea)
            lines = ptrs[:256]
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
            endian = ">" if _inf_is_be() else "<"
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
                node = {"level": level, "addr": hex(cur_ea), "points_to": hex(val), "name": name}
                # Add type info from ida_typeinf
                try:
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, val) or ida_nalt.get_tinfo(tif, cur_ea):
                        node["type"] = str(tif)
                except Exception:
                    pass
                # Check if pointer target is a relocation
                fixup = _fixup_info(cur_ea)
                if fixup:
                    node.update(fixup)
                nodes.append(node)
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
