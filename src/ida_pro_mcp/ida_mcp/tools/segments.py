"""
Segment management tool for IDA Pro MCP.

Actions: list, info, add, delete, set_attr, set_perms, move,
         analyze, find_code, find_data, compare, merge,
         sreg_get, sreg_set, sreg_list (segment-register seam)
"""

import math
from collections import Counter

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

# _common does not re-export parse_address_safe (not in its __all__); import it
# here so add/delete/move can accept unmapped destination addresses. Tried in
# the three layouts this module is loaded under: IDA plugin package mode,
# the host unit-test loader, and standalone IDA mode.
try:
    from ida_mcp.error_handling import parse_address_safe
except ImportError:
    try:
        from ida_pro_mcp.ida_mcp.error_handling import parse_address_safe
    except ImportError:
        from error_handling import parse_address_safe  # type: ignore[import-not-found]

# ida_segregs / ida_idp are only present in a live IDA process and are not
# re-exported by _common. Guard the imports so the module still loads in the
# host unit-test harness; the sreg actions degrade to a clear error when the
# runtime lacks them. Tests inject fake modules via sys.modules before loading.
try:
    import ida_idp  # noqa: F401
except ImportError:
    ida_idp = None  # type: ignore[assignment]

try:
    import ida_segregs  # noqa: F401
except ImportError:
    ida_segregs = None  # type: ignore[assignment]


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================


def _find_segment(start=None, name=None):
    """Locate a segment by address or name. Returns (seg, error_dict)."""
    if start:
        s_ea, err = validate_addr(start)
        if err:
            return None, err
        seg = idaapi.getseg(s_ea)
        if not seg:
            return None, make_error(MCPError.SEGMENT_NOT_FOUND,
                                    f"No segment at address {start}")
        return seg, None
    if name:
        for ea in idautils.Segments():
            s = idaapi.getseg(ea)
            if s and _compat.get_segment_name(ea) == name:
                return s, None
        return None, make_error(MCPError.SEGMENT_NOT_FOUND,
                                f"Segment named '{name}' not found")
    return None, make_error(MCPError.INVALID_ARGS,
                            "Specify 'start' (address) or 'name' to identify a segment")


def _perms_string(seg):
    """Build human-readable permission string from a segment object."""
    perms = ""
    if seg.perm & idaapi.SEGPERM_READ:
        perms += "r"
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms += "w"
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms += "x"
    return perms or "---"


def _seg_type_name(seg):
    """Resolve segment type to a readable name (IDA 9 compatible)."""
    seg_types = {}
    for attr_name, type_name in [
        ("SEG_CODE", "code"), ("SEG_DATA", "data"),
        ("SEG_BSS", "bss"), ("SEG_STACK", "stack"),
        ("SEG_XTRN", "extern"), ("SEG_NULL", "null"),
        ("SEG_NORM", "normal"), ("SEG_ABS", "absolute"),
    ]:
        if hasattr(ida_segment, attr_name):
            seg_types[getattr(ida_segment, attr_name)] = type_name
    return seg_types.get(seg.type, f"type_{seg.type}")


def _count_heads(seg, max_items=500000):
    """Count code heads, data heads, strings, and functions in a segment."""
    code_count = data_count = string_count = func_count = 0
    head = seg.start_ea
    iterations = 0
    while head < seg.end_ea:
        flags = ida_bytes.get_flags(head)
        if ida_bytes.is_code(flags):
            code_count += 1
        elif ida_bytes.is_data(flags):
            data_count += 1
        if ida_bytes.is_strlit(flags):
            string_count += 1
        head = idc.next_head(head, seg.end_ea)
        if head == idaapi.BADADDR:
            break
        iterations += 1
        if iterations >= max_items:
            break
    for _ in idautils.Functions(seg.start_ea, seg.end_ea):
        func_count += 1
    return code_count, data_count, string_count, func_count


def _seg_entropy(seg):
    """Compute Shannon entropy for a segment's raw bytes."""
    length = seg.end_ea - seg.start_ea
    if length <= 0:
        return 0.0
    data = ida_bytes.get_bytes(seg.start_ea, length)
    if not data:
        return 0.0
    occ = Counter(data)
    ent = 0.0
    for count in occ.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return round(ent, 4)


def _seg_import_count(seg):
    """Count imported functions whose thunk addresses fall within the segment."""
    count = 0
    for mod_idx in range(ida_nalt.get_import_module_qty()):
        def _cb(ea, name, ordinal):
            nonlocal count
            if seg.start_ea <= ea < seg.end_ea:
                count += 1
            return True  # keep enumerating; a falsy return stops the walk
        ida_nalt.enum_import_names(mod_idx, _cb)
    return count


def _strlit_value(head):
    """Decode a string literal to a JSON-safe str (empty when unreadable)."""
    val = idc.get_strlit_contents(head, -1, ida_nalt.STRTYPE_C)
    if not val:
        return ""
    try:
        return val.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, AttributeError):
        return repr(val)


def _seg_density_analysis(seg):
    """Return a dict of density metrics for a segment."""
    size = seg.end_ea - seg.start_ea
    size_kb = size / 1024.0 if size else 0.0

    code_count, data_count, string_count, func_count = _count_heads(seg)
    import_count = _seg_import_count(seg)
    entropy = _seg_entropy(seg)

    def _per_kb(val):
        return round(val / size_kb, 2) if size_kb > 0 else 0.0

    # Use the JSON-safe sentinel "inf" instead of float("inf"): a code-only
    # segment would otherwise emit Infinity, which breaks strict JSON-RPC.
    code_data_ratio = round(code_count / data_count, 2) if data_count else ("inf" if code_count else 0.0)

    return {
        "name": _compat.get_segment_name(seg.start_ea),
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": size,
        "size_kb": round(size_kb, 2),
        "entropy": entropy,
        "string_density_per_kb": _per_kb(string_count),
        "import_density_per_kb": _per_kb(import_count),
        "function_density_per_kb": _per_kb(func_count),
        "code_data_ratio": code_data_ratio,
        "string_count": string_count,
        "import_count": import_count,
        "function_count": func_count,
        "code_heads": code_count,
        "data_heads": data_count,
    }


# ============================================================================
# 11b. SEGMENT REGISTERS - ida_segregs seam (Thumb T, RISC-V GP, x86-16 CS/DS)
# ============================================================================
# Public sr_type labels map onto the sreg range tag stored by IDA:
#   signed/unsigned  -> SR_user  (an explicit, user-specified value)
#   default          -> SR_inherit (inherit the value of the previous range)
#   auto             -> SR_auto   (let IDA determine the value)
# Modern IDA stores no per-range signedness bit; "signed" and "unsigned" are
# accepted for contract parity and both write an explicit user value.

_SREG_TYPES = ("signed", "unsigned", "default", "auto")


def _resolve_sreg(reg):
    """Resolve a segment-register name (e.g. 'T', 'GP', 'CS') or number to its IDA index.

    Returns an int register index, or None when the register cannot be resolved.
    """
    if reg is None or isinstance(reg, bool):
        return None
    if isinstance(reg, int):
        return reg
    if ida_idp is not None and hasattr(ida_idp, "str2reg"):
        try:
            sr = int(ida_idp.str2reg(str(reg)))
            if sr >= 0:
                return sr
        except (ValueError, TypeError):
            pass
    try:
        return int(str(reg), 0)
    except (ValueError, TypeError):
        return None


def _sreg_name(sr):
    """Return the display name for a segment-register index from the processor table."""
    if ida_idp is not None:
        ph = getattr(ida_idp, "ph", None)
        if ph is not None:
            try:
                reg_names = getattr(ph, "reg_names", None) or []
                idx = int(sr)
                if 0 <= idx < len(reg_names) and reg_names[idx]:
                    return str(reg_names[idx])
            except (ValueError, TypeError, IndexError):
                pass
    return str(sr)


def _sreg_reg_indices():
    """Return the inclusive (first, last) segment-register index range, or None."""
    if ida_idp is None:
        return None
    ph = getattr(ida_idp, "ph", None)
    if ph is None:
        return None
    try:
        first = int(getattr(ph, "reg_first_sreg", 0) or 0)
        last = int(getattr(ph, "reg_last_sreg", 0) or 0)
    except (ValueError, TypeError):
        return None
    if last < first or first < 0:
        return None
    return (first, last)


def _sreg_tag_name(tag):
    """Map an sreg range tag (SR_inherit/SR_user/SR_auto) to the public sr_type label."""
    if ida_segregs is None:
        return "signed"
    if tag == getattr(ida_segregs, "SR_inherit", 0):
        return "default"
    if tag == getattr(ida_segregs, "SR_auto", 2):
        return "auto"
    return "signed"  # SR_user -> an explicit user-specified value


def _sreg_tag_for_type(sr_type):
    """Map the public sr_type label to the split_sreg_range tag to store."""
    if ida_segregs is None:
        return 0
    if sr_type == "default":
        return getattr(ida_segregs, "SR_inherit", 0)
    if sr_type == "auto":
        return getattr(ida_segregs, "SR_auto", 2)
    return getattr(ida_segregs, "SR_user", 1)  # signed/unsigned -> explicit user value


def _sreg_ranges_for_register(seg_start, seg_end, sr):
    """Enumerate the sreg ranges of one register overlapping [seg_start, seg_end)."""
    ranges = []
    try:
        qty = int(ida_segregs.get_sreg_ranges_qty(sr))
    except Exception:
        return ranges
    for n in range(qty):
        out = ida_segregs.sreg_range_t()
        try:
            ok = ida_segregs.getn_sreg_range(out, sr, n)
        except Exception:
            continue
        if not ok:
            continue
        start = getattr(out, "start_ea", None)
        end = getattr(out, "end_ea", None)
        if start is None or end is None:
            continue
        if end <= seg_start or start >= seg_end:
            continue
        ranges.append(out)
    return ranges


def _sreg_range_record(sr, srange):
    """Build the public {reg, value, sr_type, start, end} record for one sreg range."""
    return {
        "reg": _sreg_name(sr),
        "value": getattr(srange, "val", None),
        "sr_type": _sreg_tag_name(getattr(srange, "tag", None)),
        "start": hex(getattr(srange, "start_ea", 0)),
        "end": hex(getattr(srange, "end_ea", 0)),
    }


@tool
@idawrite
def segments(
    action: Annotated[Literal["list", "add", "delete", "set_attr", "set_perms", "move",
                              "info", "analyze", "find_code", "find_data", "compare", "merge",
                              "sreg_get", "sreg_set", "sreg_list"],
                      "Action: list|add|delete|set_attr|set_perms|move|info|analyze|find_code|find_data|compare|merge|sreg_get|sreg_set|sreg_list"],
    start: Annotated[Optional[str], "Start address (src for move); or segment address for info/analyze/find_code/find_data/sreg_get/sreg_set/sreg_list"] = None,
    end: Annotated[Optional[str], "End address (dst for move); or second address for compare"] = None,
    name: Annotated[Optional[str], "Segment name"] = None,
    name2: Annotated[Optional[str], "Second segment name (for compare)"] = None,
    sclass: Annotated[str, "Segment class"] = "DATA",
    attr: Annotated[Optional[str], "Attribute name (for set_attr)"] = None,
    value: Annotated[Optional[Union[str, int]], "Attribute value (for set_attr / set_perms) or segment-register value (for sreg_set)"] = None,
    reg: Annotated[Optional[Union[str, int]], "Segment register name (e.g. 'T', 'GP', 'CS', 'DS') or number — for sreg_get/sreg_set/sreg_list"] = None,
    sr_type: Annotated[str, "Signedness for sreg_set: 'signed' (default), 'unsigned', 'default', or 'auto'"] = "signed",
    offset: Annotated[int, "Pagination offset (for list)"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    **kwargs
) -> dict:
    """
    Manage binary segments — list, inspect, modify, and analyze.

    ====== EXISTING ACTIONS ======

    list — List all segments with basic info
        Params: offset, count (for pagination)
        Returns: {segments: [{name, start, end, size, perms}]}

    info — Detailed information about a specific segment
        Params: start (address) or name
        Returns: {segment: {name, start, end, size, perms, class, type, align,
                            bitness, code_heads, data_heads, functions, strings}}

    add — Create a new segment
        Params: start, end, name, sclass
        Returns: {ok, start, end}

    delete — Delete a segment
        Params: start (address within segment)
        Returns: {ok, start}

    set_attr — Update segment metadata
        Params: start, attr, value
        Available attrs: name, align, comb, perm, bitness, type, color
        Returns: {ok, attr, value}

    set_perms — Set segment permissions
        Params: start, value ("rwx" string or integer)
        Returns: {ok, perms}

    move — Relocate a segment
        Params: start (current), end (new start address)
        Returns: {ok, old, new}

    ====== NEW ACTIONS ======

    analyze — Compute entropy, string/import/function density, code/data ratio per segment
        Params: start or name (optional — if omitted, analyzes all segments)
        Returns: {segments: [{name, entropy, string_density_per_kb, import_density_per_kb,
                              function_density_per_kb, code_data_ratio, ...}]}

    find_code — List all functions in a segment with their sizes
        Params: start or name
        Returns: {segment, functions: [{addr, name, size}]}

    find_data — List all data items / strings in a segment
        Params: start or name
        Returns: {segment, data_items: [{addr, size, type, value}], strings: [{addr, value}]}

    compare — Compare two segments by name or address
        Params: start + end (addresses) or name + name2
        Returns: {segment_a: {...}, segment_b: {...}, differences: {...}}

    merge — Merge analysis results across all segments into a summary table
        Params: (none)
        Returns: {segments: [...], totals: {total_size, avg_entropy, ...}}

    ====== SEGMENT-REGISTER ACTIONS (ida_segregs seam) ======

    sreg_get — Read one segment register at an address (Thumb T, RISC-V GP, x86-16 CS/DS)
        Params: start (address), reg (register name or number)
        Returns: {address, reg, value, sr_type, range: {start, end}}
        value is BADSEL when the register is undefined at that address.

    sreg_set — Write one segment register at an address (governed write, mirrors set_attr)
        Params: start (address), reg (register name or number), value (int),
                sr_type ('signed'|'unsigned'|'default'|'auto', default 'signed')
        Returns: {address, reg, value, sr_type}
        sr_type maps to the IDA range tag: signed/unsigned -> SR_user (explicit
        value), default -> SR_inherit, auto -> SR_auto.

    sreg_list — Enumerate segment-register ranges overlapping the segment containing `start`
        Params: start (address), reg (optional filter — omit to list all segment registers)
        Returns: {segment, reg, ranges: [{reg, value, sr_type, start, end}], count}
    """
    try:
        # Normalize common direct-call aliases even before the MCP server's
        # argument mapper runs. This keeps the tool usable in unit tests and
        # from ad-hoc IDAPython calls.
        if start is None:
            start = kwargs.get("address") or kwargs.get("addr") or kwargs.get("ea") or kwargs.get("segment")
        if end is None:
            end = kwargs.get("address2") or kwargs.get("addr2") or kwargs.get("ea2") or kwargs.get("segment2")
        if name is None:
            name = kwargs.get("segment_name")
        if name2 is None:
            name2 = kwargs.get("segment_name2")

        # ------------------------------------------------------------------
        # LIST
        # ------------------------------------------------------------------
        if action == "list":
            results = []
            total = 0
            for ea in idautils.Segments():
                seg = idaapi.getseg(ea)
                if seg:
                    total += 1
                    if total > offset and (count == 0 or len(results) < count):
                        results.append({
                            "name": _compat.get_segment_name(ea),
                            "address": hex(seg.start_ea),
                            "start": hex(seg.start_ea),
                            "end_address": hex(seg.end_ea),
                            "end": hex(seg.end_ea),
                            "size": hex(seg.end_ea - seg.start_ea),
                            "perms": _perms_string(seg),
                            "class": _compat.get_segment_class(ea),
                        })
            return {
                "ok": True,
                "segments": results,
                "total": total,
                "offset": offset,
                "count": len(results),
            }

        # ------------------------------------------------------------------
        # INFO
        # ------------------------------------------------------------------
        elif action == "info":
            seg, err = _find_segment(start, name)
            if err:
                return err

            perms = _perms_string(seg)
            seg_type = _seg_type_name(seg)
            code_count, data_count, string_count, func_count = _count_heads(seg)

            return {
                "ok": True,
                "segment": {
                    "name": _compat.get_segment_name(seg.start_ea),
                    "address": hex(seg.start_ea),
                    "start": hex(seg.start_ea),
                    "end_address": hex(seg.end_ea),
                    "end": hex(seg.end_ea),
                    "size": hex(seg.end_ea - seg.start_ea),
                    "size_bytes": seg.end_ea - seg.start_ea,
                    "perms": perms,
                    "perms_int": seg.perm,
                    "class": _compat.get_segment_class(seg.start_ea),
                    "type": seg_type,
                    "type_int": seg.type,
                    "align": seg.align,
                    "bitness": {0: 16, 1: 32, 2: 64}.get(seg.bitness, seg.bitness * 16),
                    "comb": seg.comb,
                    "color": hex(seg.color) if seg.color != 0xFFFFFFFF else None,
                    "code_heads": code_count,
                    "data_heads": data_count,
                    "functions": func_count,
                    "strings": string_count,
                },
            }

        # ------------------------------------------------------------------
        # ADD
        # ------------------------------------------------------------------
        elif action == "add":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' is required to specify the beginning address of the new segment")
            if not end:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'end' is required to specify the ending address of the new segment")
            s_ea, err = parse_address_safe(start)
            if err:
                return err
            e_ea, err = parse_address_safe(end)
            if err:
                return err
            if s_ea >= e_ea:
                return make_error(MCPError.INVALID_ARGS,
                                  f"start ({hex(s_ea)}) must be less than end ({hex(e_ea)})")

            # Check for existing segment overlap
            existing = idaapi.getseg(s_ea)
            if existing:
                return make_error(MCPError.SEGMENT_OVERLAP,
                                  f"Address {hex(s_ea)} already belongs to segment "
                                  f"'{_compat.get_segment_name(s_ea)}'")

            seg = idaapi.segment_t()
            seg.start_ea, seg.end_ea = s_ea, e_ea
            # add_segm_ex leaves seg.perm at 0 unless the loader set it, which
            # silently makes analysis treat a CODE segment as data (no EXEC on
            # raw blobs).  Derive permissions from the segment class so a code
            # segment added to an opaque .bin is actually analyzed as code.
            perm = getattr(idaapi, "SEGPERM_READ", 1)
            sclass_upper = str(sclass or "").upper()
            if sclass_upper in ("CODE", "XTRN"):
                perm |= getattr(idaapi, "SEGPERM_EXEC", 4)
            elif sclass_upper == "BSS":
                perm |= getattr(idaapi, "SEGPERM_WRITE", 2)
            seg.perm = perm
            if idaapi.add_segm_ex(seg, name or "", sclass, 0):
                result = {"ok": True, "start": hex(s_ea), "end": hex(e_ea), "name": name, "class": sclass}
                if sclass_upper in ("CODE", "XTRN"):
                    result["perms"] = _perms_string(seg)
                    result["note"] = (
                        "Segment permissions set to READ|EXEC from sclass. "
                        "If code is still misread as data, run segments(action='set_perms', ...)."
                    )
                elif not sclass_upper:
                    result["note"] = (
                        "Run segments(action='set_perms', ...) to set explicit permissions."
                    )
                return result
            return make_error(MCPError.IDA_ERROR,
                              f"Failed to add segment '{name or ''}' at {hex(s_ea)}-{hex(e_ea)}")

        # ------------------------------------------------------------------
        # DELETE
        # ------------------------------------------------------------------
        elif action == "delete":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' is required — provide any address inside the segment to delete")
            s_ea, err = parse_address_safe(start)
            if err:
                return err
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment found at address {start}")
            seg_name = _compat.get_segment_name(s_ea)
            if idaapi.del_segm(s_ea, idaapi.SEGMOD_KILL):
                return {"ok": True, "start": hex(s_ea), "name": seg_name}
            return make_error(MCPError.IDA_ERROR,
                              f"Failed to delete segment '{seg_name}' at {hex(s_ea)}")

        # ------------------------------------------------------------------
        # SET_ATTR
        # ------------------------------------------------------------------
        elif action == "set_attr":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' is required")
            if not attr:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'attr' is required — one of: name, align, comb, perm, bitness, type, color")
            if value is None:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'value' is required — the new value for the attribute")
            s_ea, err = validate_addr(start)
            if err:
                return err
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at address {start}")

            valid_attrs = {"name", "align", "comb", "perm", "bitness", "type", "color"}
            if attr not in valid_attrs:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Unknown attribute '{attr}'. Valid attributes: {', '.join(sorted(valid_attrs))}")

            if attr == "name":
                if not _compat.set_segment_name(s_ea, str(value)):
                    return make_error(MCPError.IDA_ERROR,
                                      f"Failed to rename segment to '{value}'")
            elif hasattr(seg, attr):
                try:
                    # Convert string values to int for numeric attributes
                    if isinstance(value, str):
                        int_val = int(value, 0)  # handles "0x1F", "31", "0b11" etc.
                    else:
                        int_val = int(value)
                    setattr(seg, attr, int_val)
                except (ValueError, TypeError):
                    return make_error(MCPError.INVALID_ARG_TYPE,
                                      f"Cannot set attribute '{attr}' to value '{value}'")
            else:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Segment object has no attribute '{attr}'")

            idaapi.update_segm(seg)
            return {"ok": True, "start": hex(s_ea), "attr": attr, "value": value}

        # ------------------------------------------------------------------
        # SET_PERMS
        # ------------------------------------------------------------------
        elif action == "set_perms":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' is required")
            if value is None:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'value' is required — use a permission string like 'rwx' or an integer bitmap")
            s_ea, err = validate_addr(start)
            if err:
                return err
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at address {start}")

            if isinstance(value, str):
                perms = 0
                v = value.lower()
                if "r" in v:
                    perms |= idaapi.SEGPERM_READ
                if "w" in v:
                    perms |= idaapi.SEGPERM_WRITE
                if "x" in v:
                    perms |= idaapi.SEGPERM_EXEC
                seg.perm = perms
            else:
                seg.perm = int(value)

            idaapi.update_segm(seg)
            return {
                "ok": True,
                "start": hex(s_ea),
                "perms": _perms_string(seg),
                "perms_int": seg.perm,
            }

        # ------------------------------------------------------------------
        # MOVE
        # ------------------------------------------------------------------
        elif action == "move":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' is required — the current start address of the segment to move")
            if not end:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'end' is required — the desired new start address for the segment")
            s_ea, err = validate_addr(start)
            if err:
                return err
            # Destination is typically a free/unmapped region (making room,
            # compaction), so only parse it — validate_addr's is_mapped check
            # would reject the primary use case of move_segm.
            t_ea, err = parse_address_safe(end)
            if err:
                return err

            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at source address {start}")

            result = idaapi.move_segm(seg, t_ea, 0)
            if result == idaapi.MOVE_SEGM_OK:
                return {"ok": True, "old": hex(s_ea), "new": hex(t_ea)}

            move_errors = {
                idaapi.MOVE_SEGM_PARAM: "Invalid parameters",
                idaapi.MOVE_SEGM_ROOM: "Not enough room at destination",
                idaapi.MOVE_SEGM_IDP: "Processor module forbids move",
                idaapi.MOVE_SEGM_CHUNK: "Cannot move chunked function",
                idaapi.MOVE_SEGM_LOADER: "Loader forbids move",
                idaapi.MOVE_SEGM_ODD: "Odd segment boundaries",
                idaapi.MOVE_SEGM_ORPHAN: "Would create orphan bytes",
            }
            error_msg = move_errors.get(result, f"Unknown error code: {result}")
            return make_error(MCPError.IDA_ERROR,
                              f"Failed to move segment: {error_msg}")

        # ------------------------------------------------------------------
        # SREG_GET — read one segment register (Thumb T, RISC-V GP, x86-16 CS/DS)
        # ------------------------------------------------------------------
        elif action == "sreg_get":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' (address) is required for sreg_get")
            if reg is None or reg == "":
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'reg' (segment register, e.g. 'T', 'GP', 'CS') is required for sreg_get")
            if ida_segregs is None:
                return make_error(MCPError.IDA_ERROR,
                                  "ida_segregs is unavailable in this runtime")
            s_ea, err = validate_addr(start)
            if err:
                return err
            sr = _resolve_sreg(reg)
            if sr is None:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Unknown segment register '{reg}'. Use a name like 'T', 'GP', 'CS' or a register number.")
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at address {start}")
            value = ida_segregs.get_sreg(s_ea, sr)
            srange = ida_segregs.sreg_range_t()
            range_info = None
            try:
                if ida_segregs.get_sreg_range(srange, s_ea, sr):
                    range_info = {
                        "start": hex(srange.start_ea),
                        "end": hex(srange.end_ea),
                    }
            except Exception:
                range_info = None
            result = {
                "ok": True,
                "address": hex(s_ea),
                "reg": _sreg_name(sr),
                "value": value,
                "sr_type": _sreg_tag_name(getattr(srange, "tag", None)) if range_info else "default",
            }
            if range_info is not None:
                result["range"] = range_info
            return result

        # ------------------------------------------------------------------
        # SREG_SET — write one segment register (governed write; mirrors set_attr)
        # ------------------------------------------------------------------
        elif action == "sreg_set":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' (address) is required for sreg_set")
            if reg is None or reg == "":
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'reg' (segment register, e.g. 'T', 'GP', 'CS') is required for sreg_set")
            if value is None:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'value' is required for sreg_set")
            if sr_type not in _SREG_TYPES:
                return make_error(MCPError.INVALID_ARGS,
                                  f"sr_type must be one of: {', '.join(_SREG_TYPES)}")
            if ida_segregs is None:
                return make_error(MCPError.IDA_ERROR,
                                  "ida_segregs is unavailable in this runtime")
            s_ea, err = validate_addr(start)
            if err:
                return err
            sr = _resolve_sreg(reg)
            if sr is None:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Unknown segment register '{reg}'. Use a name like 'T', 'GP', 'CS' or a register number.")
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at address {start}")
            try:
                sval = int(value, 0) if isinstance(value, str) else int(value)
            except (ValueError, TypeError):
                return make_error(MCPError.INVALID_ARG_TYPE,
                                  f"Cannot parse segment-register value '{value}' as an integer")
            tag = _sreg_tag_for_type(sr_type)
            try:
                ok = ida_segregs.split_sreg_range(s_ea, sr, sval, tag)
            except Exception as e:
                return handle_error(e)
            if not ok:
                return make_error(MCPError.IDA_ERROR,
                                  f"Failed to set segment register '{_sreg_name(sr)}' at {hex(s_ea)}")
            return {
                "ok": True,
                "address": hex(s_ea),
                "reg": _sreg_name(sr),
                "value": sval,
                "sr_type": sr_type,
            }

        # ------------------------------------------------------------------
        # SREG_LIST — enumerate sreg ranges overlapping the address's segment
        # ------------------------------------------------------------------
        elif action == "sreg_list":
            if not start:
                return make_error(MCPError.INVALID_ARGS,
                                  "Parameter 'start' (address) is required for sreg_list")
            if ida_segregs is None:
                return make_error(MCPError.IDA_ERROR,
                                  "ida_segregs is unavailable in this runtime")
            s_ea, err = validate_addr(start)
            if err:
                return err
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND,
                                  f"No segment at address {start}")
            sr = _resolve_sreg(reg) if reg is not None and reg != "" else None
            if reg is not None and reg != "" and sr is None:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Unknown segment register '{reg}'. Use a name like 'T', 'GP', 'CS' or a register number.")
            ranges = []
            if sr is not None:
                for srange in _sreg_ranges_for_register(seg.start_ea, seg.end_ea, sr):
                    ranges.append(_sreg_range_record(sr, srange))
            else:
                sreg_indices = _sreg_reg_indices()
                if sreg_indices is not None:
                    first, last = sreg_indices
                    for idx in range(first, last + 1):
                        for srange in _sreg_ranges_for_register(seg.start_ea, seg.end_ea, idx):
                            ranges.append(_sreg_range_record(idx, srange))
            return {
                "ok": True,
                "address": hex(s_ea),
                "segment": _compat.get_segment_name(s_ea),
                "reg": _sreg_name(sr) if sr is not None else None,
                "ranges": ranges,
                "count": len(ranges),
            }

        # ==================================================================
        # NEW ACTIONS
        # ==================================================================

        # ------------------------------------------------------------------
        # ANALYZE
        # ------------------------------------------------------------------
        elif action == "analyze":
            if start or name:
                seg, err = _find_segment(start, name)
                if err:
                    return err
                return {
                    "ok": True,
                    "segments": [_seg_density_analysis(seg)],
                }

            # Analyze all segments
            results = []
            for ea in idautils.Segments():
                seg = idaapi.getseg(ea)
                if seg:
                    results.append(_seg_density_analysis(seg))
            return {"ok": True, "segments": results, "count": len(results)}

        # ------------------------------------------------------------------
        # FIND_CODE — list functions in a segment
        # ------------------------------------------------------------------
        elif action == "find_code":
            seg, err = _find_segment(start, name)
            if err:
                return err

            functions = []
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                func = idaapi.get_func(func_ea)
                if func:
                    fname = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
                    functions.append({
                        "addr": hex(func_ea),
                        "name": fname,
                        "size": func.end_ea - func.start_ea,
                    })

            return {
                "ok": True,
                "segment": {
                    "name": _compat.get_segment_name(seg.start_ea),
                    "address": hex(seg.start_ea),
                    "start": hex(seg.start_ea),
                    "end_address": hex(seg.end_ea),
                    "end": hex(seg.end_ea),
                },
                "functions": functions,
                "count": len(functions),
            }

        # ------------------------------------------------------------------
        # FIND_DATA — list data items / strings in a segment
        # ------------------------------------------------------------------
        elif action == "find_data":
            seg, err = _find_segment(start, name)
            if err:
                return err

            data_items = []
            strings = []
            head = seg.start_ea
            iterations = 0
            while head < seg.end_ea:
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_data(flags):
                    size = ida_bytes.get_item_size(head)
                    data_items.append({
                        "addr": hex(head),
                        "size": size,
                        "type": ida_bytes.is_strlit(flags) and "string" or "data",
                        "value": _strlit_value(head) if ida_bytes.is_strlit(flags) else str(hex(ida_bytes.get_qword(head) if size == 8 else (ida_bytes.get_long(head) if size == 4 else (ida_bytes.get_word(head) if size == 2 else ida_bytes.get_byte(head))))),
                    })
                if ida_bytes.is_strlit(flags):
                    strings.append({
                        "addr": hex(head),
                        "value": _strlit_value(head),
                    })
                head = idc.next_head(head, seg.end_ea)
                if head == idaapi.BADADDR:
                    break
                iterations += 1
                if iterations >= 500000:
                    break

            return {
                "ok": True,
                "segment": {
                    "name": _compat.get_segment_name(seg.start_ea),
                    "address": hex(seg.start_ea),
                    "start": hex(seg.start_ea),
                    "end_address": hex(seg.end_ea),
                    "end": hex(seg.end_ea),
                },
                "data_items": data_items,
                "strings": strings,
                "data_count": len(data_items),
                "string_count": len(strings),
            }

        # ------------------------------------------------------------------
        # COMPARE — side-by-side comparison of two segments
        # ------------------------------------------------------------------
        elif action == "compare":
            # Identify segment A
            if start or name:
                seg_a, err = _find_segment(start, name)
                if err:
                    return err
            else:
                return make_error(MCPError.INVALID_ARGS,
                                  "Identify segment A via 'start' (address) or 'name'")

            # Identify segment B
            if end or name2:
                seg_b, err = _find_segment(end, name2)
                if err:
                    return err
            else:
                return make_error(MCPError.INVALID_ARGS,
                                  "Identify segment B via 'end' (address) or 'name2'")

            # Helper to build a segment snapshot
            def _snapshot(seg):
                cc, dc, sc, fc = _count_heads(seg)
                return {
                    "name": _compat.get_segment_name(seg.start_ea),
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": seg.end_ea - seg.start_ea,
                    "perms": _perms_string(seg),
                    "class": _compat.get_segment_class(seg.start_ea),
                    "entropy": _seg_entropy(seg),
                    "function_count": fc,
                    "code_heads": cc,
                    "data_heads": dc,
                    "string_count": sc,
                }

            snap_a = _snapshot(seg_a)
            snap_b = _snapshot(seg_b)

            # Compute differences
            diff = {}
            for key in ("size", "function_count", "code_heads", "data_heads", "string_count"):
                diff[key] = snap_b[key] - snap_a[key]

            diff["entropy"] = round(snap_b["entropy"] - snap_a["entropy"], 4)
            diff["same_perms"] = snap_a["perms"] == snap_b["perms"]
            diff["same_class"] = snap_a["class"] == snap_b["class"]

            return {
                "ok": True,
                "segment_a": snap_a,
                "segment_b": snap_b,
                "differences": diff,
            }

        # ------------------------------------------------------------------
        # MERGE — aggregated analysis across all segments
        # ------------------------------------------------------------------
        elif action == "merge":
            analyses = []
            total_size = 0
            total_entropy = 0.0
            total_funcs = 0
            total_strings = 0
            total_imports = 0
            seg_count = 0

            for ea in idautils.Segments():
                seg = idaapi.getseg(ea)
                if seg:
                    d = _seg_density_analysis(seg)
                    analyses.append(d)
                    total_size += d["size"]
                    total_entropy += d["entropy"]
                    total_funcs += d["function_count"]
                    total_strings += d["string_count"]
                    total_imports += d["import_count"]
                    seg_count += 1

            avg_entropy = round(total_entropy / seg_count, 4) if seg_count else 0.0

            return {
                "ok": True,
                "segments": analyses,
                "summary": {
                    "segment_count": seg_count,
                    "total_size": total_size,
                    "total_size_kb": round(total_size / 1024.0, 2),
                    "total_functions": total_funcs,
                    "total_strings": total_strings,
                    "total_imports": total_imports,
                    "avg_entropy": avg_entropy,
                    "avg_function_density_per_kb": round(total_funcs / (total_size / 1024.0), 2) if total_size else 0.0,
                    "avg_string_density_per_kb": round(total_strings / (total_size / 1024.0), 2) if total_size else 0.0,
                    "avg_import_density_per_kb": round(total_imports / (total_size / 1024.0), 2) if total_size else 0.0,
                },
            }

        else:
            return make_error(MCPError.INVALID_ARGS,
                              f"Unknown action: '{action}'. Valid actions: list, info, add, delete, "
                              f"set_attr, set_perms, move, analyze, find_code, find_data, compare, merge, "
                              f"sreg_get, sreg_set, sreg_list")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 12. FILES - Database and file operations
# ============================================================================
