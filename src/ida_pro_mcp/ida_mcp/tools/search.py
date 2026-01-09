
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_segment
import ida_funcs
import ida_kernwin
import ida_frame
import ida_lines

# Infrastructure discovery
try:
    # Package mode
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ida_mcp.error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
        
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal["bytes", "string", "immediate", "name", "insns", "text", "operand", "comment", "data_ref", "code_ref"],
                      "Action: bytes|string|immediate|name|insns|text|operand|comment|data_ref|code_ref"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern (for compatibility)"] = None,
    limit: Annotated[int, "Max results"] = 100,
    offset: Annotated[int, "Results offset (skip first N matches)"] = 0,
    start: Annotated[Optional[str], "Start address for bounded searches"] = None,
    end: Annotated[Optional[str], "End address for bounded searches"] = None,
    **kwargs
) -> dict:
    """
    Search for patterns, specific bytes, or references in the binary.
    
    Actions:
    - bytes: Search for a byte pattern (e.g. "55 8B EC" or "E8 ?? ?? ?? ??"). Uses IDA's `bin_search`.
    - string: Search for string content in defined string literals. Substring match.
    - immediate: Search for usage of a specific immediate value/constant.
    - name: Search symbol names using a glob pattern (e.g. "*printf*").
    - insns: Search for a sequence of instruction mnemonics (e.g. "push, mov, sub").
    - text: Search disassembly text for a substring.
    - operand: Search operands for a substring (e.g., "rsp", "qword ptr").
    - comment: Search comments for a substring.
    - data_ref: Find all data references TO a specific address/name.
    - code_ref: Find all code references TO a specific address/name.
    
    Arguments:
    - pattern (or query): The search query (hex string, text, glob, or comma-separated mnemonics).
    - limit: Max number of results (default 100).
    """
    try:
        # Support both pattern and query for compatibility
        if not pattern and query:
            pattern = query
        if not pattern:
            return make_error(MCPError.INVALID_ARGS, "pattern or query parameter required")
            
        import ida_search
        import fnmatch

        results = []
        truncated = False
        matches_seen = 0
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        if limit <= 0:
            limit = 1
        try:
            offset = max(0, int(offset))
        except Exception:
            offset = 0

        def maybe_add(entry):
            nonlocal matches_seen, truncated
            matches_seen += 1
            if matches_seen <= offset:
                return False
            results.append(entry)
            if len(results) >= limit:
                truncated = True
                return True
            return False
        range_start = None
        range_end = None
        if start is not None or end is not None:
            if start is None or end is None:
                return make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
            range_start, range_end, err = validate_range(start, end)
            if err:
                return err
        seg_list = None
        if range_start is not None:
            seg_list = []
            seg = idaapi.getseg(range_start)
            while seg and seg.start_ea < range_end:
                seg_list.append(seg.start_ea)
                seg = idaapi.get_next_seg(seg.end_ea)

        if action == "bytes":
            # Byte pattern search e.g. "48 8B ?? ??"

            seg = idaapi.getseg(range_start) if range_start is not None else idaapi.get_first_seg()
            while seg and len(results) < limit:
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        seg = idaapi.get_next_seg(seg.end_ea)
                        continue
                # IDA 9.2+ bin_search with compiled pattern
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    pt = ida_bytes.compiled_binpat_vec_t()
                    err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
                    if err:
                        return make_error(MCPError.INVALID_ARGS, f"Invalid pattern: {err}")

                    ea, _ = ida_bytes.bin_search(seg_start, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
                    while ea != idaapi.BADADDR:
                        if maybe_add({"addr": hex(ea)}):
                            break
                        ea, _ = ida_bytes.bin_search(ea + 1, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)

                # Fallback for older IDA - removed, API no longer exists
                else:
                     # ida_search.find_binary removed in IDA 9
                     pass
                        
                if range_end is not None and seg.end_ea >= range_end:
                    break
                seg = idaapi.get_next_seg(seg.end_ea)
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        elif action == "string":
            for i in range(idaapi.get_strlist_qty()):
                if truncated:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if pattern.lower() in s.lower():
                                if maybe_add({"addr": hex(sc.ea), "string": s}):
                                    break
                    except:
                        pass
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        elif action == "immediate":
            if not query: return make_error(MCPError.INVALID_ARGS, "query (value) required")
            try: value = int(query, 0)
            except: return make_error(MCPError.INVALID_ARGS, "Invalid immediate value")

            import ida_ua
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                curr = seg_ea
                end = range_end if range_end is not None else idc.get_segm_end(seg_ea)
                while curr < end:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, curr) > 0:
                        for op in insn.ops:
                            if op.type == ida_ua.o_imm and op.value == value:
                                if maybe_add(hex(curr)):
                                    break
                                break
                        curr += insn.size
                    else:
                        curr = idc.next_head(curr, end)
                    if truncated:
                        break
                if truncated:
                    break
            return {
                "ok": True,
                "matches": results,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        elif action == "name":
            import fnmatch
            for ea, name in idautils.Names():
                if truncated:
                    break
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    if maybe_add({"addr": hex(ea), "name": name}):
                        break
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        elif action == "insns":
            # Search for instruction mnemonic sequence (comma-separated)
            mnemonics = [m.strip().lower() for m in pattern.split(",")]

            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue

                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue

                ea = seg_start
                while ea < seg_end and not truncated:
                    flags = ida_bytes.get_flags(ea)
                    if ida_bytes.is_code(flags):
                        match = True
                        check_ea = ea
                        for mnem in mnemonics:
                            # Print mnemonic for the current head
                            curr_mnem = idc.print_insn_mnem(check_ea).lower()
                            if mnem != "*" and curr_mnem != mnem:
                                match = False
                                break
                            check_ea = idc.next_head(check_ea, seg_end)
                            if check_ea == idaapi.BADADDR:
                                match = False
                                break
                        if match:
                            if maybe_add({"addr": hex(ea)}):
                                break
                    ea = idc.next_head(ea, seg_end)
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }

        elif action == "text":
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    line = idc.generate_disasm_line(ea, 0)
                    if line and pattern.lower() in line.lower():
                        if maybe_add({"addr": hex(ea), "text": ida_lines.tag_remove(line)}):
                            break
                    ea = idc.next_head(ea, seg_end)
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }

        elif action == "operand":
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    ops = []
                    for i in range(8):
                        if idc.get_operand_type(ea, i) == idaapi.o_void:
                            break
                        ops.append(idc.print_operand(ea, i) or "")
                    op_text = ", ".join(ops)
                    if op_text and pattern.lower() in op_text.lower():
                        if maybe_add({"addr": hex(ea), "operands": op_text}):
                            break
                    ea = idc.next_head(ea, seg_end)
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }

        elif action == "comment":
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    cmt = idc.get_cmt(ea, 0)
                    if cmt and pattern.lower() in cmt.lower():
                        if maybe_add({"addr": hex(ea), "comment": cmt}):
                            break
                    ea = idc.next_head(ea, seg_end)
            return {
                "ok": True,
                "matches": results,
                "pattern": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }

        elif action == "data_ref":
            # Search for data references to address
            target_ea, error = validate_addr(pattern)
            if error:
                # If pattern is not an address, try as name
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"Target '{pattern}' not found")

            for xref in idautils.XrefsTo(target_ea, 0):
                if truncated:
                    break
                if not xref.iscode:
                    if maybe_add({"from": hex(xref.frm), "to": hex(xref.to), "type": "data"}):
                        break
            return {
                "ok": True,
                "matches": results,
                "target": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        elif action == "code_ref":
            # Search for code references to address
            target_ea, error = validate_addr(pattern)
            if error:
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"Target '{pattern}' not found")

            for xref in idautils.XrefsTo(target_ea, 0):
                if truncated:
                    break
                if xref.iscode:
                    func = idaapi.get_func(xref.frm)
                    entry = {"from": hex(xref.frm), "to": hex(xref.to), "type": "code"}
                    if func:
                        entry["func"] = ida_funcs.get_func_name(func.start_ea)
                    if maybe_add(entry):
                        break
            return {
                "ok": True,
                "matches": results,
                "target": pattern,
                "offset": offset,
                "count": len(results),
                "total": matches_seen,
                "truncated": truncated,
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================
