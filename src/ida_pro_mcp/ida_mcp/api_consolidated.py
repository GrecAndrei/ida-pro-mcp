"""IDA Pro MCP - Consolidated API

Standardized version with consistent hex formatting and improved reliability.
"""

from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
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

# Support both package mode (MCP server) and standalone mode (idat daemon)
try:
    from .rpc import tool, unsafe
    from .sync import idaread, idawrite, IDAError
    from .utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from .error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except ImportError:
    # Standalone mode
    def tool(func): return func
    def unsafe(func): return func
    def idaread(func): return func
    def idawrite(func): return func
    class IDAError(Exception): pass
    
    # Direct imports from current dir
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
# 1. IDB - Database Metadata
# ============================================================================

@tool
@idaread
def idb(
    action: Annotated[Literal["meta", "segments", "cursor", "entrypoints"], 
                      "Action: meta|segments|cursor|entrypoints"],
) -> dict:
    """Get information about the IDA Database (IDB)."""
    try:
        if action == "meta":
            import hashlib
            path = idc.get_idb_path()
            module = ida_nalt.get_root_filename()
            base = hex_ea(idaapi.get_imagebase())
            size = hex_size(get_image_size())
            input_path = ida_nalt.get_input_file_path()
            try:
                with open(input_path, "rb") as f:
                    data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
            except:
                md5 = sha256 = "unavailable"
            return {"path": path, "module": module, "base": base, "size": size, "md5": md5, "sha256": sha256}
        
        elif action == "segments":
            segments = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if seg:
                    perms = ""
                    if seg.perm & idaapi.SEGPERM_READ: perms += "r"
                    if seg.perm & idaapi.SEGPERM_WRITE: perms += "w"
                    if seg.perm & idaapi.SEGPERM_EXEC: perms += "x"
                    segments.append({
                        "name": ida_segment.get_segm_name(seg),
                        "start": hex_ea(seg.start_ea),
                        "end": hex_ea(seg.end_ea),
                        "size": hex_size(seg.size()),
                        "perms": perms or "---"
                    })
            return {"segments": segments}
        
        elif action == "cursor":
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            result = {"addr": hex_ea(ea)}
            if func:
                result["function"] = {"addr": hex_ea(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea)}
            return result
        
        elif action == "entrypoints":
            entries = []
            _qty = getattr(idaapi, "get_entry_qty", getattr(ida_nalt, "get_entry_qty", None))
            _ordinal = getattr(idaapi, "get_entry_ordinal", getattr(ida_nalt, "get_entry_ordinal", None))
            _entry = getattr(idaapi, "get_entry", getattr(ida_nalt, "get_entry", None))
            _name = getattr(idaapi, "get_entry_name", getattr(ida_nalt, "get_entry_name", None))
            if _qty:
                for i in range(_qty()):
                    ordinal = _ordinal(i)
                    ea = _entry(ordinal)
                    entries.append({"addr": hex_ea(ea), "name": _name(ordinal), "ordinal": ordinal})
            return {"ok": True, "entrypoints": entries}
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

# ============================================================================
# 2. CODE - Decompilation & Disassembly
# ============================================================================

@tool
@idaread
def code(
    action: Annotated[Literal["decompile", "disasm", "xrefs_to", "xrefs_from", "callees", "callers", "blocks", "analyze"], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es)"] = None,
    addr: Annotated[Optional[str], "Single address"] = None,
    max_items: Annotated[int, "Max items"] = 1000,
    max_depth: Annotated[int, "Max depth"] = 5,
) -> list[dict] | dict:
    """Perform code analysis, decompilation, and graph traversal."""
    try:
        if not addrs and addr: addrs = addr
        if not addrs: return make_error(MCPError.INVALID_ARGS, "addrs required")
        addrs = normalize_list_input(addrs)
        results = []
        for a in addrs:
            ea, error = validate_addr(a)
            if error:
                results.append({"addr": a, **error})
                continue
            if action == "decompile":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": a, "error": f"No function at {hex_ea(ea)}"})
                    continue
                try:
                    if not ida_hexrays.init_hexrays_plugin():
                        results.append({"addr": a, "error": "Hex-Rays not available"})
                        continue
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    results.append({"ok": True, "addr": hex_ea(func.start_ea), "code": str(cfunc), "prototype": get_prototype(func)})
                except Exception as e: results.append({"addr": a, "error": str(e)})
            elif action == "disasm":
                func = idaapi.get_func(ea)
                curr = func.start_ea if func else ea
                end = func.end_ea if func else ea + 0x100
                insns = []
                while curr < end and len(insns) < max_items:
                    insns.append({"addr": hex_ea(curr), "text": idc.generate_disasm_line(curr, 0)})
                    curr = idc.next_head(curr, end)
                results.append({"ok": True, "addr": a, "instructions": insns})
            elif action == "xrefs_to":
                xrefs = [{"from": hex_ea(x.frm), "type": "code" if x.iscode else "data"} for x in idautils.XrefsTo(ea, 0)]
                results.append({"ok": True, "addr": a, "xrefs": xrefs[:max_items]})
            elif action == "xrefs_from":
                xrefs = [{"to": hex_ea(x.to), "type": "code" if x.iscode else "data"} for x in idautils.XrefsFrom(ea, 0)]
                results.append({"ok": True, "addr": a, "xrefs": xrefs[:max_items]})
            elif action == "analyze":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                fname = ida_funcs.get_func_name(func.start_ea)
                info = {"ok": True, "addr": a, "name": fname, "size": hex_size(func.end_ea - func.start_ea)}
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    info["pseudocode"] = str(cfunc)
                except: info["pseudocode"] = None
                info["prototype"] = get_prototype(func)
                results.append(info)
        return results[0] if len(addrs) == 1 else results
    except Exception as e: return handle_error(e)

# ============================================================================
# 3. DATA - Functions, globals, strings
# ============================================================================

@tool
@idaread
def data(
    action: Annotated[Literal["functions", "globals", "strings", "imports", "exports", "lookup"], "Action"],
    query: Annotated[Optional[str], "Filter pattern"] = None,
    offset: Annotated[int, "Offset"] = 0,
    count: Annotated[int, "Count"] = 100,
) -> dict:
    """Query, filter, and list data items."""
    try:
        if action == "functions":
            funcs = []
            for ea in idautils.Functions():
                fn = idaapi.get_func(ea)
                name = ida_funcs.get_func_name(ea)
                if not query or query.lower() in name.lower():
                    funcs.append({"addr": hex_ea(ea), "name": name, "size": hex_size(fn.end_ea - fn.start_ea)})
            return {"ok": True, "functions": funcs[offset:offset+count], "total": len(funcs)}
        elif action == "lookup":
            ea = idc.get_name_ea_simple(query)
            if ea != idaapi.BADADDR: return {"ok": True, "addr": hex_ea(ea)}
            try:
                val = int(query, 0)
                return {"ok": True, "addr": hex_ea(val), "name": idc.get_name(val)}
            except: return make_error(MCPError.ADDRESS_INVALID, f"Not found: {query}")
        else: return make_error(MCPError.INVALID_ARGS, f"Action {action} implementation deferred")
    except Exception as e: return handle_error(e)

# ============================================================================
# 4. SEARCH - Pattern matching
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal["bytes", "string", "immediate", "name", "insns", "data_ref", "code_ref"],
                      "Action: bytes|string|immediate|name|insns|data_ref|code_ref"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern"] = None,
    limit: Annotated[int, "Max results"] = 100,
) -> dict:
    """Search for patterns, specific bytes, or references in the binary."""
    try:
        if not pattern and query: pattern = query
        if not pattern: return make_error(MCPError.INVALID_ARGS, "pattern required")
            
        results = []
        if action == "bytes":
            import ida_bytes
            seg = idaapi.get_first_seg()
            while seg and len(results) < limit:
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    pt = ida_bytes.compiled_binpat_vec_t()
                    if not ida_bytes.parse_binpat_str(pt, 0, pattern, 16):
                        ea, _ = ida_bytes.bin_search(seg.start_ea, seg.end_ea, pt, ida_bytes.BIN_SEARCH_FORWARD)
                        while ea != idaapi.BADADDR and len(results) < limit:
                            results.append({"addr": hex_ea(ea)})
                            ea, _ = ida_bytes.bin_search(ea + 1, seg.end_ea, pt, ida_bytes.BIN_SEARCH_FORWARD)
                seg = idaapi.get_next_seg(seg.end_ea)
            return {"ok": True, "matches": results, "pattern": pattern}
        
        elif action == "string":
            for i in range(idaapi.get_strlist_qty()):
                if len(results) >= limit: break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    content = idc.get_strlit_contents(sc.ea)
                    if content:
                        s = content.decode("utf-8", errors="replace")
                        if pattern.lower() in s.lower():
                            results.append({"addr": hex_ea(sc.ea), "string": s})
            return {"ok": True, "matches": results, "pattern": pattern}
        
        elif action == "immediate":
            try: value = int(pattern, 0)
            except: return make_error(MCPError.INVALID_ARGS, f"Invalid immediate: {pattern}")
            import ida_search
            seg = idaapi.get_first_seg()
            while seg and len(results) < limit:
                if hasattr(ida_search, "find_imm"):
                    ea = ida_search.find_imm(seg.start_ea, ida_search.SEARCH_DOWN, value)
                    while ea[0] != idaapi.BADADDR and len(results) < limit:
                        results.append({"addr": hex_ea(ea[0])})
                        ea = ida_search.find_imm(ea[0] + 1, ida_search.SEARCH_DOWN, value)
                seg = idaapi.get_next_seg(seg.end_ea)
            return {"ok": True, "matches": results, "value": pattern}
        
        elif action == "name":
            import fnmatch
            for ea, name in idautils.Names():
                if len(results) >= limit: break
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    results.append({"addr": hex_ea(ea), "name": name})
            return {"ok": True, "matches": results, "pattern": pattern}
        
        elif action == "insns":
            mnemonics = [m.strip().lower() for m in pattern.split(",")]
            for seg_ea in idautils.Segments():
                if len(results) >= limit: break
                seg = idaapi.getseg(seg_ea)
                if not seg or seg.perm & idaapi.SEGPERM_EXEC == 0: continue
                ea = seg.start_ea
                while ea < seg.end_ea and len(results) < limit:
                    if idc.is_code(idc.get_full_flags(ea)):
                        match, check_ea = True, ea
                        for mnem in mnemonics:
                            if mnem != "*" and idc.print_insn_mnem(check_ea).lower() != mnem:
                                match = False; break
                            check_ea = idc.next_head(check_ea)
                        if match: results.append({"addr": hex_ea(ea)})
                    ea = idc.next_head(ea, seg.end_ea)
            return {"ok": True, "matches": results, "pattern": pattern}
        
        elif action in ["data_ref", "code_ref"]:
            target_ea, error = validate_addr(pattern)
            if error: return error
            is_code = (action == "code_ref")
            for xref in idautils.XrefsTo(target_ea, 0):
                if len(results) >= limit: break
                if xref.iscode == is_code:
                    res = {"from": hex_ea(xref.frm), "to": hex_ea(xref.to)}
                    if is_code:
                        func = idaapi.get_func(xref.frm)
                        if func: res["func"] = ida_funcs.get_func_name(func.start_ea)
                    results.append(res)
            return {"ok": True, "matches": results, "target": hex_ea(target_ea)}
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)

# ============================================================================
# Infrastructure placeholders for server initialization
# ============================================================================

@tool
@idawrite
def types(
    action: Annotated[Literal["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct"],
                      "Action"],
    name: Annotated[Optional[str], "Type name"] = None,
    addr: Annotated[Optional[str], "Address"] = None,
    decl: Annotated[Optional[str], "Declaration"] = None,
    query: Annotated[Optional[str], "Query"] = None,
    kind: Annotated[Optional[str], "Kind"] = None,
) -> dict:
    """Manage and inspect types, structures, and function prototypes."""
    try:
        import itertools
        if action == "list":
            types_list = []
            for ordinal in itertools.count(1):
                tif = ida_typeinf.tinfo_t()
                if not tif.get_numbered_type(None, ordinal): break
                if tif.get_type_name():
                    types_list.append({"ordinal": ordinal, "name": tif.get_type_name(), "type": str(tif),
                                     "is_struct": tif.is_struct(), "is_enum": tif.is_enum()})
            return {"ok": True, "types": types_list}
    
        elif action == "get":
            if not name: return make_error(MCPError.INVALID_ARGS, "name required")
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                return make_error(MCPError.TYPE_ERROR, f"Type not found: {name}")
            res = {"ok": True, "name": name, "type": str(tif), "size": tif.get_size()}
            if tif.is_struct() or tif.is_union():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    res["members"] = [{"name": m.name, "offset": m.offset // 8, "type": str(m.type)} for m in udt]
            elif tif.is_enum():
                ei = ida_typeinf.enum_type_data_t()
                if tif.get_enum_details(ei):
                    res["members"] = [{"name": ei[i].name, "value": ei[i].value} for i in range(ei.size())]
            return res
        
        elif action == "set_prototype":
            if not addr or not decl: return make_error(MCPError.INVALID_ARGS, "addr and decl required")
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse: {decl}")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": hex_ea(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to apply type")
            
        elif action == "parse_decl":
            if not decl: return make_error(MCPError.INVALID_ARGS, "decl required")
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse: {decl}")
            return {"ok": True, "parsed": str(tif), "size": tif.get_size()}
            
        elif action == "declare":
            if not decl: return make_error(MCPError.INVALID_ARGS, "decl required")
            res = idc.parse_decls(decl, 0)
            if res == 0: return {"ok": True}
            return make_error(MCPError.TYPE_ERROR, f"Failed to declare types. Error code: {res}")

        elif action == "apply":
            if not addr or not name: return make_error(MCPError.INVALID_ARGS, "addr and name (type) required")
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                return make_error(MCPError.TYPE_ERROR, f"Type not found: {name}")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": hex_ea(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to apply type")

        elif action == "infer":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.guess_tinfo(tif, ea):
                return {"ok": True, "addr": hex_ea(ea), "type": str(tif)}
            return make_error(MCPError.IDA_ERROR, "Could not infer type")

        elif action == "read_struct":
            if not addr or not name: return make_error(MCPError.INVALID_ARGS, "addr and name required")
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name) or not tif.is_struct():
                return make_error(MCPError.TYPE_ERROR, f"Struct not found: {name}")
            udt = ida_typeinf.udt_type_data_t()
            tif.get_udt_details(udt)
            res = {}
            for m in udt:
                m_ea = ea + (m.offset // 8)
                if m.type.is_int():
                    if m.size == 1: res[m.name] = ida_bytes.get_byte(m_ea)
                    elif m.size == 2: res[m.name] = ida_bytes.get_word(m_ea)
                    elif m.size == 4: res[m.name] = ida_bytes.get_dword(m_ea)
                    elif m.size == 8: res[m.name] = ida_bytes.get_qword(m_ea)
                else: res[m.name] = f"<{str(m.type)}>"
            return {"ok": True, "addr": hex_ea(ea), "struct": name, "data": res}
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

@tool
@idawrite
def memory(
    action: Annotated[Literal["read", "write"], "Action: read|write"],
    addr: Annotated[str, "Address"],
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "string"], "Data type"] = "u32",
    size: Annotated[int, "Size in bytes"] = 16,
    data: Annotated[Optional[str], "Hex data to write"] = None,
) -> dict:
    """Read or write raw memory in the database."""
    try:
        ea, error = validate_addr(addr)
        if error: return error
        if action == "read":
            if size > 1024 * 1024: return make_error(MCPError.SIZE_LIMIT_EXCEEDED, "Read size > 1MB")
            if type == "bytes":
                raw = ida_bytes.get_bytes(ea, size)
                value = " ".join(f"{x:02x}" for x in raw) if raw else None
            elif type == "u8": value = ida_bytes.get_wide_byte(ea)
            elif type == "u16": value = ida_bytes.get_wide_word(ea)
            elif type == "u32": value = ida_bytes.get_wide_dword(ea)
            elif type == "u64": value = ida_bytes.get_qword(ea)
            elif type == "string":
                raw = idaapi.get_strlit_contents(ea, -1, 0)
                value = raw.decode("utf-8", errors="replace")[:65536] if raw else None
            return {"ok": True, "addr": hex_ea(ea), "value": value}
        elif action == "write":
            if not data: return make_error(MCPError.INVALID_ARGS, "data required")
            try: bytes_data = bytes.fromhex(data.replace(" ", ""))
            except: return make_error(MCPError.INVALID_ARGS, "Invalid hex data")
            ida_bytes.patch_bytes(ea, bytes_data)
            return {"ok": True, "addr": hex_ea(ea), "size": len(bytes_data)}
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

@tool
@idawrite
def modify(
    action: Annotated[Literal["rename", "comment", "set_type", "patch_asm"], "Action"],
    addr: Annotated[str, "Address"],
    value: Annotated[Optional[str], "Value"] = None,
    comment_type: Annotated[Literal["regular", "repeatable", "anterior", "posterior"], "Comment type"] = "regular",
) -> dict:
    """Modify the database: renaming, commenting, types, and assembly patching."""
    try:
        ea, error = validate_addr(addr)
        if error: return error
        if action == "rename":
            if idc.set_name(ea, value, ida_name.SN_FORCE): return {"ok": True, "addr": hex_ea(ea), "name": value}
            return make_error(MCPError.IDA_ERROR, "Failed to rename")
        elif action == "comment":
            if comment_type == "regular": idc.set_cmt(ea, value, 0)
            elif comment_type == "repeatable": idc.set_cmt(ea, value, 1)
            else:
                if hasattr(ida_lines, "add_extra_cmt"):
                    ida_lines.add_extra_cmt(ea, (comment_type == "anterior"), value)
            return {"ok": True, "addr": hex_ea(ea), "comment_type": comment_type}
        elif action == "set_type":
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, value, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse type: {value}")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": hex_ea(ea), "type": str(tif)}
            return make_error(MCPError.IDA_ERROR, "Failed to apply type")
        elif action == "patch_asm":
            import ida_idp
            assembled = ida_idp.assemble(ea, 0, ea, True, value)
            if assembled:
                ida_bytes.patch_bytes(ea, assembled)
                return {"ok": True, "addr": hex_ea(ea), "size": len(assembled), "asm": value}
            return make_error(MCPError.IDA_ERROR, f"Failed to assemble: {value}")
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

@tool
@unsafe
@idawrite
def misc(
    action: Annotated[Literal["python", "idc", "undo", "redo", "stack_get", "reanalyze", "auto_wait"], "Action"],
    code: Annotated[Optional[str], "Code"] = None,
    addr: Annotated[Optional[str], "Address"] = None,
) -> dict:
    """Miscellaneous utilities: Python, IDC, stack, reanalyze."""
    try:
        if action == "python":
            stdout_cap, stderr_cap = io.StringIO(), io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            try:
                sys.stdout, sys.stderr = stdout_cap, stderr_cap
                exec_globals = {"idaapi": idaapi, "idc": idc, "idautils": __import__("idautils"), "hex_ea": hex_ea}
                exec(code, exec_globals)
                return {"ok": True, "stdout": stdout_cap.getvalue(), "stderr": stderr_cap.getvalue()}
            finally: sys.stdout, sys.stderr = old_out, old_err
        elif action == "idc":
            return {"ok": True, "result": idc.eval_idc(code)}
        elif action in ["undo", "redo"]:
            import ida_undo
            res = ida_undo.perform_undo() if action == "undo" else ida_undo.perform_redo()
            return {"ok": res}
        elif action == "stack_get":
            ea = parse_address(addr)
            return {"addr": hex_ea(ea), "variables": get_stack_frame_variables_internal(ea, True)}
        elif action == "reanalyze":
            ea = parse_address(addr)
            idaapi.plan_and_wait(ea, ea + 1)
            return {"ok": True, "addr": hex_ea(ea)}
        elif action == "auto_wait":
            idaapi.auto_wait(); return {"ok": True}
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

@tool
@unsafe
@idawrite
def debug(
    action: Annotated[Literal["start", "stop", "continue", "breakpoints", "add_bp", "regs", "read_mem"], "Action"],
    addr: Annotated[Optional[str], "Address"] = None,
    size: Annotated[int, "Size"] = 16,
    tid: Annotated[Optional[int], "Thread ID"] = None,
) -> dict:
    """Debugger control: process state, breakpoints, registers, memory."""
    try:
        import ida_dbg
        if action == "start":
            if ida_dbg.run_to(idaapi.inf_get_start_ea()): return {"ok": True}
            return make_error(MCPError.IDA_ERROR, "Failed to start")
        elif action == "stop":
            if ida_dbg.term_process(): return {"ok": True}
            return make_error(MCPError.IDA_ERROR, "Failed to stop")
        elif action == "continue":
            if ida_dbg.continue_process(): return {"ok": True}
            return make_error(MCPError.IDA_ERROR, "Failed to continue")
        elif action == "breakpoints":
            bps = []
            for i in range(ida_dbg.get_bpt_qty()):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.getn_bpt(i, bpt):
                    bps.append({"addr": hex_ea(bpt.ea), "enabled": bpt.is_enabled(), "type": bpt.type})
            return {"breakpoints": bps}
        elif action == "add_bp":
            ea, error = validate_addr(addr, require_code=True)
            if error: return error
            if ida_dbg.add_bpt(ea, 0, 0): return {"ok": True, "addr": hex_ea(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to add bp")
        elif action == "regs":
            import ida_idd
            target_tid = tid if tid is not None else ida_dbg.get_current_thread()
            dbg = ida_idd.get_dbg()
            regvals = ida_dbg.get_reg_vals(target_tid)
            if not regvals: return make_error(MCPError.IDA_ERROR, "Failed to get regs")
            regs = {}
            for i, rv in enumerate(regvals):
                if i < dbg.nregs:
                    name = dbg.regs(i).name
                    val = rv.pyval(dbg.regs(i).dtype)
                    regs[name] = hex_ea(val) if isinstance(val, int) else str(val)
            return {"registers": regs, "tid": target_tid}
        elif action == "read_mem":
            ea, err = parse_address_safe(addr)
            if err: return err
            raw = ida_dbg.read_dbg_memory(ea, size)
            if raw: return {"addr": hex_ea(ea), "data": " ".join(f"{b:02x}" for b in raw)}
            return make_error(MCPError.IDA_ERROR, "Failed to read dbg mem")
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

@tool
@idaread
def agent(
    action: Annotated[Literal["analyze_function", "explore_address"], "Action"],
    addr: Annotated[Optional[str], "Address"] = None,
) -> dict:
    """High-level agent tools for automated analysis and exploration."""
    try:
        if action == "analyze_function":
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            return {
                "addr": hex_ea(ea), "name": ida_funcs.get_func_name(ea),
                "code": decompile_function_safe(ea), "asm": get_assembly_lines(ea),
                "xrefs": get_all_xrefs(ea)
            }
        elif action == "explore_address":
            ea, err = validate_addr(addr)
            if err: return err
            return {
                "addr": hex_ea(ea), "name": idc.get_name(ea) or None,
                "disasm": idc.generate_disasm_line(ea, 0), "xrefs": get_all_xrefs(ea)
            }
        else: return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e: return handle_error(e)

__all__ = ["idb", "code", "data", "search", "types", "memory", "modify", "misc", "debug", "agent"]
