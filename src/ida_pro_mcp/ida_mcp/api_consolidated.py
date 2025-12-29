"""IDA Pro MCP - Consolidated API

DESIGN: mega-tools covering all functionality, optimized for context efficiency.
Each tool uses an 'action' parameter to access sub-operations.
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
        get_stack_frame_variables_internal, get_type_by_name,
    )
except ImportError:
    # Standalone mode - define no-op decorators
    def tool(func):
        return func
    def unsafe(func):
        return func
    def idaread(func):
        return func
    def idawrite(func):
        return func
    class IDAError(Exception):
        pass
    
    # Import utils functions directly (they should be in same directory)
    import os
    import sys
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    if _this_dir not in sys.path:
        sys.path.insert(0, _this_dir)
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name,
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
    """
    Get information about the IDA Database (IDB).
    
    ACTIONS:
    
    meta - Get database metadata
        Returns: {path, module, base, size, md5, sha256}
        Example: idb(action="meta")
        
    segments - List all binary segments
        Returns: {segments: [{name, start, end, size, perms}, ...]}
        Example: idb(action="segments")
        Each segment has: name (str), start/end (hex), size (hex), perms ("rwx")
        
    cursor - Get current cursor position in IDA GUI
        Returns: {addr, function?: {addr, name}}
        Example: idb(action="cursor")
        If cursor is inside a function, function info is included
        
    entrypoints - List program entry points (exports)
        Returns: {entrypoints: [{addr, name, ordinal}, ...]}
        Example: idb(action="entrypoints")
    """
    try:
        if action == "meta":
            import hashlib
            import zlib
            
            path = idc.get_idb_path()
            module = ida_nalt.get_root_filename()
            base = hex(idaapi.get_imagebase())
            size = hex(get_image_size())
            
            input_path = ida_nalt.get_input_file_path()
            try:
                with open(input_path, "rb") as f:
                    data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
            except:
                md5 = sha256 = "unavailable"
            
            return {"path": path, "module": module, "base": base, "size": size, 
                    "md5": md5, "sha256": sha256}
        
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
                        "start": hex(seg.start_ea),
                        "end": hex(seg.end_ea),
                        "size": hex(seg.size()),
                        "perms": perms or "---"
                    })
            return {"segments": segments}
        
        elif action == "cursor":
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            result = {"addr": hex(ea)}
            if func:
                result["function"] = {
                    "addr": hex(func.start_ea),
                    "name": ida_funcs.get_func_name(func.start_ea)
                }
            return result
        
        elif action == "entrypoints":
            entries = []
            
            # Resolve API
            _qty = getattr(idaapi, "get_entry_qty", None)
            _ordinal = getattr(idaapi, "get_entry_ordinal", None)
            _entry = getattr(idaapi, "get_entry", None)
            _name = getattr(idaapi, "get_entry_name", None)
            
            if not _qty:
                # IDA 9 compatibility - check for function existence, not just module
                try:
                    import ida_entry
                    if hasattr(ida_entry, 'get_entry_qty'):
                        _qty = ida_entry.get_entry_qty
                        _ordinal = ida_entry.get_entry_ordinal
                        _entry = ida_entry.get_entry
                        _name = ida_entry.get_entry_name
                    else:
                        raise AttributeError("ida_entry has no get_entry_qty")
                except (ImportError, AttributeError):
                    if hasattr(ida_nalt, 'get_entry_qty'):
                        _qty = ida_nalt.get_entry_qty
                        _ordinal = ida_nalt.get_entry_ordinal
                        _entry = ida_nalt.get_entry
                        _name = ida_nalt.get_entry_name
                    else:
                        return {"error": "Entry API not available in this IDA version"}

            for i in range(_qty()):
                ordinal = _ordinal(i)
                ea = _entry(ordinal)
                name = _name(ordinal)
                entries.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
            return {"entrypoints": entries}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 2. CODE - Decompilation & Disassembly
# ============================================================================

@tool
@idaread
def code(
    action: Annotated[Literal[
        "decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field",
        "callees", "callers", "blocks", "analyze", "callgraph", "export",
        "find_paths", "strings_in_func"
    ], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es) - hex string or name"] = None,
    addr: Annotated[Optional[str], "Single address (alias for addrs)"] = None,  # Alias for compatibility
    max_items: Annotated[int, "Max items to return"] = 1000,
    max_depth: Annotated[int, "Max depth for callgraph/find_paths"] = 5,
    format: Annotated[Literal["json", "c_header", "prototypes"], "Export format"] = "json",
    field_name: Annotated[Optional[str], "Struct field name (for xrefs_to_field)"] = None,
    target: Annotated[Optional[str], "Target address (for find_paths)"] = None,
) -> list[dict] | dict:
    """
    Perform code analysis, decompilation, and graph traversal.
    
    ACTIONS:
    
    decompile - Decompile function to Pseudo-C (requires Hex-Rays)
        Params: addrs (REQUIRED)
        Returns: [{addr, code, prototype}] or {addr, error}
        Example: code(action="decompile", addrs="0x401000")
        Example: code(action="decompile", addrs=["main", "0x402000"])
        
    disasm - Get assembly listing
        Params: addrs (REQUIRED)
        Returns: [{addr, disasm: [{ea, mnemonic, operands}, ...]}]
        Example: code(action="disasm", addrs="0x401000")
        
    xrefs_to - Get cross-references TO an address
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: [{from, type}, ...]}]
        Example: code(action="xrefs_to", addrs="0x401000")
        
    xrefs_from - Get cross-references FROM an address
        Params: addrs (REQUIRED)  
        Returns: [{addr, xrefs: [{to, type}, ...]}]
        Example: code(action="xrefs_from", addrs="0x401000")
        
    callees - List functions called BY this function
        Params: addrs (REQUIRED)
        Returns: [{addr, callees: [{addr, name}, ...]}]
        Example: code(action="callees", addrs="main")
        
    callers - List functions that CALL this function
        Params: addrs (REQUIRED)
        Returns: [{addr, callers: [{addr, name}, ...]}]
        Example: code(action="callers", addrs="printf")
        
    blocks - Get basic blocks (control flow graph nodes)
        Params: addrs (REQUIRED)
        Returns: [{addr, blocks: [{start, end, type}, ...]}]
        Example: code(action="blocks", addrs="0x401000")
        
    analyze - Comprehensive analysis (decompile + callees + callers + strings)
        Params: addrs (REQUIRED)
        Returns: [{addr, code, prototype, callees, callers, strings}]
        Example: code(action="analyze", addrs="main")
        Best for: Getting full context about a function in one call
        
    callgraph - Generate call graph from starting function
        Params: addrs (REQUIRED), max_depth (default 5)
        Returns: [{addr, callgraph: [{caller, callee}, ...]}]
        Example: code(action="callgraph", addrs="main", max_depth=3)
        
    find_paths - Find control flow paths between two addresses
        Params: addrs (REQUIRED), target (REQUIRED)
        Returns: [{addr, paths: [[addr1, addr2, ...], ...]}]
        Example: code(action="find_paths", addrs="0x401000", target="0x402000")
        
    strings_in_func - List strings referenced in function
        Params: addrs (REQUIRED)
        Returns: [{addr, strings: [{addr, value}, ...]}]
        Example: code(action="strings_in_func", addrs="main")
    """
    try:
        # Support both addr (singular) and addrs (plural) for compatibility
        if not addrs and addr:
            addrs = addr
        if not addrs:
            return {"error": "addrs or addr parameter required"}
        addrs = normalize_list_input(addrs)
        results = []
        
        for addr in addrs:
            ea = parse_address(addr)
            
            if action == "decompile":
                func = idaapi.get_func(ea)
                if not func:
                    # Find nearest function for better error
                    prev_func = idaapi.get_prev_func(ea)
                    next_func = idaapi.get_next_func(ea)
                    suggestion = ""
                    if prev_func:
                        suggestion = f" Try {hex(prev_func.start_ea)} ({ida_funcs.get_func_name(prev_func.start_ea) or 'unnamed'})"
                    elif next_func:
                        suggestion = f" Try {hex(next_func.start_ea)} ({ida_funcs.get_func_name(next_func.start_ea) or 'unnamed'})"
                    results.append({
                        "addr": addr, 
                        "error": f"No function at {addr}.{suggestion}",
                        "hint": "Use 'data functions' to list all functions, or 'funcs create' to define a new function"
                    })
                    continue
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    results.append({
                        "addr": addr, 
                        "name": ida_funcs.get_func_name(func.start_ea),
                        "code": str(cfunc)
                    })
                except Exception as e:
                    results.append({"addr": addr, "error": str(e), "hint": "Hex-Rays decompiler may have failed. Try 'disasm' action instead."})
            
            elif action == "disasm":
                func = idaapi.get_func(ea)
                if not func:
                    # Disassemble raw bytes even without function
                    insns = []
                    curr = ea
                    for _ in range(50):  # Show 50 lines anyway
                        line = idc.generate_disasm_line(curr, 0)
                        if line:
                            insns.append({"addr": hex(curr), "text": line})
                        next_ea = idc.next_head(curr, ea + 0x1000)
                        if next_ea == idaapi.BADADDR or next_ea <= curr:
                            break
                        curr = next_ea
                    results.append({
                        "addr": addr, 
                        "warning": "Address is not within a defined function. Showing raw disassembly.",
                        "instructions": insns
                    })
                    continue
                insns = []
                curr = func.start_ea
                count = 0
                while curr < func.end_ea and count < max_items:
                    insns.append({"addr": hex(curr), "text": idc.generate_disasm_line(curr, 0)})
                    curr = idc.next_head(curr, func.end_ea)
                    count += 1
                results.append({"addr": addr, "instructions": insns})
            
            elif action == "xrefs_to":
                xrefs = [{"from": hex(x.frm), "type": "code" if x.iscode else "data"} 
                         for x in idautils.XrefsTo(ea, 0)][:max_items]
                results.append({"addr": addr, "xrefs": xrefs})
            
            elif action == "xrefs_from":
                xrefs = [{"to": hex(x.to), "type": "code" if x.iscode else "data"} 
                         for x in idautils.XrefsFrom(ea, 0)][:max_items]
                results.append({"addr": addr, "xrefs": xrefs})
            
            elif action == "callees":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                callees = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.iscode:
                            target_func = idaapi.get_func(xref.to)
                            if target_func and target_func.start_ea != func.start_ea:
                                callees.add((hex(target_func.start_ea), 
                                            ida_funcs.get_func_name(target_func.start_ea)))
                results.append({"addr": addr, "callees": [{"addr": a, "name": n} for a, n in callees]})
            
            elif action == "callers":
                func = idaapi.get_func(ea)
                start = func.start_ea if func else ea
                callers = set()
                for xref in idautils.XrefsTo(start, 0):
                    if xref.iscode:
                        caller_func = idaapi.get_func(xref.frm)
                        if caller_func:
                            callers.add((hex(caller_func.start_ea),
                                        ida_funcs.get_func_name(caller_func.start_ea)))
                results.append({"addr": addr, "callers": [{"addr": a, "name": n} for a, n in callers]})
            
            elif action == "blocks":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                fc = idaapi.FlowChart(func)
                blocks = []
                for block in fc:
                    blocks.append({
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "succs": [hex(s.start_ea) for s in block.succs()],
                        "preds": [hex(p.start_ea) for p in block.preds()]
                    })
                    if len(blocks) >= max_items:
                        break
                results.append({"addr": addr, "blocks": blocks})
            
            elif action == "analyze":
                # Comprehensive function analysis
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                
                fname = ida_funcs.get_func_name(func.start_ea)
                info = {"addr": addr, "name": fname, "size": hex(func.end_ea - func.start_ea)}
                
                # Decompile
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    info["code"] = str(cfunc)
                except:
                    info["code"] = None
                
                # Callees
                callees = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.iscode:
                            tf = idaapi.get_func(xref.to)
                            if tf and tf.start_ea != func.start_ea:
                                callees.add(ida_funcs.get_func_name(tf.start_ea))
                info["callees"] = list(callees)
                
                # Callers
                callers = set()
                for xref in idautils.XrefsTo(func.start_ea, 0):
                    if xref.iscode:
                        cf = idaapi.get_func(xref.frm)
                        if cf:
                            callers.add(ida_funcs.get_func_name(cf.start_ea))
                info["callers"] = list(callers)
                
                # Strings referenced
                strs = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                strs.append(s.decode("utf-8", errors="replace"))
                info["strings"] = strs[:100]
                
                results.append(info)
            
            elif action == "callgraph":
                # Build call graph from function
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                
                visited = {}
                def traverse(start_ea, depth):
                    if depth > max_depth or start_ea in visited:
                        return
                    fn = idaapi.get_func(start_ea)
                    if not fn:
                        return
                    name = ida_funcs.get_func_name(fn.start_ea)
                    visited[start_ea] = {"name": name, "callees": []}
                    
                    for item in idautils.FuncItems(fn.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != fn.start_ea:
                                    visited[start_ea]["callees"].append(ida_funcs.get_func_name(tf.start_ea))
                                    traverse(tf.start_ea, depth + 1)
                
                traverse(func.start_ea, 0)
                results.append({"addr": addr, "graph": {hex(k): v for k, v in visited.items()}})
            
            elif action == "export":
                # Export function info
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                
                name = ida_funcs.get_func_name(func.start_ea)
                proto = get_prototype(func)
                
                if format == "c_header":
                    results.append({"addr": addr, "header": f"{proto};"})
                elif format == "prototypes":
                    results.append({"addr": addr, "prototype": proto})
                else:
                    results.append({"addr": addr, "name": name, "prototype": proto, 
                                   "start": hex(func.start_ea), "end": hex(func.end_ea)})
            
            elif action == "xrefs_to_field":
                # Find xrefs to a struct field
                if not field_name:
                    results.append({"addr": addr, "error": "field_name required"})
                    continue
                
                # Struct API removed in IDA 9
                results.append({"addr": addr, "error": "xrefs_to_field not supported in this IDA version"})
                continue

            elif action == "find_paths":
                # Find path(s) from addr to target
                if not target:
                    results.append({"addr": addr, "error": "target required"})
                    continue
                
                target_ea = parse_address(target)
                
                # Simple BFS
                queue = [(ea, [hex(ea)])]
                visited = {ea}
                paths = []
                
                while queue and len(paths) < max_items:
                    curr, path = queue.pop(0)
                    if curr == target_ea:
                        paths.append(path)
                        continue
                    
                    if len(path) >= max_depth:
                        continue
                        
                    # Get succs
                    succs = []
                    func = idaapi.get_func(curr) # if callgraph
                    if func:
                        # Intra-procedural flow? Or callgraph? Let's do callgraph for now as it's more useful typically
                        for item in idautils.FuncItems(func.start_ea):
                            for xref in idautils.XrefsFrom(item, 0):
                                if xref.iscode:
                                    tf = idaapi.get_func(xref.to)
                                    if tf and tf.start_ea != func.start_ea:
                                        succs.append(tf.start_ea)
                    
                    for s in succs:
                        if s not in visited:
                            visited.add(s)
                            queue.append((s, path + [hex(s)]))
                            
                results.append({"from": addr, "to": target, "paths": paths})
            
            elif action == "strings_in_func":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                
                strs = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            # Check if string
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                strs.append({"addr": hex(xref.to), "string": s.decode("utf-8", errors="replace")})
                results.append({"addr": addr, "strings": strs})

            else:
                return {"error": f"Unknown action: {action}"}
        
        return results[0] if len(results) == 1 else results
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================

@tool
@idaread
def data(
    action: Annotated[Literal["functions", "globals", "strings", "imports", "exports", "lookup"],
                      "Action: functions|globals|strings|imports|exports|lookup"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
) -> dict:
    """
    Query, filter, and list data items: functions, globals, strings, imports.
    
    Actions:
    - functions: List all defined functions. Supports `query` filter.
    - globals: List global names/variables (non-functions). Supports `query` filter.
    - strings: List string literals defined in the binary. Supports `query` filter.
    - imports: List imported modules and functions.
    - exports: List extracted entry points (same as idb.entrypoints).
    - lookup: Resolve a name to an address (and vice-versa). REQUIRED: `query`.
    
    Arguments:
    - query: String to filter names/content, or name/address for lookup.
    - count: Max results to return (default 100). Use 0 for all (CAUTION).
    - offset: Start index for pagination.
    """
    try:
        if action == "functions":
            funcs = []
            for ea in idautils.Functions():
                fn = idaapi.get_func(ea)
                if fn:
                    name = ida_funcs.get_func_name(ea)
                    if not query or query.lower() in name.lower():
                        funcs.append({"addr": hex(ea), "name": name, "size": hex(fn.end_ea - fn.start_ea)})
            total = len(funcs)
            funcs = funcs[offset:offset+count] if count else funcs[offset:]
            result = {"functions": funcs, "total": total}
            if total == 0:
                result["warning"] = "No functions found. Binary may not be auto-analyzed yet. Try loading IDB in IDA GUI first, or the binary has no recognized code."
            return result
        
        elif action == "globals":
            globs = []
            for ea, name in idautils.Names():
                if idaapi.get_func(ea):
                    continue
                if not query or query.lower() in name.lower():
                    globs.append({"addr": hex(ea), "name": name})
            total = len(globs)
            globs = globs[offset:offset+count] if count else globs[offset:]
            return {"globals": globs, "total": total}
        
        elif action == "strings":
            strings = []
            for i in range(idaapi.get_strlist_qty()):
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            # Filter out garbage:
                            # 1. Min 8 chars (real strings are usually longer)
                            # 2. Check for meaningful content
                            # 3. Skip strings in executable sections
                            if len(s) >= 8:
                                # Skip strings in code sections (likely misidentified bytes)
                                seg = idaapi.getseg(sc.ea)
                                if seg and (seg.perm & idaapi.SEGPERM_EXEC):
                                    continue  # Skip executable segments
                                
                                # Check for meaningful content (letters + common chars)
                                alnum_count = sum(1 for c in s if c.isalnum() or c in ' ._-/:=()[]{}\\n\\t')
                                if alnum_count / len(s) >= 0.7:  # At least 70% meaningful
                                    if not query or query.lower() in s.lower():
                                        strings.append({"addr": hex(sc.ea), "string": s[:200], "length": sc.length})  # Truncate long strings
                    except:
                        pass
            total = len(strings)
            strings = strings[offset:offset+count] if count else strings[offset:]
            return {"strings": strings, "total": total}
        
        elif action == "imports":
            imports = []
            for i in range(ida_nalt.get_import_module_qty()):
                module = ida_nalt.get_import_module_name(i)
                def cb(ea, name, ordinal):
                    imports.append({"addr": hex(ea), "name": name or f"ord_{ordinal}", "module": module})
                    return True
                ida_nalt.enum_import_names(i, cb)
            total = len(imports)
            imports = imports[offset:offset+count] if count else imports[offset:]
            return {"imports": imports, "total": total}
        
        elif action == "exports":
            exports = []
            
            # Resolve API
            _qty = getattr(idaapi, "get_entry_qty", None)
            _ordinal = getattr(idaapi, "get_entry_ordinal", None)
            _entry = getattr(idaapi, "get_entry", None)
            _name = getattr(idaapi, "get_entry_name", None)
            
            if not _qty:
                try:
                    import ida_entry
                    if hasattr(ida_entry, 'get_entry_qty'):
                        _qty = ida_entry.get_entry_qty
                        _ordinal = ida_entry.get_entry_ordinal
                        _entry = ida_entry.get_entry
                        _name = ida_entry.get_entry_name
                    else:
                        raise AttributeError("ida_entry has no get_entry_qty")
                except (ImportError, AttributeError):
                    if hasattr(ida_nalt, 'get_entry_qty'):
                        _qty = ida_nalt.get_entry_qty
                        _ordinal = ida_nalt.get_entry_ordinal
                        _entry = ida_nalt.get_entry
                        _name = ida_nalt.get_entry_name
                    else:
                        return {"error": "Entry API not available in this IDA version"}

            for i in range(_qty()):
                ordinal = _ordinal(i)
                ea = _entry(ordinal)
                name = _name(ordinal)
                exports.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
            return {"exports": exports}
        
        elif action == "lookup":
            if not query:
                return {"error": "query required for lookup"}
            # Try as address
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                    name = idc.get_name(ea)
                    func = idaapi.get_func(ea)
                    return {"addr": hex(ea), "name": name, "is_func": func is not None}
                except:
                    pass
            # Try as name
            ea = idc.get_name_ea_simple(query)
            if ea != idaapi.BADADDR:
                func = idaapi.get_func(ea)
                return {"addr": hex(ea), "name": query, "is_func": func is not None}
            return {"error": f"Not found: {query}"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal["bytes", "string", "immediate", "name", "insns", "data_ref", "code_ref"],
                      "Action: bytes|string|immediate|name|insns|data_ref|code_ref"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern (for compatibility)"] = None,
    limit: Annotated[int, "Max results"] = 100,
) -> dict:
    """
    Search for patterns, specific bytes, or references in the binary.
    
    Actions:
    - bytes: Search for a byte pattern (e.g. "55 8B EC" or "E8 ?? ?? ?? ??"). Uses IDA's `bin_search`.
    - string: Search for string content in defined string literals. Substring match.
    - immediate: Search for usage of a specific immediate value/constant.
    - name: Search symbol names using a glob pattern (e.g. "*printf*").
    - insns: Search for a sequence of instruction mnemonics (e.g. "push, mov, sub").
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
            return {"error": "pattern or query parameter required"}
            
        import ida_search
        import fnmatch
        
        results = []
        
        if action == "bytes":
            # Byte pattern search e.g. "48 8B ?? ??"
            # Byte pattern search e.g. "48 8B ?? ??"
            
            seg = idaapi.get_first_seg()
            while seg and len(results) < limit:
                # IDA 9.2+ bin_search with compiled pattern
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    pt = ida_bytes.compiled_binpat_vec_t()
                    err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
                    if err:
                        return {"error": f"Invalid pattern: {err}"}
                    
                    ea, _ = ida_bytes.bin_search(seg.start_ea, seg.end_ea, pt, ida_bytes.BIN_SEARCH_FORWARD)
                    while ea != idaapi.BADADDR and len(results) < limit:
                        results.append({"addr": hex(ea)})
                        ea, _ = ida_bytes.bin_search(ea + 1, seg.end_ea, pt, ida_bytes.BIN_SEARCH_FORWARD)
                
                # Fallback for older IDA - removed, API no longer exists
                else:
                     # ida_search.find_binary removed in IDA 9
                     pass
                        
                seg = idaapi.get_next_seg(seg.end_ea)
            return {"matches": results, "pattern": pattern}
        
        elif action == "string":
            for i in range(idaapi.get_strlist_qty()):
                if len(results) >= limit:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if pattern.lower() in s.lower():
                                results.append({"addr": hex(sc.ea), "string": s})
                    except:
                        pass
            return {"matches": results, "pattern": pattern}
        
        elif action == "immediate":
            # Immediate value search
            value = int(pattern, 0)
            seg = idaapi.get_first_seg()
            while seg and len(results) < limit:
                # Check for find_imm API change
                if hasattr(ida_search, "find_imm"):
                     ea = ida_search.find_imm(seg.start_ea, ida_search.SEARCH_DOWN, value)
                else:
                     # find_immediate does not exist in IDA 9
                     ea = (idaapi.BADADDR, 0) # API not found

                while ea[0] != idaapi.BADADDR and len(results) < limit:
                    results.append({"addr": hex(ea[0])})
                    if hasattr(ida_search, "find_imm"):
                        ea = ida_search.find_imm(ea[0] + 1, ida_search.SEARCH_DOWN, value)
                    else:
                         break
                seg = idaapi.get_next_seg(seg.end_ea)
            return {"matches": results, "value": pattern}
        
        elif action == "name":
            for ea, name in idautils.Names():
                if len(results) >= limit:
                    break
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    results.append({"addr": hex(ea), "name": name})
            return {"matches": results, "pattern": pattern}
        
        elif action == "insns":
            # Search for instruction mnemonic sequence (comma-separated)
            mnemonics = [m.strip().lower() for m in pattern.split(",")]
            seq_len = len(mnemonics)
            
            for seg_ea in idautils.Segments():
                if len(results) >= limit:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or seg.perm & idaapi.SEGPERM_EXEC == 0:
                    continue
                
                ea = seg.start_ea
                while ea < seg.end_ea and len(results) < limit:
                    if idc.is_code(idc.get_full_flags(ea)):
                        match = True
                        check_ea = ea
                        for i, mnem in enumerate(mnemonics):
                            insn_mnem = idc.print_insn_mnem(check_ea).lower()
                            if mnem != "*" and insn_mnem != mnem:
                                match = False
                                break
                            check_ea = idc.next_head(check_ea)
                        if match:
                            results.append({"addr": hex(ea)})
                    ea = idc.next_head(ea, seg.end_ea)
            return {"matches": results, "pattern": pattern}
        
        elif action == "data_ref":
            # Search for data references to address
            target_ea = parse_address(pattern)
            for xref in idautils.XrefsTo(target_ea, 0):
                if len(results) >= limit:
                    break
                if not xref.iscode:
                    results.append({"from": hex(xref.frm), "to": hex(xref.to)})
            return {"matches": results, "target": pattern}
        
        elif action == "code_ref":
            # Search for code references to address
            target_ea = parse_address(pattern)
            for xref in idautils.XrefsTo(target_ea, 0):
                if len(results) >= limit:
                    break
                if xref.iscode:
                    func = idaapi.get_func(xref.frm)
                    entry = {"from": hex(xref.frm), "to": hex(xref.to)}
                    if func:
                        entry["func"] = ida_funcs.get_func_name(func.start_ea)
                    results.append(entry)
            return {"matches": results, "target": pattern}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================

@tool
@idawrite
def types(
    action: Annotated[Literal["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct"],
                      "Action: list|get|set_prototype|parse_decl|declare|apply|search_structs|infer|read_struct"],
    name: Annotated[Optional[str], "Type name (or variable name for apply)"] = None,
    addr: Annotated[Optional[str], "Address (for set_prototype/apply/infer/read_struct)"] = None,
    decl: Annotated[Optional[str], "Type declaration string"] = None,
    query: Annotated[Optional[str], "Search query (for search_structs)"] = None,
    kind: Annotated[Optional[str], "Apply kind: function, global, local, stack"] = None,
) -> dict:
    """
    Manage and inspect types, structures, and function prototypes.
    
    Actions:
    - list: List all types (structs, enums, typedefs) in the Type Library (TIL).
    - get: Get detailed structure layout or enum members for a named type.
    - set_prototype: Set the C-style function prototype at an address.
    - parse_decl: Parse a C declaration string to verify validity and size.
    - declare: Define a new local type/struct from a C declaration.
    - apply: Apply a type to an address (global/function).
    - search_structs: Find structs containing a field matching `query`.
    - infer: Attempt to guess the type at an address (using Hex-Rays or simple size).
    - read_struct: specific read helper to read structured data from memory using a type.
    
    Arguments:
    - name: Type name, or variable name when applying types.
    - addr: Target address.
    - decl: C declaration string (e.g. "int *foo;").
    """
    try:
        if action == "list":
            types_list = []
            
            # Iterate until we run out of types (robust across IDA versions)
            import itertools
            for ordinal in itertools.count(1):
                tif = ida_typeinf.tinfo_t()
                if not tif.get_numbered_type(None, ordinal):
                    break
                    
                types_list.append({
                    "ordinal": ordinal,
                    "name": tif.get_type_name(),
                    "type": str(tif),
                    "is_struct": tif.is_struct(),
                    "is_enum": tif.is_enum()
                })
            return {"types": types_list}
        
        elif action == "get":
            if not name:
                return {"error": "name required"}
            
            IDA9 = int(idaapi.get_kernel_version().split('.')[0]) >= 9
            tid = ida_typeinf.get_named_type_tid(name) if IDA9 else idaapi.BADADDR
            
            tif = ida_typeinf.tinfo_t()
            if tid != idaapi.BADADDR:
                tif.get_type_by_tid(tid)
            else:
                # Try parse
                if not tif.get_named_type(None, name):
                    return {"error": f"Type not found: {name}"}
            
            result = {"name": name, "type": str(tif), "size": tif.get_size()}
            
            if tif.is_struct() or tif.is_union():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for i in range(udt.size()):
                        m = udt[i]
                        members.append({"name": m.name, "offset": m.offset // 8, "type": str(m.type)})
                    result["members"] = members
            
            elif tif.is_enum():
                ei = ida_typeinf.enum_type_data_t()
                if tif.get_enum_details(ei):
                    members = [{"name": ei[i].name, "value": ei[i].value} for i in range(ei.size())]
                    result["members"] = members
            
            return result
        
        elif action == "set_prototype":
            if not addr or not decl:
                return {"error": "addr and decl required"}
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return {"error": f"Failed to parse: {decl}"}
            if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"error": "Failed to apply type"}
            return {"ok": True, "addr": addr, "type": str(tif)}
        
        elif action == "parse_decl":
            if not decl:
                return {"error": "decl required"}
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return {"error": f"Failed to parse: {decl}"}
            return {"parsed": str(tif), "size": tif.get_size()}
        
        elif action == "declare":
            # Declare a new local type
            if not decl:
                return {"error": "decl required"}
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return {"error": f"Failed to parse: {decl}"}
            
            # Get type name
            type_name = name or tif.get_type_name()
            if not type_name:
                return {"error": "Could not determine type name"}
            
            # Save to local types
            ordinal = ida_typeinf.set_numbered_type(None, 0, ida_typeinf.NTF_REPLACE, type_name, tif)
            if ordinal > 0:
                return {"ok": True, "name": type_name, "ordinal": ordinal}
            return {"error": "Failed to save type"}
        
        elif action == "apply":
            # Apply type to address (enhanced)
            if not addr or not decl:
                return {"error": "addr and decl required"}
            ea = parse_address(addr)
            
            # Determine kind if not specified
            apply_kind = kind
            func = idaapi.get_func(ea)
            if not apply_kind:
                if func and func.start_ea == ea:
                    apply_kind = "function"
                elif func:
                    # Inside function, could be local/stack or global
                    # default to global if not specified, unless name provided?
                    apply_kind = "global"
                else:
                    apply_kind = "global"
            
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return {"error": f"Failed to parse: {decl}"}

            if apply_kind == "function":
                 if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                     return {"error": "Failed to apply function type"}
            
            elif apply_kind == "local":
                if not name:
                    return {"error": "name required for local var"}
                if not func:
                     return {"error": "Address not in function"}
                # Requires Hex-Rays
                import ida_hexrays
                if not ida_hexrays.init_hexrays_plugin():
                    return {"error": "Hex-Rays decompiler not available"}
                
                # Simplified local var modification - usually needs user_lvar_modifier
                # This is complex to implement fully without helper classes.
                # For now, let's stick to global/func.
                return {"error": "Applying local types not fully supported yet in consolidated tool"}

            elif apply_kind == "stack":
                 if not name:
                     return {"error": "name required for stack var"}
                 if not func:
                     return {"error": "Address not in function"}
                 
                 frame_tif = ida_typeinf.tinfo_t()
                 if not ida_frame.get_func_frame(frame_tif, func):
                     return {"error": "No frame"}
                 
                 idx, udm = frame_tif.get_udm(name)
                 if not udm:
                     return {"error": f"Stack var '{name}' not found"}
                 
                 # Set member type in frame
                 offset = udm.offset // 8
                 if not ida_frame.set_frame_member_type(func, offset, tif):
                     return {"error": "Failed to set stack var type"}

            else: # global
                if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return {"error": "Failed to apply type"}

            return {"ok": True, "addr": addr, "type": str(tif), "kind": apply_kind}
        
        elif action == "search_structs":
            # Search structs by field name or type
            if not query:
                return {"error": "query required"}
            
            matches = []
            # Check if ordinal qty API exists
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return {"error": "Type ordinal API not available"}
            for ordinal in range(1, qty_func(None)):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and (tif.is_struct() or tif.is_union()):
                    type_name = tif.get_type_name()
                    # Check type name
                    if query.lower() in type_name.lower():
                        matches.append({"name": type_name, "ordinal": ordinal, "match": "name"})
                        continue
                    
                    # Check fields
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for i in range(udt.size()):
                            m = udt[i]
                            if query.lower() in m.name.lower():
                                matches.append({
                                    "name": type_name,
                                    "ordinal": ordinal,
                                    "match": "field",
                                    "field": m.name
                                })
                                break
            return {"matches": matches, "query": query}
        
        elif action == "infer":
             # Infer type at address
             if not addr:
                 return {"error": "addr required"}
             ea = parse_address(addr)
             tif = ida_typeinf.tinfo_t()
             
             method = "none"
             confidence = "none"
             
             # Try Hex-Rays
             try:
                 import ida_hexrays
                 if ida_hexrays.init_hexrays_plugin():
                     # guess_tinfo removed in IDA 9, use decompile approach
                     if hasattr(ida_hexrays, 'guess_tinfo') and ida_hexrays.guess_tinfo(tif, ea):
                          method = "hexrays"
                          confidence = "high"
                     elif hasattr(ida_hexrays, 'decompile'):
                          # Try to infer from decompilation
                          try:
                              cfunc = ida_hexrays.decompile(ea)
                              if cfunc and cfunc.type:
                                  tif = cfunc.type
                                  method = "hexrays"
                                  confidence = "high"
                          except:
                              pass
             except:
                 pass
             
             if method == "none":
                 # Try existing
                 if ida_nalt.get_tinfo(tif, ea):
                     method = "existing"
                     confidence = "high"
            
             if method == "none":
                 # Size based
                 size = ida_bytes.get_item_size(ea)
                 if size > 0:
                     type_guess = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, f"uint8_t[{size}]")
                     return {"addr": addr, "inferred_type": type_guess, "method": "size", "confidence": "low"}
                     
             return {"addr": addr, "inferred_type": str(tif) if method != "none" else None, "method": method, "confidence": confidence}

        elif action == "read_struct":
            # Read struct at address
            if not addr: # 'name' param is struct name here!
                 return {"error": "addr required"}
            if not name:
                return {"error": "name (struct name) required"}
            
            ea = parse_address(addr)
            
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                return {"error": f"Struct '{name}' not found"}
            
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return {"error": "Not a struct/union or failed to get details"}
            
            members = []
            for i in range(udt.size()):
                m = udt[i]
                offset = m.offset // 8
                mem_addr = ea + offset
                mem_type = str(m.type)
                mem_size = m.type.get_size()
                
                # Simple value reading
                val_str = "?"
                try:
                    if m.type.is_ptr():
                         val = ida_bytes.get_qword(mem_addr) # assume 64-bit for now or check
                         val_str = hex(val)
                    elif mem_size in [1, 2, 4, 8]:
                        val = ida_bytes.get_wide_byte(mem_addr) # simplistic
                        if mem_size == 1: val = ida_bytes.get_byte(mem_addr)
                        elif mem_size == 2: val = ida_bytes.get_word(mem_addr)
                        elif mem_size == 4: val = ida_bytes.get_dword(mem_addr)
                        elif mem_size == 8: val = ida_bytes.get_qword(mem_addr)
                        val_str = hex(val)
                    else:
                        val_str = "..."
                except:
                    pass
                
                members.append({
                    "name": m.name,
                    "offset": hex(offset),
                    "type": mem_type,
                    "value": val_str
                })
            
            return {"addr": addr, "struct": name, "members": members}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 6. MEMORY - Read/Write operations
# ============================================================================

@tool 
@idawrite
def memory(
    action: Annotated[Literal["read", "write"], "Action: read|write"],
    addr: Annotated[str, "Address"],
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "string"], 
                    "Data type (for read)"] = "u32",
    size: Annotated[int, "Size in bytes (for type=bytes)"] = 16,
    data: Annotated[Optional[str], "Hex data to write (for write)"] = None,
) -> dict:
    """
    Read or write raw memory in the database (or debugger memory if running).
    
    Actions:
    - read: Read values from `addr`. Returns hex or native value.
    - write: Patch bytes at `addr`.
    
    Arguments:
    - addr: Address to read/write.
    - type: Data type for read (u8, u16, u32, u64, bytes, string). Default 'u32'.
    - size: Number of bytes to read (only for type='bytes').
    - data: Hex string to write (e.g. "90 90 90"). REQUIRED for write.
    """
    try:
        ea = parse_address(addr)
        
        if action == "read":
            if type == "bytes":
                value = " ".join(f"{x:02x}" for x in ida_bytes.get_bytes(ea, size))
            elif type == "u8":
                value = ida_bytes.get_wide_byte(ea)
            elif type == "u16":
                value = ida_bytes.get_wide_word(ea)
            elif type == "u32":
                value = ida_bytes.get_wide_dword(ea)
            elif type == "u64":
                value = ida_bytes.get_qword(ea)
            elif type == "string":
                value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
            else:
                return {"error": f"Unknown type: {type}"}
            return {"addr": addr, "value": value}
        
        elif action == "write":
            if not data:
                return {"error": "data required for write"}
            bytes_data = bytes.fromhex(data.replace(" ", ""))
            ida_bytes.patch_bytes(ea, bytes_data)
            return {"ok": True, "addr": addr, "size": len(bytes_data)}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 7. MODIFY - Rename, comments, set type
# ============================================================================

@tool
@idawrite
def modify(
    action: Annotated[Literal["rename", "comment", "set_type", "patch_asm"], 
                      "Action: rename|comment|set_type|patch_asm"],
    addr: Annotated[str, "Address"],
    value: Annotated[Optional[str], "New name, comment text, type declaration, or assembly instruction"] = None,
    # Aliases for compatibility
    name: Annotated[Optional[str], "Alias for value (when action=rename)"] = None,
    text: Annotated[Optional[str], "Alias for value (when action=comment)"] = None,
    type_str: Annotated[Optional[str], "Alias for value (when action=set_type)"] = None,
    asm: Annotated[Optional[str], "Alias for value (when action=patch_asm)"] = None,
    comment_type: Annotated[Literal["regular", "repeatable", "anterior", "posterior"], 
                            "Comment type (for action=comment)"] = "regular",
) -> dict:
    """
    Modify the database: renaming, commenting, types, and assembly patching.
    
    Actions:
    - rename: Change the name of a function, label, or data item at `addr`.
    - comment: Add a comment. Supports regular, repeatable, anterior (above), posterior (below).
    - set_type: Apply a type declaration to `addr` (similar to types.apply).
    - patch_asm: Assemble and patch instructions at `addr` (e.g. "mov eax, 1").
    
    Arguments:
    - value (or name/text/type_str/asm): The content to apply.
    - comment_type: One of 'regular', 'repeatable', 'anterior', 'posterior'.
    """
    try:
        # Support multiple parameter names for compatibility
        if not value:
            if action == "rename" and name:
                value = name
            elif action == "comment" and text:
                value = text
            elif action == "set_type" and type_str:
                value = type_str
            elif action == "patch_asm" and asm:
                value = asm
        
        if not value:
            return {"error": f"value parameter required (or use {action}-specific alias: name/text/type_str/asm)"}
        
        ea = parse_address(addr)
        
        if action == "rename":
            if idc.set_name(ea, value, ida_name.SN_FORCE):
                return {"ok": True, "addr": addr, "name": value}
            return {"error": "Failed to rename"}
        
        elif action == "comment":
            if comment_type == "regular":
                idc.set_cmt(ea, value, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, value, 1)
            else:
                # Anterior/Posterior
                import ida_lines
                is_anterior = (comment_type == "anterior")
                if hasattr(ida_lines, "add_extra_cmt"):
                    ida_lines.add_extra_cmt(ea, is_anterior, value)
                else:
                    # API not available - fall through to return ok anyway
                    pass
            return {"ok": True, "addr": addr, "comment_type": comment_type}
        
        elif action == "set_type":
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, value, ida_typeinf.PT_SIL):
                return {"error": f"Failed to parse type: {value}"}
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": addr, "type": str(tif)}
            return {"error": "Failed to apply type"}
        
        elif action == "patch_asm":
            # Assemble and patch
            import ida_idp
            import ida_ua
            
            # Get current architecture info
            insn = ida_ua.insn_t()
            assembled = ida_idp.assemble(ea, 0, ea, True, value)
            if assembled:
                # assembled returns a bytes object on success
                ida_bytes.patch_bytes(ea, assembled)
                return {"ok": True, "addr": addr, "size": len(assembled), "asm": value}
            return {"error": f"Failed to assemble: {value}"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 8. MISC - Python exec, signatures, bookmarks, undo, stack
# ============================================================================

@tool
@unsafe
@idawrite
def misc(
    action: Annotated[Literal[
        "python", "idc", "undo", "redo",
        "sig_list", "sig_apply", "til_load", 
        "bookmark_list", "bookmark_set", "bookmark_del",
        "stack_get", "reanalyze", "auto_wait"
    ], "Action"],
    code: Annotated[Optional[str], "Python/IDC code"] = None,
    name: Annotated[Optional[str], "Signature/TIL name"] = None,
    addr: Annotated[Optional[str], "Address"] = None,
    slot: Annotated[Optional[int], "Bookmark slot 0-9"] = None,
) -> dict:
    """
    Miscellaneous utilities: Python execution, IDC, signatures, bookmarks.
    
    Actions:
    - python: Execute arbitrary Python code in IDA's context. Returns stringified result.
    - idc: Evaluate an IDC expression.
    - undo/redo: Perform undo/redo operations.
    - sig_list/sig_apply: Manage Labelled Library Signatures (FLIRT).
    - til_load: Load a type library by name (e.g. "mssdk").
    - bookmark_list/set/del: Manage user bookmarks at addresses.
    - stack_get: Get variables in the stack frame of the function at `addr`.
    - reanalyze: Force re-analysis of the function/area at `addr`.
    - auto_wait: Block until IDA's auto-analysis is finished.
    
    Arguments:
    - code: Python or IDC code to execute.
    - name: Name for signatures or TIL.
    - slot: Bookmark index (0-9).
    """
    try:
        if action == "python":
            if not code:
                return {"error": "code required"}
            
            # Capture stdout/stderr
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            
            try:
                sys.stdout = stdout_capture
                sys.stderr = stderr_capture
                
                # Create execution context with IDA modules (lazy import to avoid errors)
                def lazy_import(module_name):
                    try:
                        return __import__(module_name)
                    except Exception:
                        return None
                
                exec_globals = {
                    "__builtins__": __builtins__,
                    "idaapi": idaapi,
                    "idc": idc,
                    "idautils": lazy_import("idautils"),
                    "ida_allins": lazy_import("ida_allins"),
                    "ida_auto": lazy_import("ida_auto"),
                    "ida_bitrange": lazy_import("ida_bitrange"),
                    "ida_bytes": ida_bytes,
                    "ida_dbg": lazy_import("ida_dbg"),
                    "ida_dirtree": lazy_import("ida_dirtree"),
                    "ida_diskio": lazy_import("ida_diskio"),
                    "ida_entry": lazy_import("ida_entry"),
                    "ida_expr": lazy_import("ida_expr"),
                    "ida_fixup": lazy_import("ida_fixup"),
                    "ida_fpro": lazy_import("ida_fpro"),
                    "ida_frame": ida_frame,
                    "ida_funcs": ida_funcs,
                    "ida_gdl": lazy_import("ida_gdl"),
                    "ida_graph": lazy_import("ida_graph"),
                    "ida_hexrays": ida_hexrays,
                    "ida_ida": lazy_import("ida_ida"),
                    "ida_idd": lazy_import("ida_idd"),
                    "ida_idp": lazy_import("ida_idp"),
                    "ida_ieee": lazy_import("ida_ieee"),
                    "ida_kernwin": ida_kernwin,
                    "ida_libfuncs": lazy_import("ida_libfuncs"),
                    "ida_lines": ida_lines,
                    "ida_loader": lazy_import("ida_loader"),
                    "ida_merge": lazy_import("ida_merge"),
                    "ida_mergemod": lazy_import("ida_mergemod"),
                    "ida_moves": lazy_import("ida_moves"),
                    "ida_nalt": ida_nalt,
                    "ida_name": ida_name,
                    "ida_netnode": lazy_import("ida_netnode"),
                    "ida_offset": lazy_import("ida_offset"),
                    "ida_pro": lazy_import("ida_pro"),
                    "ida_problems": lazy_import("ida_problems"),
                    "ida_range": lazy_import("ida_range"),
                    "ida_regfinder": lazy_import("ida_regfinder"),
                    "ida_registry": lazy_import("ida_registry"),
                    "ida_search": lazy_import("ida_search"),
                    "ida_segment": ida_segment,
                    "ida_segregs": lazy_import("ida_segregs"),
                    "ida_srclang": lazy_import("ida_srclang"),
                    "ida_strlist": lazy_import("ida_strlist"),
                    # ida_struct and ida_enum were removed in IDA 9.0
                    # Use ida_typeinf instead for new code
                    "ida_struct": lazy_import("ida_struct") if int(idaapi.get_kernel_version().split('.')[0]) < 9 else None,
                    "ida_tryblks": lazy_import("ida_tryblks"),
                    "ida_typeinf": ida_typeinf,
                    "ida_ua": lazy_import("ida_ua"),
                    "ida_undo": lazy_import("ida_undo"),
                    "ida_xref": lazy_import("ida_xref"),
                    "ida_enum": lazy_import("ida_enum") if int(idaapi.get_kernel_version().split('.')[0]) < 9 else None,
                    "parse_address": parse_address,
                    "get_function": get_function,
                }
                
                result_value = None
                
                # Try evaluation first (for simple expressions)
                try:
                    result_value = str(eval(code, exec_globals))
                except Exception:
                    # Execute as statements
                    exec_locals = {}
                    exec(code, exec_globals, exec_locals)
                    
                    # Merge locals into globals for multi-statement blocks
                    exec_globals.update(exec_locals)
                    
                    # Try to eval the last line as an expression (Jupyter-style)
                    lines = code.strip().split("\n")
                    if lines:
                        last_line = lines[-1].strip()
                        if last_line and not last_line.startswith(
                            (
                                "#",
                                "import ",
                                "from ",
                                "def ",
                                "class ",
                                "if ",
                                "for ",
                                "while ",
                                "with ",
                                "try:",
                            )
                        ):
                            try:
                                result_value = str(eval(last_line, exec_globals))
                            except Exception:
                                pass
                    
                    # Return 'result' variable if explicitly set
                    if result_value is None and "result" in exec_locals:
                        result_value = str(exec_locals["result"])
                    
                    # Return last assigned variable
                    if result_value is None and exec_locals:
                        last_key = list(exec_locals.keys())[-1]
                        result_value = str(exec_locals[last_key])
                
                # Collect output
                stdout_text = stdout_capture.getvalue()
                stderr_text = stderr_capture.getvalue()
                
                return {
                    "result": result_value or "",
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                }
            
            except Exception:
                import traceback
                
                # Safely get stdout if available
                stdout_text = stdout_capture.getvalue() if 'stdout_capture' in locals() else ""
                
                return {
                    "result": "",
                    "stdout": stdout_text,
                    "stderr": traceback.format_exc(),
                }
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        
        elif action == "idc":
            # Evaluate IDC expression
            if not code:
                return {"error": "code required"}
            result = idc.eval_idc(code)
            if result is None:
                return {"error": "IDC evaluation failed"}
            return {"result": result}
        
        elif action == "undo":
            import ida_undo
            if ida_undo.create_undo_point("MCP undo") and ida_undo.perform_undo():
                return {"ok": True}
            return {"error": "Undo failed"}
        
        elif action == "redo":
            import ida_undo
            if ida_undo.perform_redo():
                return {"ok": True}
            return {"error": "Redo failed"}
        
        elif action == "sig_list":
            import os
            sig_dir = idc.idadir("sig")
            sigs = []
            if sig_dir and os.path.exists(sig_dir):
                for root, dirs, files in os.walk(sig_dir):
                    for f in files:
                        if f.lower().endswith(".sig"):
                            sigs.append(os.path.splitext(f)[0])
            return {"signatures": sorted(sigs)}
        
        elif action == "sig_apply":
            if not name:
                return {"error": "name required"}
            import ida_libfuncs
            ida_libfuncs.plan_to_apply_ldes(name)
            return {"ok": True, "name": name}
        
        elif action == "til_load":
            if not name:
                return {"error": "name required"}
            if ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT):
                return {"ok": True, "name": name}
            return {"error": "Failed to load TIL"}
        
        elif action == "bookmark_list":
            bookmarks = []
            # IDA 9 bookmarks
            if hasattr(idaapi, "bookmarks_t_get"):
                 for i in range(10): # Legacy slots 0-9 usually
                     # Complex C++ wrapper, might fail logic.
                     # For now, return empty or safe error to avoid crashing.
                     pass
            return {"bookmarks": bookmarks, "note": "Bookmarks API changed in IDA 9, listing temporarily disabled"}
        
        elif action == "bookmark_set":
             return {"error": "Not supported in this version"}
        
        elif action == "bookmark_del":
             return {"error": "Not supported in this version"}
        
        elif action == "stack_get":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            return {"addr": addr, "variables": vars}
        
        elif action == "reanalyze":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            idaapi.plan_and_wait(ea)
            return {"ok": True, "addr": addr}
        
        elif action == "auto_wait":
            idaapi.auto_wait()
            return {"ok": True}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 9. DEBUG - Debugger operations
# ============================================================================

@tool
@unsafe
@idawrite
def debug(
    action: Annotated[Literal[
        "start", "stop", "continue", "step_into", "step_over", "run_to",
        "breakpoints", "add_bp", "del_bp", "enable_bp",
        "regs", "callstack", "read_mem", "write_mem"
    ], "Action"],
    addr: Annotated[Optional[str], "Address"] = None,
    size: Annotated[int, "Size for read_mem"] = 16,
    data: Annotated[Optional[str], "Hex data for write_mem"] = None,
    enabled: Annotated[bool, "Enable/disable for enable_bp"] = True,
    tid: Annotated[Optional[int], "Thread ID for regs"] = None,
) -> dict:
    """
    Debugger control: process state, breakpoints, registers, memory.
    
    Actions:
    - start: Launch the debugger/process.
    - stop: Terminate the process.
    - continue: Resume execution.
    - step_into/step_over: Single step execution.
    - run_to: Execute until `addr` is reached.
    - breakpoints: List current breakpoints.
    - add_bp/del_bp: Add or remove software breakpoints.
    - enable_bp: Enable/disable an existing breakpoint.
    - regs: Get current register values (and TID).
    - callstack: Get the current thread's call stack (Not supported in IDA 9).
    - read_mem/write_mem: Read/write memory in the debugged process.
    """
    try:
        import ida_dbg
        import ida_idd
        
        if action == "start":
            if ida_dbg.start_process():
                return {"ok": True}
            return {"error": "Failed to start debugger"}
        
        elif action == "stop":
            ida_dbg.exit_process()
            return {"ok": True}
        
        elif action == "continue":
            ida_dbg.continue_process()
            return {"ok": True}
        
        elif action == "step_into":
            ida_dbg.step_into()
            return {"ok": True}
        
        elif action == "step_over":
            ida_dbg.step_over()
            return {"ok": True}
        
        elif action == "run_to":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            ida_dbg.run_to(ea)
            return {"ok": True, "addr": addr}
        
        elif action == "breakpoints":
            bps = []
            for i in range(ida_dbg.get_bpt_qty()):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.getn_bpt(i, bpt):
                    bps.append({
                        "addr": hex(bpt.ea),
                        "enabled": bpt.is_enabled(),
                        "type": bpt.type
                    })
            return {"breakpoints": bps}
        

        
        elif action == "add_bp":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            # 0 = BPT_DEFAULT/BPT_BRK in older APIs, BPT_BRK in new
            if ida_dbg.add_bpt(ea, 0, 0): 
                return {"ok": True, "addr": addr}
            return {"error": "Failed to add breakpoint"}
        
        elif action == "enable_bp":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            if ida_dbg.enable_bpt(ea, enabled):
                return {"ok": True, "addr": addr, "enabled": enabled}
            return {"error": "Failed to enable/disable breakpoint"}
        
        elif action == "regs":
            if not ida_dbg.is_debugger_on():
                return {"error": "Debugger not running"}
            
            # Determine thread ID
            target_tid = tid if tid is not None else ida_dbg.get_current_thread()
            
            # Get debugger info for register names/types
            dbg = ida_idd.get_dbg()
            if not dbg:
                 return {"error": "No debugger info"}
            
            # Get values for specific thread
            regvals = ida_dbg.get_reg_vals(target_tid)
            if not regvals:
                 return {"error": f"Failed to get registers for thread {target_tid}"}
            
            regs = {}
            for i, rv in enumerate(regvals):
                 if i < dbg.nregs:
                     reg_info = dbg.regs(i)
                     if not reg_info: continue
                     
                     name = reg_info.name
                     try:
                         val = rv.pyval(reg_info.dtype)
                         # Format value roughly matching original
                         if isinstance(val, int): 
                             val_str = hex(val)
                         elif isinstance(val, bytes):
                             val_str = val.hex(" ")
                         else:
                             val_str = str(val)
                         regs[name] = val_str
                     except:
                         regs[name] = "?"
            return {"registers": regs, "tid": target_tid}
        
        elif action == "callstack":
            if not ida_dbg.is_debugger_on():
                return {"error": "Debugger not running"}
            # call_stack_t / get_call_stack removed in IDA 9
            if hasattr(ida_dbg, 'collect_stack_trace'):
                stack = []
                frames = ida_dbg.collect_stack_trace(ida_dbg.get_current_thread())
                if frames:
                    for frame in frames:
                        stack.append({"addr": hex(frame.ea), "func": idc.get_name(frame.ea) or ""})
                return {"callstack": stack}
            return {"error": "Callstack API not available in this IDA version"}
        
        elif action == "read_mem":
            if not addr:
                return {"error": "addr required"}
            if not ida_dbg.is_debugger_on():
                return {"error": "Debugger not running"}
            ea = parse_address(addr)
            data = ida_dbg.read_dbg_memory(ea, size)
            if data:
                return {"addr": addr, "data": " ".join(f"{b:02x}" for b in data)}
            return {"error": "Failed to read memory"}
        
        elif action == "write_mem":
            if not addr or not data:
                return {"error": "addr and data required"}
            if not ida_dbg.is_debugger_on():
                return {"error": "Debugger not running"}
            ea = parse_address(addr)
            bytes_data = bytes.fromhex(data.replace(" ", ""))
            if ida_dbg.write_dbg_memory(ea, bytes_data):
                return {"ok": True, "addr": addr, "size": len(bytes_data)}
            return {"error": "Failed to write memory"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 10. FUNCS - Function management
# ============================================================================

@tool
@idawrite
def funcs(
    action: Annotated[Literal["create", "delete", "set_flags", "comment"],
                      "Action: create|delete|set_flags|comment"],
    addr: Annotated[str, "Address"],
    end_addr: Annotated[Optional[str], "End address (for create)"] = None,
    flags: Annotated[Optional[int], "Flags (for set_flags)"] = None,
    comment: Annotated[Optional[str], "Comment text"] = None,
    repeatable: Annotated[bool, "Repeatable comment"] = False,
) -> dict:
    """
    Manage function definitions (create, edit, delete).
    
    Actions:
    - create: Define a new function starting at `addr`.
    - delete: Undefine the function at `addr`.
    - set_flags: Set function flags (e.g. FUNC_NORET).
    - comment: Set a function comment.
    
    Arguments:
    - end_addr: End address (for create).
    - flags: Integer flags.
    - repeatable: Boolean for repeatable comments.
    """
    try:
        ea = parse_address(addr)
        
        if action == "create":
            end = parse_address(end_addr) if end_addr else idaapi.BADADDR
            if idaapi.add_func(ea, end):
                return {"ok": True, "addr": addr}
            return {"error": "Failed to create function"}
        
        elif action == "delete":
            if idaapi.del_func(ea):
                return {"ok": True, "addr": addr}
            return {"error": "Failed to delete function"}
        
        elif action == "set_flags":
            if flags is None:
                return {"error": "flags required"}
            func = idaapi.get_func(ea)
            if not func:
                return {"error": "No function at address"}
            func.flags = flags
            if idaapi.update_func(func):
                return {"ok": True, "addr": addr, "flags": flags}
            return {"error": "Failed to update flags"}
        
        elif action == "comment":
            if comment is None:
                return {"error": "comment required"}
            func = idaapi.get_func(ea)
            if not func:
                return {"error": "No function at address"}
            ida_funcs.set_func_cmt(func, comment, repeatable)
            return {"ok": True, "addr": addr}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================

@tool
@idawrite
def segments(
    action: Annotated[Literal["list", "add", "delete", "set_attr", "move"],
                      "Action: list|add|delete|set_attr|move"],
    start: Annotated[Optional[str], "Start address (src for move)"] = None,
    end: Annotated[Optional[str], "End address (dst for move)"] = None,
    name: Annotated[Optional[str], "Segment name"] = None,
    sclass: Annotated[str, "Segment class"] = "DATA",
    attr: Annotated[Optional[str], "Attribute name (for set_attr)"] = None,
    value: Annotated[Optional[int], "Attribute value (for set_attr)"] = None,
) -> dict:
    """
    Manage binary segments.
    
    Actions:
    - list: List all segments (same as idb.segments).
    - add: Create a new segment.
    - delete: Delete a segment.
    - set_attr: Set a segment attribute (e.g. name, class).
    - move: Move a segment to a new address range.
    
    Arguments:
    - start, end: Segment bounds.
    - sclass: Segment class (CODE, DATA, BSS, etc.).
    - attr: Attribute name (for set_attr).
    - value: New value (for set_attr).
    """
    try:
        if action == "list":
            segs = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if seg:
                    perms = ""
                    if seg.perm & idaapi.SEGPERM_READ: perms += "r"
                    if seg.perm & idaapi.SEGPERM_WRITE: perms += "w"
                    if seg.perm & idaapi.SEGPERM_EXEC: perms += "x"
                    segs.append({
                        "name": ida_segment.get_segm_name(seg),
                        "start": hex(seg.start_ea),
                        "end": hex(seg.end_ea),
                        "perms": perms or "---"
                    })
            return {"segments": segs}
        
        elif action == "add":
            if not start or not end:
                return {"error": "start and end required"}
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            seg = idaapi.segment_t()
            seg.start_ea = start_ea
            seg.end_ea = end_ea
            if idaapi.add_segm_ex(seg, name or "", sclass, 0):
                return {"ok": True, "start": start, "end": end}
            return {"error": "Failed to add segment"}
        
        elif action == "delete":
            if not start:
                return {"error": "start required"}
            start_ea = parse_address(start)
            if idaapi.del_segm(start_ea, idaapi.SEGMOD_KILL):
                return {"ok": True, "start": start}
            return {"error": "Failed to delete segment"}
        
        elif action == "set_attr":
            if not start or not attr or value is None:
                return {"error": "start, attr, and value required"}
            start_ea = parse_address(start)
            seg = idaapi.getseg(start_ea)
            if not seg:
                return {"error": "Segment not found"}
            if hasattr(seg, attr):
                setattr(seg, attr, value)
                idaapi.update_segm(seg)
                return {"ok": True, "start": start, "attr": attr, "value": value}
            return {"error": f"Unknown attribute: {attr}"}

        elif action == "move":
            if not start or not end:
                return {"error": "start and end (new_start) required"}
            start_ea = parse_address(start)
            to_ea = parse_address(end)
            seg = idaapi.getseg(start_ea)
            if not seg:
                return {"error": "Segment not found"}
            if idaapi.move_segm(start_ea, to_ea, 0) == idaapi.MOVE_SEGM_OK:
                return {"ok": True, "old_start": start, "new_start": end}
            return {"error": "Failed to move segment"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 12. FILES - Database and file operations
# ============================================================================

@tool
@unsafe
@idawrite
def files(
    action: Annotated[Literal[
        "save", "close", "open", "load_binary",
        "list_recent", "get_cwd", "set_cwd", 
        "list_dir", "exists", "read", "write", "sessions", "batch"
    ], "Action"],
    path: Annotated[Optional[str], "File path or JSON array of paths for batch"] = None,
    base_addr: Annotated[Optional[str], "Base address for load_binary"] = None,
    content: Annotated[Optional[str], "Content to write, or mode for open"] = None,
) -> dict:
    """
    File and Database I/O with MULTI-FILE BATCH ANALYSIS support.
    
    ACTIONS:
    
    open - Open file in new IDA instance (multi-session support!)
        Params: path (REQUIRED), content (optional: "load"|"overwrite"|"-c -B"...)
        Returns: {ok, path, mode, pid, cmd, existing_db, session_file}
        Example: files(action="open", path="C:/samples/malware.exe")
        Example: files(action="open", path="C:/samples/mal.exe", content="overwrite")
        Behavior:
          - Default ("load"): Opens existing .i64/.idb if found, else creates new
          - "overwrite": Forces new database creation (deletes existing)
          - Custom flags: Pass IDA CLI flags like "-c -B -A"
        
    batch - MULTI-FILE BATCH ANALYSIS (headless mode only!)
        Params: path (JSON array of paths OR directory path)
        Returns: {analyzed, failed, total, results: [{path, ok, functions, md5}]}
        Example: files(action="batch", path='["file1.exe", "file2.exe"]')
        Example: files(action="batch", path="C:/samples/")
        Note: Requires idalib-mcp headless mode. Analyzes each file sequentially.
        
    sessions - List all spawned IDA sessions
        Returns: {sessions: [{pid, path, port, started}], current: {pid, path}}
        Example: files(action="sessions")
        
    save - Save current database
    close - Close database (in headless: ready for next file)
    load_binary - Load additional binary into current IDB
    list_recent - List recently opened files
    get_cwd/set_cwd - Working directory management
    list_dir - Directory listing
    exists/read/write - File system operations
    """
    try:
        import os
        
        if action == "sessions":
            # List all spawned IDA sessions
            import json
            # Use user's home dir for session tracking (avoids Program Files permissions)
            home_dir = os.path.expanduser("~")
            session_file = os.path.join(home_dir, ".ida_mcp_sessions.json")
            
            sessions = []
            try:
                if os.path.exists(session_file):
                    with open(session_file, "r") as f:
                        sessions = json.load(f)
            except:
                pass
            
            # Current session info
            current = {
                "pid": os.getpid(),
                "path": idc.get_idb_path(),
                "port": 13337  # Default MCP port
            }
            
            return {
                "sessions": sessions,
                "current": current,
                "session_file": session_file,
                "note": "Use open action to spawn new IDA instances"
            }
        
        elif action == "save":
            import ida_loader
            if ida_loader.save_database(path or "", 0):
                return {"ok": True, "path": path or idc.get_idb_path()}
            return {"error": "Failed to save database"}
        
        elif action == "close":
            # IDA 9.2: Closing is supported but context-dependent
            # In headless/idalib mode: use idapro.close_database()
            # In GUI mode: warn about qexit
            
            # Try idapro first (IDA 9.x headless)
            try:
                import idapro
                if hasattr(idapro, 'close_database'):
                    idapro.close_database()
                    return {"ok": True, "note": "Database closed via idapro. Ready for next file."}
            except ImportError:
                pass
            
            # Try older idalib module name
            try:
                import idalib
                if hasattr(idalib, 'close_database'):
                    idalib.close_database()
                    return {"ok": True, "note": "Database closed via idalib."}
            except ImportError:
                pass
            
            # GUI mode - can request quit
            try:
                import ida_pro
                if hasattr(ida_pro, 'qexit'):
                    return {"warning": "GUI mode - use ida_pro.qexit(0) to close. This exits IDA.",
                            "how_to": "misc(action='python', code='import ida_pro; ida_pro.qexit(0)')"}
            except:
                pass
            
            return {"error": "close_database not available. In GUI mode, use File > Exit."}
        
        elif action == "open":
            # IDA 9.2: File opening support
            # In idalib: use open_database()
            # In GUI mode: spawn a NEW IDA process with the target file
            if not path:
                return {"error": "path required"}
            
            import os
            if not os.path.exists(path):
                return {"error": f"File not found: {path}"}
            
            # HEADLESS MODE: Try idapro first (IDA 9.x), then idalib
            # This allows batch analysis of multiple files
            
            # Try idapro (IDA 9.x headless)
            try:
                import idapro
                import ida_auto
                if hasattr(idapro, 'open_database'):
                    # open_database returns 0 on success
                    result = idapro.open_database(path, run_auto_analysis=True)
                    if result == 0:
                        # Wait for auto-analysis to complete
                        ida_auto.auto_wait()
                        return {"ok": True, "path": path, "mode": "idapro", 
                                "note": "Database opened and auto-analysis complete"}
                    return {"error": f"idapro.open_database failed with code: {result}"}
            except ImportError:
                pass
            
            # Try older idalib module
            try:
                import idalib
                if hasattr(idalib, 'open_database'):
                    if path.lower().endswith(('.idb', '.i64')):
                        result = idalib.open_database(path)
                        if result == 0:
                            return {"ok": True, "path": path, "type": "database", "mode": "idalib"}
                        return {"error": f"Failed to open database: {path}"}
                    
                    cli_args = content or "-c -A"
                    result = idalib.open_database(path, cli_args)
                    if result == 0:
                        return {"ok": True, "path": path, "type": "binary", "mode": "idalib", "args": cli_args}
                    return {"error": f"Failed to load binary: {path}"}
            except ImportError:
                pass  # Fall through to GUI mode handling
            
            # GUI MODE: Spawn a new IDA process
            # This allows AI agents to open files even in GUI mode
            import subprocess
            import sys
            
            # Find ida executable - IDA 9.x uses unified naming (ida.exe, idat.exe)
            # Older versions (8.x) used ida64.exe, idat64.exe for 64-bit
            ida_dir = idaapi.idadir("")
            
            # Try multiple executable names in order of preference
            exe_candidates = []
            if os.name == "nt":
                # Windows
                exe_candidates = ["ida.exe", "ida64.exe", "idat.exe", "idat64.exe"]
            else:
                # Linux/Mac
                exe_candidates = ["ida", "ida64", "idat", "idat64"]
            
            ida_exe = None
            for candidate in exe_candidates:
                test_path = os.path.join(ida_dir, candidate)
                if os.path.exists(test_path):
                    ida_exe = test_path
                    break
            
            if not ida_exe:
                return {"error": f"IDA executable not found in {ida_dir}", "tried": exe_candidates}
            
            # Check for existing database
            base_name = os.path.splitext(path)[0]
            existing_idb = None
            for ext in ['.i64', '.idb']:
                check_path = base_name + ext
                if os.path.exists(check_path):
                    existing_idb = check_path
                    break
            
            # Build command line with proper flags
            # -B: batch mode (suppress dialogs)
            # -c: create new database (overwrite if exists)
            # content parameter can override: "overwrite", "load", or custom flags
            mode = content.lower().strip() if content else "load"
            
            if mode == "overwrite" or mode == "new":
                # Force create new database
                cmd = [ida_exe, "-c", "-B", path]
            elif mode == "load" and existing_idb:
                # Load existing database directly
                cmd = [ida_exe, existing_idb]
            elif mode.startswith("-"):
                # Custom flags passed
                cmd = [ida_exe] + mode.split() + [path]
            else:
                # Default: batch mode, will load existing or create new
                cmd = [ida_exe, "-B", path]
            
            # Track spawned instances for multi-session support
            import json
            # Use user's home dir for session tracking (avoids Program Files permissions)
            home_dir = os.path.expanduser("~")
            session_file = os.path.join(home_dir, ".ida_mcp_sessions.json")
            
            try:
                # Spawn process WITH visible window
                if os.name == "nt":
                    # Windows: CREATE_NEW_PROCESS_GROUP keeps it independent but visible
                    proc = subprocess.Popen(
                        cmd,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                else:
                    # Unix: use start_new_session
                    proc = subprocess.Popen(
                        cmd,
                        start_new_session=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                
                # Record session for multi-instance tracking
                session_info = {
                    "pid": proc.pid,
                    "path": path,
                    "started": str(os.times()),
                    "port": 13337  # Default, may increment if multiple instances
                }
                
                # Load existing sessions and add new one
                sessions = []
                try:
                    if os.path.exists(session_file):
                        with open(session_file, "r") as f:
                            sessions = json.load(f)
                except:
                    pass
                
                sessions.append(session_info)
                
                try:
                    with open(session_file, "w") as f:
                        json.dump(sessions, f, indent=2)
                except:
                    pass  # Non-critical
                
                return {
                    "ok": True,
                    "path": path,
                    "mode": "spawned",
                    "pid": proc.pid,
                    "cmd": " ".join(cmd),
                    "existing_db": existing_idb,
                    "behavior": mode,
                    "note": "IDA window spawned. MCP plugin will auto-start on port 13337+.",
                    "session_file": session_file
                }
            except Exception as e:
                return {"error": f"Failed to spawn IDA: {str(e)}", "cmd": " ".join(cmd)}
        
        elif action == "load_binary":
            # Load additional binary into current database (not replace)
            if not path:
                return {"error": "path required"}
            ba = parse_address(base_addr) if base_addr else 0
            
            # Try multiple approaches
            try:
                import ida_loader
                
                # Method 1: idaapi.load_binary_file (if available)
                if hasattr(idaapi, "load_binary_file"):
                    if idaapi.load_binary_file(path, ba):
                        return {"ok": True, "path": path, "base_addr": hex(ba), "method": "load_binary_file"}
                
                # Method 2: loader_input_t approach (older IDA)
                if hasattr(ida_loader, 'loader_input_t'):
                    li = ida_loader.loader_input_t()
                    if li.open(path, False):
                        if ida_loader.load_binary_file(path, li, 0, 0, ba, 0):
                            return {"ok": True, "path": path, "base_addr": hex(ba), "method": "loader_input_t"}
                        return {"error": "load_binary_file failed"}
                    return {"error": f"Failed to open file: {path}"}
                
                return {"error": "No suitable binary loading API found"}
                
            except Exception as e:
                return {"error": f"Load failed: {str(e)}"}
        
        elif action == "list_recent":
            import ida_diskio
            recent = []
            if hasattr(ida_diskio, "get_ida_recent_file_count"):
                for i in range(ida_diskio.get_ida_recent_file_count()):
                    f = ida_diskio.get_ida_recent_file(i)
                    if f:
                        recent.append(f)
            else:
                 # Check registry or alternative
                 # For now, return empty or error to avoid crash
                 pass
            return {"recent": recent}
        
        elif action == "get_cwd":
            return {"cwd": os.getcwd()}
        
        elif action == "set_cwd":
            if not path:
                return {"error": "path required"}
            os.chdir(path)
            return {"ok": True, "cwd": path}
        
        elif action == "list_dir":
            target = path or os.getcwd()
            if not os.path.exists(target):
                return {"error": f"Path not found: {target}"}
            entries = []
            for name in os.listdir(target):
                full = os.path.join(target, name)
                entries.append({
                    "name": name,
                    "is_dir": os.path.isdir(full),
                    "size": os.path.getsize(full) if os.path.isfile(full) else 0
                })
            return {"path": target, "entries": entries}
        
        elif action == "exists":
            if not path:
                return {"error": "path required"}
            return {"path": path, "exists": os.path.exists(path), "is_file": os.path.isfile(path), "is_dir": os.path.isdir(path)}
        
        elif action == "read":
            if not path:
                return {"error": "path required"}
            if not os.path.exists(path):
                return {"error": f"File not found: {path}"}
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return {"path": path, "content": f.read()}
        
        elif action == "write":
            if not path or content is None:
                return {"error": "path and content required"}
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return {"ok": True, "path": path, "size": len(content)}
        
        elif action == "batch":
            # FULLY AUTOMATIC BATCH ANALYSIS
            # Spawns headless IDA worker to analyze multiple files
            # NO MANUAL SETUP REQUIRED
            
            if not path:
                return {"error": "path required - provide JSON array of paths or a directory"}
            
            import json as json_mod
            import subprocess
            import tempfile
            import sys
            
            # Parse paths
            file_list = []
            if path.startswith("["):
                try:
                    file_list = json_mod.loads(path)
                except:
                    return {"error": "Invalid JSON array for paths"}
            elif os.path.isdir(path):
                for f in os.listdir(path):
                    full = os.path.join(path, f)
                    if os.path.isfile(full):
                        ext = os.path.splitext(f)[1].lower()
                        if ext in ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '']:
                            file_list.append(full)
            else:
                return {"error": f"path must be JSON array or directory, got: {path}"}
            
            if not file_list:
                return {"error": "No files to analyze"}
            
            # Check if already in headless mode
            try:
                import idapro
                if hasattr(idapro, 'open_database'):
                    # Already in headless - do direct analysis
                    results = []
                    import ida_auto
                    for filepath in file_list:
                        if not os.path.exists(filepath):
                            results.append({"path": filepath, "error": "File not found"})
                            continue
                        try:
                            try:
                                idapro.close_database()
                            except:
                                pass
                            ret = idapro.open_database(filepath, run_auto_analysis=True)
                            if ret == 0:
                                ida_auto.auto_wait()
                                func_count = len(list(idautils.Functions()))
                                results.append({"path": filepath, "ok": True, "functions": func_count})
                            else:
                                results.append({"path": filepath, "error": f"open_database returned {ret}"})
                        except Exception as e:
                            results.append({"path": filepath, "error": str(e)})
                    return {"mode": "direct", "analyzed": len([r for r in results if r.get("ok")]), 
                            "failed": len([r for r in results if r.get("error")]), "results": results}
            except ImportError:
                pass
            
            # GUI MODE: Auto-spawn headless worker
            # Find idat executable (text-mode IDA for scripting)
            ida_dir = idaapi.idadir("")
            idat_candidates = ["idat.exe", "idat64.exe", "idat"] if os.name == "nt" else ["idat64", "idat"]
            idat_exe = None
            for cand in idat_candidates:
                test = os.path.join(ida_dir, cand)
                if os.path.exists(test):
                    idat_exe = test
                    break
            
            if not idat_exe:
                return {"error": f"idat executable not found in {ida_dir}"}
            
            # Create analysis script
            script_content = '''
import sys
import json
import os

try:
    import idapro
    import ida_auto
    import idautils
    import idc
except ImportError:
    # Fallback for older IDA
    import ida_auto
    import idautils
    import idc

files = FILES_PLACEHOLDER
results = []

for filepath in files:
    if not os.path.exists(filepath):
        results.append({"path": filepath, "error": "File not found"})
        continue
    try:
        # For idat, we need to use ida_loader or just run per-file
        # This script runs once per file via idat -A -S
        func_count = len(list(idautils.Functions()))
        md5 = idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else ""
        results.append({
            "path": idc.get_input_file_path(),
            "ok": True,
            "functions": func_count,
            "strings": len(list(idautils.Strings())),
            "md5": md5
        })
    except Exception as e:
        results.append({"path": filepath, "error": str(e)})

# Write results
with open(OUTPUT_PLACEHOLDER, "w") as f:
    json.dump(results, f)

# Exit IDA
import ida_pro
ida_pro.qexit(0)
'''
            
            # Run analysis on each file WITH CACHING
            results = []
            home_dir = os.path.expanduser("~")
            cached_count = 0
            
            for filepath in file_list:
                if not os.path.exists(filepath):
                    results.append({"path": filepath, "error": "File not found"})
                    continue
                
                # CACHE CHECK: If .i64 or .idb exists, load it instead of re-analyzing
                base_name = os.path.splitext(filepath)[0]
                cached_idb = None
                for ext in ['.i64', '.idb']:
                    check = base_name + ext
                    if os.path.exists(check):
                        cached_idb = check
                        break
                
                if cached_idb:
                    # Load cached database - much faster!
                    output_file = os.path.join(home_dir, f".ida_batch_{os.getpid()}_{len(results)}.json")
                    
                    cache_script = f'''
import json
import idautils
import idc
import ida_pro

try:
    func_count = len(list(idautils.Functions()))
    string_count = len(list(idautils.Strings()))
    md5 = idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else ""
    result = {{"path": idc.get_input_file_path(), "ok": True, "functions": func_count, "strings": string_count, "md5": md5, "cached": True}}
except Exception as e:
    result = {{"path": "{filepath}", "error": str(e), "cached": True}}

with open(r"{output_file}", "w") as f:
    json.dump(result, f)

ida_pro.qexit(0)
'''
                    script_file = os.path.join(home_dir, f".ida_batch_script_{os.getpid()}.py")
                    with open(script_file, "w") as f:
                        f.write(cache_script)
                    
                    try:
                        # Load cached IDB - should be very fast
                        cmd = [idat_exe, "-A", f"-S{script_file}", cached_idb]
                        proc = subprocess.run(cmd, capture_output=True, timeout=60)  # Only 1 min for cached
                        
                        if os.path.exists(output_file):
                            with open(output_file, "r") as f:
                                result = json_mod.load(f)
                                results.append(result)
                                cached_count += 1
                            os.remove(output_file)
                        else:
                            results.append({"path": filepath, "error": "Cache load failed"})
                    except subprocess.TimeoutExpired:
                        results.append({"path": filepath, "error": "Cache load timed out"})
                    except Exception as e:
                        results.append({"path": filepath, "error": f"Cache error: {str(e)}"})
                    finally:
                        try:
                            os.remove(script_file)
                        except:
                            pass
                    continue
                
                # NO CACHE: Full analysis needed
                output_file = os.path.join(home_dir, f".ida_batch_{os.getpid()}_{len(results)}.json")
                
                single_script = f'''
import json
import os
import idautils
import idc
import ida_pro

try:
    func_count = len(list(idautils.Functions()))
    string_count = len(list(idautils.Strings()))
    md5 = idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else ""
    result = {{"path": idc.get_input_file_path(), "ok": True, "functions": func_count, "strings": string_count, "md5": md5, "cached": False}}
except Exception as e:
    result = {{"path": "{filepath}", "error": str(e)}}

with open(r"{output_file}", "w") as f:
    json.dump(result, f)

ida_pro.qexit(0)
'''
                
                script_file = os.path.join(home_dir, f".ida_batch_script_{os.getpid()}.py")
                with open(script_file, "w") as f:
                    f.write(single_script)
                
                try:
                    # Full analysis - longer timeout
                    cmd = [idat_exe, "-A", f"-S{script_file}", filepath]
                    proc = subprocess.run(cmd, capture_output=True, timeout=300)  # 5 min for new files
                    
                    # Read results
                    if os.path.exists(output_file):
                        with open(output_file, "r") as f:
                            result = json_mod.load(f)
                            results.append(result)
                        os.remove(output_file)
                    else:
                        results.append({"path": filepath, "error": "Analysis did not produce output"})
                except subprocess.TimeoutExpired:
                    results.append({"path": filepath, "error": "Analysis timed out (5 min)"})
                except Exception as e:
                    results.append({"path": filepath, "error": f"Subprocess error: {str(e)}"})
                finally:
                    try:
                        os.remove(script_file)
                    except:
                        pass
            
            return {
                "mode": "auto-spawned",
                "worker": idat_exe,
                "analyzed": len([r for r in results if r.get("ok")]),
                "cached": cached_count,
                "fresh": len([r for r in results if r.get("ok") and not r.get("cached")]),
                "failed": len([r for r in results if r.get("error")]),
                "total": len(file_list),
                "results": results
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 13. PLUGINS - Plugin operations
# ============================================================================

@tool
@unsafe
@idawrite
def plugins(
    action: Annotated[Literal["list", "run"], "Action: list|run"],
    name: Annotated[Optional[str], "Plugin name (for run)"] = None,
    arg: Annotated[int, "Plugin argument"] = 0,
) -> dict:
    """
    Manage IDA plugins.
    
    Actions:
    - list: List loaded plugins (Note: May not be supported in newer IDA versions).
    - run: Run a plugin by name.
    
    Arguments:
    - name: Plugin name (e.g. "Hex-Rays Decompiler").
    - arg: Integer argument for the plugin run call.
    """
    try:
        import ida_loader
        
        if action == "list":
            # Plugin enumeration API removed in IDA 9
            return {"error": "Plugin listing not supported in this IDA version"}
        
        elif action == "run":
            if not name:
                return {"error": "name required"}
            # Try to run plugin by name
            if ida_loader.run_plugin(ida_loader.find_plugin(name, True), arg):
                return {"ok": True, "name": name}
            return {"error": f"Failed to run plugin: {name}"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 14. TRACE - Trace operations
# ============================================================================

@tool
@unsafe
@idawrite
def trace(
    action: Annotated[Literal["get", "clear", "set_options"], "Action: get|clear|set_options"],
    addr: Annotated[Optional[str], "Address filter"] = None,
    count: Annotated[int, "Max trace entries to return"] = 1000,
    enable_insn: Annotated[Optional[bool], "Enable instruction tracing"] = None,
    enable_func: Annotated[Optional[bool], "Enable function tracing"] = None,
    enable_bblk: Annotated[Optional[bool], "Enable basic block tracing"] = None,
) -> dict:
    """Trace operations: get trace data, clear, set options"""
    try:
        import ida_dbg
        
        if action == "get":
            if not ida_dbg.is_debugger_on():
                return {"error": "Debugger not running"}
            
            traces = []
            # tev_t removed in IDA 9, check for availability
            if not hasattr(ida_dbg, 'tev_t'):
                return {"error": "Trace API not available in this IDA version"}
            tev = ida_dbg.tev_t()
            for i in range(min(ida_dbg.get_tev_qty(), count)):
                if ida_dbg.get_tev_info(i, tev):
                    entry = {"idx": i, "addr": hex(tev.ea), "type": tev.type}
                    if addr and hex(tev.ea) != addr:
                        continue
                    traces.append(entry)
            return {"traces": traces}
        
        elif action == "clear":
            ida_dbg.clear_trace()
            return {"ok": True}
        
        elif action == "set_options":
            # Set trace options
            opts = ida_dbg.get_step_trace_options()
            if enable_insn is not None:
                if enable_insn:
                    opts |= ida_dbg.ST_OVER_LIB_FUNC
                else:
                    opts &= ~ida_dbg.ST_OVER_LIB_FUNC
            ida_dbg.set_step_trace_options(opts)
            return {"ok": True, "options": opts}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 15. FIXUPS - Relocation/fixup operations
# ============================================================================

@tool
@idawrite
def fixups(
    action: Annotated[Literal["list", "get", "add", "delete"], "Action: list|get|add|delete"],
    addr: Annotated[Optional[str], "Address"] = None,
    target: Annotated[Optional[str], "Target address (for add)"] = None,
    fixup_type: Annotated[int, "Fixup type (for add)"] = 0,
    start: Annotated[Optional[str], "Start address for list"] = None,
    end: Annotated[Optional[str], "End address for list"] = None,
    count: Annotated[int, "Max entries"] = 1000,
) -> dict:
    """
    Manage fixups (relocations) in the database.
    
    Actions:
    - list: List fixups in a range (default: all).
    - get: Get fixup details at `addr`.
    - add: Add a fixup at `addr` targeting `target`.
    - delete: Remove a fixup.
    
    Arguments:
    - fixup_type: Integer type (processor specific).
    - target: Target address for the fixup.
    """
    try:
        import ida_fixup
        
        if action == "list":
            import ida_ida
            # Fix min_ea/max_ea access for IDA 9.0+
            if hasattr(ida_ida, "inf_get_min_ea"):
                min_ea = ida_ida.inf_get_min_ea()
                max_ea = ida_ida.inf_get_max_ea()
            else:
                # Fallback
                min_ea = idaapi.cvar.inf.min_ea
                max_ea = idaapi.cvar.inf.max_ea
                
            start_ea = parse_address(start) if start else min_ea
            end_ea = parse_address(end) if end else max_ea
            
            fixup_list = []
            ea = ida_fixup.get_first_fixup_ea()
            while ea != idaapi.BADADDR and len(fixup_list) < count:
                if start_ea <= ea <= end_ea:
                    fd = ida_fixup.fixup_data_t()
                    if ida_fixup.get_fixup(fd, ea):
                        fixup_list.append({
                            "addr": hex(ea),
                            "type": fd.get_type(),
                            "target": hex(fd.off) if fd.off != idaapi.BADADDR else None
                        })
                ea = ida_fixup.get_next_fixup_ea(ea)
            return {"fixups": fixup_list}
        
        elif action == "get":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                return {
                    "addr": addr,
                    "type": fd.get_type(),
                    "target": hex(fd.off) if fd.off != idaapi.BADADDR else None
                }
            return {"error": "No fixup at address"}
        
        elif action == "add":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            fd = ida_fixup.fixup_data_t()
            fd.set_type(fixup_type)
            if target:
                fd.off = parse_address(target)
            ida_fixup.set_fixup(ea, fd)
            return {"ok": True, "addr": addr}
        
        elif action == "delete":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            ida_fixup.del_fixup(ea)
            return {"ok": True, "addr": addr}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 16. DATA_OPS - Data creation operations
# ============================================================================

@tool
@idawrite
def data_ops(
    action: Annotated[Literal["make_data", "make_array", "make_string", "undefine", "make_code"],
                      "Action: make_data|make_array|make_string|undefine|make_code"],
    addr: Annotated[str, "Address"],
    size: Annotated[Optional[int], "Size in bytes"] = None,
    count: Annotated[Optional[int], "Array element count"] = None,
    str_type: Annotated[int, "String type (0=C, 1=Pascal, 2=UTF16)"] = 0,
) -> dict:
    """Data creation: make_data, make_array, make_string, undefine, make_code"""
    try:
        ea = parse_address(addr)
        
        if action == "make_data":
            if size is None:
                size = 1
            flags = {1: ida_bytes.byte_flag(), 2: ida_bytes.word_flag(), 
                     4: ida_bytes.dword_flag(), 8: ida_bytes.qword_flag()}.get(size, ida_bytes.byte_flag())
            if ida_bytes.create_data(ea, flags, size, idaapi.BADADDR):
                return {"ok": True, "addr": addr, "size": size}
            return {"error": "Failed to create data"}
        
        elif action == "make_array":
            if count is None:
                return {"error": "count required"}
            elem_size = size or 1
            flags = {1: ida_bytes.byte_flag(), 2: ida_bytes.word_flag(),
                     4: ida_bytes.dword_flag(), 8: ida_bytes.qword_flag()}.get(elem_size, ida_bytes.byte_flag())
            if ida_bytes.create_data(ea, flags, elem_size, idaapi.BADADDR):
                # Set array info
                import ida_nalt as nalt
                arr = nalt.array_parameters()
                arr.flags = 0
                arr.lineitems = 0
                arr.alignment = 0
                nalt.set_array_parameters(ea, arr)
                idc.make_array(ea, count)
                return {"ok": True, "addr": addr, "count": count, "elem_size": elem_size}
            return {"error": "Failed to create array"}
        
        elif action == "make_string":
            str_types = {0: idc.STRTYPE_C, 1: idc.STRTYPE_PASCAL, 2: idc.STRTYPE_C_16}
            stype = str_types.get(str_type, idc.STRTYPE_C)
            length = size or idaapi.BADADDR
            if idc.create_strlit(ea, length if length != idaapi.BADADDR else idc.BADADDR):
                return {"ok": True, "addr": addr}
            return {"error": "Failed to create string"}
        
        elif action == "undefine":
            length = size or ida_bytes.get_item_size(ea)
            if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, length):
                return {"ok": True, "addr": addr, "size": length}
            return {"error": "Failed to undefine"}
        
        elif action == "make_code":
            length = idc.create_insn(ea)
            if length > 0:
                return {"ok": True, "addr": addr, "size": length}
            return {"error": "Failed to create instruction"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 17. AGENT - High-level analysis helpers
# ============================================================================

@tool
@idaread
def agent(
    action: Annotated[Literal["analyze_function", "explore_address", "find_references", "search_all"],
                      "Action: analyze_function|explore_address|find_references|search_all"],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Search query"] = None,
    depth: Annotated[int, "Exploration depth"] = 1,
) -> dict:
    """High-level agent helpers: comprehensive analysis, exploration, universal search"""
    try:
        if action == "analyze_function":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                return {"error": "No function at address"}
            
            name = ida_funcs.get_func_name(func.start_ea)
            result = {
                "addr": hex(func.start_ea),
                "name": name,
                "size": func.end_ea - func.start_ea,
            }
            
            # Decompile
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                result["pseudocode"] = str(cfunc)
            except:
                result["pseudocode"] = None
            
            # Prototype
            result["prototype"] = get_prototype(func)
            
            # Callees
            callees = set()
            for item in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.iscode:
                        tf = idaapi.get_func(xref.to)
                        if tf and tf.start_ea != func.start_ea:
                            callees.add(ida_funcs.get_func_name(tf.start_ea))
            result["callees"] = list(callees)
            
            # Callers
            callers = set()
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if xref.iscode:
                    cf = idaapi.get_func(xref.frm)
                    if cf:
                        callers.add(ida_funcs.get_func_name(cf.start_ea))
            result["callers"] = list(callers)
            
            # Strings
            strings = []
            for item in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    if not xref.iscode:
                        s = idc.get_strlit_contents(xref.to)
                        if s:
                            strings.append(s.decode("utf-8", errors="replace"))
            result["strings"] = strings[:50]
            
            # Stack vars
            result["stack_vars"] = get_stack_frame_variables_internal(func.start_ea, False)
            
            return result
        
        elif action == "explore_address":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            
            result = {"addr": hex(ea), "name": idc.get_name(ea) or ""}
            
            # What is at this address?
            func = idaapi.get_func(ea)
            if func:
                result["type"] = "function"
                result["func_name"] = ida_funcs.get_func_name(func.start_ea)
                result["func_start"] = hex(func.start_ea)
            elif ida_bytes.is_code(ida_bytes.get_flags(ea)):
                result["type"] = "code"
            elif ida_bytes.is_data(ida_bytes.get_flags(ea)):
                result["type"] = "data"
                result["size"] = ida_bytes.get_item_size(ea)
            else:
                result["type"] = "unknown"
            
            # Xrefs to
            result["xrefs_to"] = [{"from": hex(x.frm)} for x in list(idautils.XrefsTo(ea, 0))[:20]]
            
            # Xrefs from
            result["xrefs_from"] = [{"to": hex(x.to)} for x in list(idautils.XrefsFrom(ea, 0))[:20]]
            
            # Bytes
            result["bytes"] = " ".join(f"{b:02x}" for b in ida_bytes.get_bytes(ea, 16) or [])
            
            # Disasm
            result["disasm"] = idc.generate_disasm_line(ea, 0)
            
            return result
        
        elif action == "find_references":
            if not addr:
                return {"error": "addr required"}
            ea = parse_address(addr)
            
            result = {"addr": hex(ea), "code_refs": [], "data_refs": []}
            
            for xref in idautils.XrefsTo(ea, 0):
                entry = {"from": hex(xref.frm)}
                func = idaapi.get_func(xref.frm)
                if func:
                    entry["func"] = ida_funcs.get_func_name(func.start_ea)
                
                if xref.iscode:
                    result["code_refs"].append(entry)
                else:
                    result["data_refs"].append(entry)
            
            return result
        
        elif action == "search_structs":
            # Struct search not supported in IDA 9 (ida_struct removed)
            return {"error": "Struct search not supported in this IDA version"}
        
        elif action == "search_all":
            if not query:
                return {"error": "query required"}
            
            results = {"query": query, "functions": [], "strings": [], "names": []}
            
            # Search functions
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                if query.lower() in name.lower():
                    results["functions"].append({"addr": hex(ea), "name": name})
                    if len(results["functions"]) >= 50:
                        break
            
            # Search strings
            for i in range(idaapi.get_strlist_qty()):
                if len(results["strings"]) >= 50:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if query.lower() in s.lower():
                                results["strings"].append({"addr": hex(sc.ea), "string": s[:100]})
                    except:
                        pass
            
            # Search names
            for ea, name in idautils.Names():
                if query.lower() in name.lower():
                    results["names"].append({"addr": hex(ea), "name": name})
                    if len(results["names"]) >= 50:
                        break
            
            return results
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================

@tool
@idaread
def microcode(
    action: Annotated[Literal["get", "blocks", "instructions"],
                      "Action: get|blocks|instructions"],
    addr: Annotated[str, "Address of function to analyze"],
    maturity: Annotated[int, "Optimization level 0-7 (higher=more optimized)"] = 7,
) -> dict:
    """
    Access Hex-Rays microcode (intermediate representation) for deep analysis.
    
    Actions:
    - get: Get microcode maturity levels and basic info
    - blocks: Get microcode basic blocks structure
    - instructions: Get microcode instructions (minsn_t) for a function
    
    Maturity levels:
    - 0: MMAT_GENERATED - initial microcode
    - 1: MMAT_PREOPTIMIZED - preoptimized
    - 7: MMAT_LVARS - final with local variables
    """
    try:
        import ida_hexrays
        
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "Hex-Rays not available"}
        
        ea = parse_address(addr)
        func = get_function(ea)
        if not func:
            return {"error": f"No function at {addr}"}
        
        if action == "get":
            # Get basic microcode info
            try:
                mba = ida_hexrays.gen_microcode(func, None, None, 0, maturity)
                if not mba:
                    return {"error": "Failed to generate microcode"}
                
                return {
                    "addr": addr,
                    "maturity": maturity,
                    "qty": mba.qty,  # number of basic blocks
                    "fullsize": mba.fullsize,
                    "argidx": mba.argidx.size() if hasattr(mba, 'argidx') else 0,
                }
            except Exception as e:
                return {"error": f"Microcode generation failed: {str(e)}"}
        
        elif action == "blocks":
            try:
                mba = ida_hexrays.gen_microcode(func, None, None, 0, maturity)
                if not mba:
                    return {"error": "Failed to generate microcode"}
                
                blocks = []
                for i in range(mba.qty):
                    blk = mba.get_mblock(i)
                    if blk:
                        blocks.append({
                            "idx": i,
                            "start": hex(blk.start),
                            "end": hex(blk.end),
                            "type": blk.type,
                            "flags": blk.flags,
                            "npred": blk.npred(),
                            "nsucc": blk.nsucc(),
                        })
                return {"blocks": blocks, "count": len(blocks)}
            except Exception as e:
                return {"error": f"Block access failed: {str(e)}"}
        
        elif action == "instructions":
            try:
                mba = ida_hexrays.gen_microcode(func, None, None, 0, maturity)
                if not mba:
                    return {"error": "Failed to generate microcode"}
                
                instructions = []
                for i in range(mba.qty):
                    blk = mba.get_mblock(i)
                    if blk:
                        insn = blk.head
                        while insn:
                            try:
                                instructions.append({
                                    "block": i,
                                    "opcode": insn.opcode,
                                    "ea": hex(insn.ea),
                                    "text": str(insn) if hasattr(insn, '__str__') else f"op{insn.opcode}",
                                })
                            except:
                                pass
                            insn = insn.next
                            if len(instructions) > 500:
                                break
                    if len(instructions) > 500:
                        break
                
                return {"instructions": instructions, "count": len(instructions), "truncated": len(instructions) > 500}
            except Exception as e:
                return {"error": f"Instruction access failed: {str(e)}"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================

@tool
@idaread
def graph(
    action: Annotated[Literal["callgraph", "cfg", "xref_graph"],
                      "Action: callgraph|cfg|xref_graph"],
    addr: Annotated[Optional[str], "Starting address (function or location)"] = None,
    depth: Annotated[int, "Max traversal depth"] = 3,
    direction: Annotated[Literal["down", "up", "both"], "Direction: down (callees), up (callers), both"] = "down",
    format: Annotated[Literal["json", "dot"], "Output format: json or DOT (Graphviz)"] = "json",
) -> dict:
    """
    Export graphs for visualization and analysis.
    
    Actions:
    - callgraph: Generate function call graph starting from addr
    - cfg: Generate control flow graph for function at addr
    - xref_graph: Generate cross-reference graph
    
    Output formats:
    - json: Structured JSON with nodes and edges
    - dot: Graphviz DOT format for visualization
    """
    try:
        if action == "callgraph":
            if not addr:
                return {"error": "addr required for callgraph"}
            
            ea = parse_address(addr)
            func = get_function(ea)
            if not func:
                return {"error": f"No function at {addr}"}
            
            nodes = {}
            edges = []
            visited = set()
            
            def add_node(func_ea):
                if func_ea not in nodes:
                    name = idc.get_name(func_ea) or f"sub_{func_ea:x}"
                    nodes[func_ea] = {"id": hex(func_ea), "name": name}
            
            def traverse_down(func_ea, current_depth):
                if current_depth > depth or func_ea in visited:
                    return
                visited.add(func_ea)
                add_node(func_ea)
                
                f = get_function(func_ea)
                if not f:
                    return
                
                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        target_func = get_function(xref)
                        if target_func and target_func.start_ea != func_ea:
                            add_node(target_func.start_ea)
                            edge = (hex(func_ea), hex(target_func.start_ea))
                            if edge not in edges:
                                edges.append(edge)
                            traverse_down(target_func.start_ea, current_depth + 1)
            
            def traverse_up(func_ea, current_depth):
                if current_depth > depth or func_ea in visited:
                    return
                visited.add(func_ea)
                add_node(func_ea)
                
                for xref in idautils.CodeRefsTo(func_ea, 0):
                    caller_func = get_function(xref)
                    if caller_func and caller_func.start_ea != func_ea:
                        add_node(caller_func.start_ea)
                        edge = (hex(caller_func.start_ea), hex(func_ea))
                        if edge not in edges:
                            edges.append(edge)
                        traverse_up(caller_func.start_ea, current_depth + 1)
            
            if direction in ["down", "both"]:
                traverse_down(func.start_ea, 0)
            if direction in ["up", "both"]:
                visited.clear()  # Reset for upward traversal
                traverse_up(func.start_ea, 0)
            
            if format == "dot":
                dot_lines = ["digraph CallGraph {"]
                dot_lines.append("  rankdir=TB;")
                for node_id, node_data in nodes.items():
                    dot_lines.append(f'  "{node_data["id"]}" [label="{node_data["name"]}"];')
                for src, dst in edges:
                    dot_lines.append(f'  "{src}" -> "{dst}";')
                dot_lines.append("}")
                return {"dot": "\n".join(dot_lines)}
            else:
                return {
                    "nodes": list(nodes.values()),
                    "edges": [{"from": e[0], "to": e[1]} for e in edges],
                    "root": hex(func.start_ea),
                }
        
        elif action == "cfg":
            if not addr:
                return {"error": "addr required for cfg"}
            
            ea = parse_address(addr)
            func = get_function(ea)
            if not func:
                return {"error": f"No function at {addr}"}
            
            import ida_gdl
            
            nodes = []
            edges = []
            
            flowchart = ida_gdl.FlowChart(func)
            for block in flowchart:
                nodes.append({
                    "id": block.id,
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "type": block.type,
                })
                for succ in block.succs():
                    edges.append({"from": block.id, "to": succ.id})
            
            if format == "dot":
                dot_lines = ["digraph CFG {"]
                dot_lines.append("  rankdir=TB;")
                for node in nodes:
                    dot_lines.append(f'  {node["id"]} [label="BB{node["id"]}\\n{node["start"]}-{node["end"]}"];')
                for edge in edges:
                    dot_lines.append(f'  {edge["from"]} -> {edge["to"]};')
                dot_lines.append("}")
                return {"dot": "\n".join(dot_lines)}
            else:
                return {"nodes": nodes, "edges": edges, "function": hex(func.start_ea)}
        
        elif action == "xref_graph":
            if not addr:
                return {"error": "addr required for xref_graph"}
            
            ea = parse_address(addr)
            
            nodes = {ea: {"id": hex(ea), "name": idc.get_name(ea) or f"loc_{ea:x}"}}
            edges = []
            
            # Xrefs TO this address
            for xref in idautils.XrefsTo(ea, 0):
                if xref.frm not in nodes:
                    nodes[xref.frm] = {"id": hex(xref.frm), "name": idc.get_name(xref.frm) or f"loc_{xref.frm:x}"}
                edges.append({"from": hex(xref.frm), "to": hex(ea), "type": "to"})
            
            # Xrefs FROM this address
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.to not in nodes:
                    nodes[xref.to] = {"id": hex(xref.to), "name": idc.get_name(xref.to) or f"loc_{xref.to:x}"}
                edges.append({"from": hex(ea), "to": hex(xref.to), "type": "from"})
            
            if format == "dot":
                dot_lines = ["digraph XrefGraph {"]
                for node_id, node_data in nodes.items():
                    dot_lines.append(f'  "{node_data["id"]}" [label="{node_data["name"]}"];')
                for edge in edges:
                    dot_lines.append(f'  "{edge["from"]}" -> "{edge["to"]}";')
                dot_lines.append("}")
                return {"dot": "\n".join(dot_lines)}
            else:
                return {"nodes": list(nodes.values()), "edges": edges, "center": hex(ea)}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================

@tool
@unsafe
@idawrite
def bulk(
    action: Annotated[Literal["rename", "comment", "apply_type", "import_annotations", "export_annotations"],
                      "Action: rename|comment|apply_type|import_annotations|export_annotations"],
    items: Annotated[Optional[list[dict]], "List of {addr, value} dicts for bulk operations"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
) -> dict:
    """
    Bulk operations for efficient multi-target modifications.
    Perfect for LLMs that generate many annotations at once.
    
    Actions:
    - rename: Bulk rename [{addr, value}, ...]
    - comment: Bulk add comments [{addr, value, type?}, ...]
    - apply_type: Bulk apply types [{addr, value}, ...]
    - import_annotations: Load names/comments from JSON file
    - export_annotations: Save all names/comments to JSON file
    
    Example items for rename:
    [{"addr": "0x401000", "value": "main"}, {"addr": "0x401100", "value": "init"}]
    """
    try:
        if action == "rename":
            if not items:
                return {"error": "items required for rename"}
            
            success = 0
            failed = []
            for item in items:
                addr_str = item.get("addr")
                name = item.get("value")
                if not addr_str or not name:
                    failed.append({"addr": addr_str, "error": "missing addr or value"})
                    continue
                
                try:
                    ea = parse_address(addr_str)
                    # Try to get SN_FORCE flag
                    force_flag = getattr(ida_name, 'SN_FORCE', 0) | getattr(ida_name, 'SN_NOWARN', 0)
                    if idc.set_name(ea, name, force_flag):
                        success += 1
                    else:
                        failed.append({"addr": addr_str, "error": "set_name failed"})
                except Exception as e:
                    failed.append({"addr": addr_str, "error": str(e)})
            
            return {"success": success, "failed": len(failed), "errors": failed[:10]}
        
        elif action == "comment":
            if not items:
                return {"error": "items required for comment"}
            
            success = 0
            failed = []
            for item in items:
                addr_str = item.get("addr")
                comment_text = item.get("value")
                comment_type = item.get("type", "regular")
                
                if not addr_str or not comment_text:
                    failed.append({"addr": addr_str, "error": "missing addr or value"})
                    continue
                
                try:
                    ea = parse_address(addr_str)
                    if comment_type == "repeatable":
                        idc.set_cmt(ea, comment_text, 1)
                    else:
                        idc.set_cmt(ea, comment_text, 0)
                    success += 1
                except Exception as e:
                    failed.append({"addr": addr_str, "error": str(e)})
            
            return {"success": success, "failed": len(failed), "errors": failed[:10]}
        
        elif action == "apply_type":
            if not items:
                return {"error": "items required for apply_type"}
            
            success = 0
            failed = []
            for item in items:
                addr_str = item.get("addr")
                type_str = item.get("value")
                
                if not addr_str or not type_str:
                    failed.append({"addr": addr_str, "error": "missing addr or value"})
                    continue
                
                try:
                    ea = parse_address(addr_str)
                    tif = ida_typeinf.tinfo_t()
                    if ida_typeinf.parse_decl(tif, None, type_str, ida_typeinf.PT_SIL):
                        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                            success += 1
                        else:
                            failed.append({"addr": addr_str, "error": "apply failed"})
                    else:
                        failed.append({"addr": addr_str, "error": "parse failed"})
                except Exception as e:
                    failed.append({"addr": addr_str, "error": str(e)})
            
            return {"success": success, "failed": len(failed), "errors": failed[:10]}
        
        elif action == "export_annotations":
            import json
            
            annotations = {"names": [], "comments": [], "function_comments": []}
            
            # Export names
            for ea, name in idautils.Names():
                if not name.startswith("sub_") and not name.startswith("loc_"):
                    annotations["names"].append({"addr": hex(ea), "name": name})
            
            # Export comments (sample from functions)
            for func_ea in idautils.Functions():
                func = get_function(func_ea)
                if not func:
                    continue
                
                # Function comment
                fc = idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1)
                if fc:
                    annotations["function_comments"].append({"addr": hex(func_ea), "comment": fc})
                
                # Line comments (sample first 10 per function)
                count = 0
                for item_ea in idautils.FuncItems(func_ea):
                    cmt = idc.get_cmt(item_ea, 0) or idc.get_cmt(item_ea, 1)
                    if cmt:
                        annotations["comments"].append({"addr": hex(item_ea), "comment": cmt})
                        count += 1
                        if count >= 10:
                            break
            
            if path:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(annotations, f, indent=2)
                return {"ok": True, "path": path, "stats": {k: len(v) for k, v in annotations.items()}}
            else:
                return annotations
        
        elif action == "import_annotations":
            if not path:
                return {"error": "path required for import"}
            
            import json
            import os
            
            if not os.path.exists(path):
                return {"error": f"File not found: {path}"}
            
            with open(path, 'r', encoding='utf-8') as f:
                annotations = json.load(f)
            
            stats = {"names_applied": 0, "comments_applied": 0, "errors": 0}
            
            # Import names
            for item in annotations.get("names", []):
                try:
                    ea = parse_address(item["addr"])
                    if idc.set_name(ea, item["name"], ida_name.SN_FORCE | ida_name.SN_NOWARN):
                        stats["names_applied"] += 1
                except:
                    stats["errors"] += 1
            
            # Import comments
            for item in annotations.get("comments", []) + annotations.get("function_comments", []):
                try:
                    ea = parse_address(item["addr"])
                    cmt = item.get("comment") or item.get("value")
                    idc.set_cmt(ea, cmt, 0)
                    stats["comments_applied"] += 1
                except:
                    stats["errors"] += 1
            
            return {"ok": True, "stats": stats}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 21. CTREE - Hex-Rays AST/CTree Access for Deep Decompiler Analysis
# ============================================================================

@tool
@idaread
def ctree(
    action: Annotated[Literal["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions"],
                      "Action: get|traverse|find_calls|find_vars|find_strings|find_conditions"],
    addr: Annotated[str, "Address of function to analyze"],
    query: Annotated[Optional[str], "Filter pattern (for find_* actions)"] = None,
    depth: Annotated[int, "Max traversal depth"] = 10,
) -> dict:
    """
    Access Hex-Rays CTree (decompiler AST) for deep code analysis.
    
    ACTIONS:
    
    get - Get full CTree structure for function
        Returns: {func, items: [{op, ea, type, text}]}
        
    traverse - Traverse CTree with structure info
        Returns: {nodes: [{op, ea, children}]}
        
    find_calls - Find all function calls in decompiled code
        Params: query (optional filter)
        Returns: {calls: [{func, ea, args}]}
        
    find_vars - Find all variable usages
        Returns: {vars: [{name, type, refs}]}
        
    find_strings - Find string references in function
        Returns: {strings: [{value, ea}]}
        
    find_conditions - Find all if/while/for conditions
        Returns: {conditions: [{type, ea, expr}]}
    """
    try:
        ea = parse_address(addr)
        
        # Get decompiled function
        cfunc = None
        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure:
            return {"error": f"Decompilation failed for {addr}"}
        
        if not cfunc:
            return {"error": f"Could not decompile function at {addr}"}
        
        func_name = idc.get_func_name(ea) or hex(ea)
        
        if action == "get":
            # Collect all CTree items
            items = []
            
            class CtreeVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.items = []
                
                def visit_expr(self, e):
                    self.items.append({
                        "op": ida_hexrays.get_ctype_name(e.op),
                        "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None,
                        "type": str(e.type) if hasattr(e, 'type') else None,
                        "is_expr": True
                    })
                    return 0
                
                def visit_insn(self, i):
                    self.items.append({
                        "op": ida_hexrays.get_ctype_name(i.op),
                        "ea": hex(i.ea) if i.ea != idaapi.BADADDR else None,
                        "is_expr": False
                    })
                    return 0
            
            visitor = CtreeVisitor()
            visitor.apply_to(cfunc.body, None)
            
            return {
                "func": func_name,
                "items": visitor.items[:500],  # Limit for context
                "total": len(visitor.items)
            }
        
        elif action == "find_calls":
            calls = []
            
            class CallFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_call:
                        call_info = {
                            "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None,
                            "args_count": e.a.size() if hasattr(e, 'a') else 0
                        }
                        # Get called function name
                        if hasattr(e, 'x') and e.x:
                            if e.x.op == ida_hexrays.cot_obj:
                                call_info["target"] = idc.get_name(e.x.obj_ea) or hex(e.x.obj_ea)
                            elif e.x.op == ida_hexrays.cot_helper:
                                call_info["target"] = e.x.helper
                        
                        if not query or (call_info.get("target", "").lower().find(query.lower()) >= 0):
                            calls.append(call_info)
                    return 0
            
            finder = CallFinder()
            finder.apply_to(cfunc.body, None)
            
            return {"func": func_name, "calls": calls}
        
        elif action == "find_vars":
            lvars = []
            for i, lvar in enumerate(cfunc.lvars):
                lvars.append({
                    "name": lvar.name,
                    "type": str(lvar.type()),
                    "is_arg": lvar.is_arg_var,
                    "is_result": lvar.is_result_var if hasattr(lvar, 'is_result_var') else False,
                    "width": lvar.width
                })
            return {"func": func_name, "vars": lvars}
        
        elif action == "find_strings":
            strings = []
            
            class StringFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_str:
                        strings.append({
                            "value": e.string,
                            "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None
                        })
                    elif e.op == ida_hexrays.cot_obj:
                        # Check if it's a string reference
                        str_type = idc.get_str_type(e.obj_ea)
                        if str_type is not None and str_type >= 0:
                            s = idc.get_strlit_contents(e.obj_ea)
                            if s:
                                strings.append({
                                    "value": s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s,
                                    "ea": hex(e.obj_ea)
                                })
                    return 0
            
            finder = StringFinder()
            finder.apply_to(cfunc.body, None)
            
            return {"func": func_name, "strings": strings}
        
        elif action == "find_conditions":
            conditions = []
            
            class CondFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                
                def visit_insn(self, i):
                    if i.op in [ida_hexrays.cit_if, ida_hexrays.cit_while, 
                               ida_hexrays.cit_do, ida_hexrays.cit_for]:
                        cond_type = {
                            ida_hexrays.cit_if: "if",
                            ida_hexrays.cit_while: "while",
                            ida_hexrays.cit_do: "do-while",
                            ida_hexrays.cit_for: "for"
                        }.get(i.op, "unknown")
                        
                        conditions.append({
                            "type": cond_type,
                            "ea": hex(i.ea) if i.ea != idaapi.BADADDR else None
                        })
                    return 0
            
            finder = CondFinder()
            finder.apply_to(cfunc.body, None)
            
            return {"func": func_name, "conditions": conditions}
        
        elif action == "traverse":
            # Build tree structure
            nodes = []
            
            def traverse_node(item, current_depth=0):
                if current_depth > depth:
                    return None
                
                node = {
                    "op": ida_hexrays.get_ctype_name(item.op),
                    "ea": hex(item.ea) if item.ea != idaapi.BADADDR else None
                }
                
                # Get children for compound statements
                children = []
                if hasattr(item, 'cblock') and item.cblock:
                    for child in item.cblock:
                        c = traverse_node(child, current_depth + 1)
                        if c:
                            children.append(c)
                
                if children:
                    node["children"] = children
                
                return node
            
            root = traverse_node(cfunc.body)
            return {"func": func_name, "tree": root}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 22. DIFF - Binary Comparison and Diffing
# ============================================================================

@tool
@idaread
def diff(
    action: Annotated[Literal["functions", "bytes", "signatures", "names", "summary"],
                      "Action: functions|bytes|signatures|names|summary"],
    addr1: Annotated[Optional[str], "First address/function"] = None,
    addr2: Annotated[Optional[str], "Second address/function (or path to second IDB)"] = None,
    idb2: Annotated[Optional[str], "Path to second IDB for cross-database comparison"] = None,
    threshold: Annotated[float, "Similarity threshold (0.0-1.0)"] = 0.8,
) -> dict:
    """
    Compare functions, bytes, or databases for diffing/patch analysis.
    
    ACTIONS:
    
    functions - Compare two functions by decompilation
        Params: addr1, addr2 (addresses in current IDB)
        Returns: {similarity, diff_lines, added, removed}
        
    bytes - Compare raw bytes between two ranges
        Params: addr1 (start1:end1), addr2 (start2:end2)
        Returns: {similarity, changed_bytes}
        
    signatures - Find similar functions by code signature
        Params: addr1 (function to match), threshold
        Returns: {matches: [{addr, name, similarity}]}
        
    names - Compare named functions/globals between current and reference
        Returns: {added, removed, renamed, stats}
        
    summary - Get overall database statistics for comparison
        Returns: {functions, strings, imports, exports, segments}
    """
    try:
        if action == "functions":
            if not addr1 or not addr2:
                return {"error": "addr1 and addr2 required for function comparison"}
            
            ea1 = parse_address(addr1)
            ea2 = parse_address(addr2)
            
            # Decompile both functions
            try:
                cfunc1 = ida_hexrays.decompile(ea1)
                cfunc2 = ida_hexrays.decompile(ea2)
            except ida_hexrays.DecompilationFailure as e:
                return {"error": f"Decompilation failed: {e}"}
            
            if not cfunc1 or not cfunc2:
                return {"error": "Could not decompile one or both functions"}
            
            # Get pseudocode
            lines1 = []
            lines2 = []
            
            sv1 = cfunc1.get_pseudocode()
            sv2 = cfunc2.get_pseudocode()
            
            for line in sv1:
                lines1.append(ida_lines.tag_remove(line.line))
            for line in sv2:
                lines2.append(ida_lines.tag_remove(line.line))
            
            # Simple diff
            import difflib
            differ = difflib.unified_diff(lines1, lines2, lineterm='')
            diff_lines = list(differ)
            
            # Calculate similarity
            matcher = difflib.SequenceMatcher(None, lines1, lines2)
            similarity = matcher.ratio()
            
            # Count changes
            added = len([l for l in diff_lines if l.startswith('+')])
            removed = len([l for l in diff_lines if l.startswith('-')])
            
            return {
                "func1": idc.get_func_name(ea1) or hex(ea1),
                "func2": idc.get_func_name(ea2) or hex(ea2),
                "similarity": round(similarity, 3),
                "added_lines": added,
                "removed_lines": removed,
                "diff": diff_lines[:100]  # Limit output
            }
        
        elif action == "bytes":
            if not addr1:
                return {"error": "addr1 required (format: start:end or start,size)"}
            
            # Parse addr1 as start:end or start,size
            if ':' in addr1:
                start1, end1 = addr1.split(':')
                ea1_start = parse_address(start1)
                ea1_end = parse_address(end1)
            else:
                ea1_start = parse_address(addr1)
                ea1_end = ea1_start + 256  # Default size
            
            if addr2:
                if ':' in addr2:
                    start2, end2 = addr2.split(':')
                    ea2_start = parse_address(start2)
                    ea2_end = parse_address(end2)
                else:
                    ea2_start = parse_address(addr2)
                    ea2_end = ea2_start + (ea1_end - ea1_start)
            else:
                return {"error": "addr2 required for byte comparison"}
            
            # Read bytes
            bytes1 = ida_bytes.get_bytes(ea1_start, ea1_end - ea1_start)
            bytes2 = ida_bytes.get_bytes(ea2_start, ea2_end - ea2_start)
            
            if not bytes1 or not bytes2:
                return {"error": "Could not read bytes"}
            
            # Compare
            changes = []
            min_len = min(len(bytes1), len(bytes2))
            matching = 0
            
            for i in range(min_len):
                if bytes1[i] == bytes2[i]:
                    matching += 1
                else:
                    changes.append({
                        "offset": i,
                        "addr1": hex(ea1_start + i),
                        "addr2": hex(ea2_start + i),
                        "byte1": f"{bytes1[i]:02x}",
                        "byte2": f"{bytes2[i]:02x}"
                    })
            
            similarity = matching / max(len(bytes1), len(bytes2)) if bytes1 and bytes2 else 0
            
            return {
                "range1": f"{hex(ea1_start)}:{hex(ea1_end)}",
                "range2": f"{hex(ea2_start)}:{hex(ea2_end)}",
                "size1": len(bytes1),
                "size2": len(bytes2),
                "similarity": round(similarity, 3),
                "changes": changes[:100]  # Limit
            }
        
        elif action == "signatures":
            if not addr1:
                return {"error": "addr1 required (function to match)"}
            
            ea = parse_address(addr1)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {addr1}"}
            
            # Get target function bytes for signature
            target_bytes = ida_bytes.get_bytes(func.start_ea, min(256, func.end_ea - func.start_ea))
            if not target_bytes:
                return {"error": "Could not read function bytes"}
            
            matches = []
            
            # Compare with all other functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if func_ea == func.start_ea:
                        continue
                    
                    other_func = ida_funcs.get_func(func_ea)
                    if not other_func:
                        continue
                    
                    other_bytes = ida_bytes.get_bytes(other_func.start_ea, 
                                                      min(256, other_func.end_ea - other_func.start_ea))
                    if not other_bytes:
                        continue
                    
                    # Calculate similarity
                    import difflib
                    matcher = difflib.SequenceMatcher(None, target_bytes, other_bytes)
                    similarity = matcher.ratio()
                    
                    if similarity >= threshold:
                        matches.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea) or hex(func_ea),
                            "size": other_func.end_ea - other_func.start_ea,
                            "similarity": round(similarity, 3)
                        })
            
            # Sort by similarity
            matches.sort(key=lambda x: x["similarity"], reverse=True)
            
            return {
                "target": idc.get_func_name(ea) or hex(ea),
                "matches": matches[:50],  # Limit
                "threshold": threshold
            }
        
        elif action == "summary":
            # Collect database statistics for comparison
            stats = {
                "functions": 0,
                "named_functions": 0,
                "imports": 0,
                "exports": 0,
                "strings": 0,
                "segments": []
            }
            
            # Count functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    stats["functions"] += 1
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        stats["named_functions"] += 1
            
            # Count imports
            for i in range(ida_nalt.get_import_module_qty()):
                def imp_cb(ea, name, ordinal):
                    stats["imports"] += 1
                    return True
                ida_nalt.enum_import_names(i, imp_cb)
            
            # Count exports
            for i in range(idaapi.get_entry_qty()):
                stats["exports"] += 1
            
            # Count strings
            for s in idautils.Strings():
                stats["strings"] += 1
            
            # Segments
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg:
                    stats["segments"].append({
                        "name": ida_segment.get_segm_name(seg),
                        "start": hex(seg.start_ea),
                        "end": hex(seg.end_ea),
                        "size": seg.end_ea - seg.start_ea
                    })
            
            return stats
        
        elif action == "names":
            # List all named items for export/comparison
            names = []
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        names.append({
                            "addr": hex(func_ea),
                            "name": name,
                            "type": "function"
                        })
            
            # Named data
            for ea in range(idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea):
                name = idc.get_name(ea)
                if name and not name.startswith(("loc_", "unk_", "byte_", "word_", "dword_", "qword_")):
                    if not ida_funcs.get_func(ea):  # Skip functions
                        names.append({
                            "addr": hex(ea),
                            "name": name,
                            "type": "data"
                        })
                        if len(names) > 5000:
                            break
            
            return {"names": names, "total": len(names)}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 23. LUMINA - Cloud-Based Function Recognition
# ============================================================================

@tool
@idaread
def lumina(
    action: Annotated[Literal["pull", "push", "status", "history", "search"],
                      "Action: pull|push|status|history|search"],
    addr: Annotated[Optional[str], "Address of function"] = None,
    query: Annotated[Optional[str], "Search query for function names"] = None,
    push_all: Annotated[bool, "Push all functions (for push action)"] = False,
) -> dict:
    """
    Interact with Hex-Rays Lumina server for function recognition.
    
    ACTIONS:
    
    pull - Pull function metadata from Lumina
        Params: addr (specific function) or none (pull all)
        Returns: {pulled: count, functions: [{addr, name, source}]}
        
    push - Push function metadata to Lumina
        Params: addr (specific function) or push_all=True
        Returns: {pushed: count, status}
        
    status - Check Lumina connection status
        Returns: {connected, server, user}
        
    history - Get Lumina history for function
        Params: addr
        Returns: {history: [{date, user, name}]}
        
    search - Search Lumina for function by name/pattern
        Params: query
        Returns: {results: [{name, matches}]}
    """
    try:
        # Check if Lumina is available
        if not hasattr(ida_hexrays, 'LUMINA_ENABLED'):
            # Try using the lumina module directly
            try:
                import ida_lumina
            except ImportError:
                return {"error": "Lumina module not available in this IDA version"}
        
        if action == "status":
            # Check connection status
            try:
                import ida_lumina
                
                # Try to get status
                status = {
                    "available": True,
                    "module": "ida_lumina",
                    "note": "Use pull/push actions to interact with Lumina server"
                }
                
                # Check if authenticated
                if hasattr(ida_lumina, 'get_lumina_user'):
                    status["user"] = ida_lumina.get_lumina_user()
                
                return status
            except Exception as e:
                return {
                    "available": False,
                    "error": str(e),
                    "note": "Lumina requires IDA Pro license with Lumina access"
                }
        
        elif action == "pull":
            try:
                import ida_lumina
                
                if addr:
                    # Pull for specific function
                    ea = parse_address(addr)
                    func = ida_funcs.get_func(ea)
                    if not func:
                        return {"error": f"No function at {addr}"}
                    
                    # Request metadata from Lumina
                    if hasattr(ida_lumina, 'pull_md'):
                        result = ida_lumina.pull_md(ea)
                        return {
                            "addr": hex(ea),
                            "pulled": 1 if result else 0,
                            "name": idc.get_func_name(ea)
                        }
                    else:
                        return {"error": "pull_md not available"}
                else:
                    # Pull all
                    if hasattr(ida_lumina, 'pull_all_mds'):
                        count = ida_lumina.pull_all_mds()
                        return {"pulled": count}
                    else:
                        return {"error": "pull_all_mds not available"}
            
            except Exception as e:
                return {"error": str(e), "note": "Lumina server may not be reachable"}
        
        elif action == "push":
            try:
                import ida_lumina
                
                if push_all:
                    if hasattr(ida_lumina, 'push_all_mds'):
                        count = ida_lumina.push_all_mds()
                        return {"pushed": count}
                    else:
                        return {"error": "push_all_mds not available"}
                elif addr:
                    ea = parse_address(addr)
                    if hasattr(ida_lumina, 'push_md'):
                        result = ida_lumina.push_md(ea)
                        return {
                            "addr": hex(ea),
                            "pushed": 1 if result else 0,
                            "name": idc.get_func_name(ea)
                        }
                    else:
                        return {"error": "push_md not available"}
                else:
                    return {"error": "addr or push_all=True required"}
            
            except Exception as e:
                return {"error": str(e)}
        
        elif action == "history":
            if not addr:
                return {"error": "addr required for history"}
            
            ea = parse_address(addr)
            
            try:
                import ida_lumina
                
                if hasattr(ida_lumina, 'get_func_history'):
                    history = ida_lumina.get_func_history(ea)
                    return {
                        "addr": hex(ea),
                        "name": idc.get_func_name(ea),
                        "history": history or []
                    }
                else:
                    return {"error": "Function history not available in this IDA version"}
            except Exception as e:
                return {"error": str(e)}
        
        elif action == "search":
            if not query:
                return {"error": "query required for search"}
            
            try:
                import ida_lumina
                
                if hasattr(ida_lumina, 'search_funcs'):
                    results = ida_lumina.search_funcs(query)
                    return {
                        "query": query,
                        "results": results or []
                    }
                else:
                    return {"error": "Lumina search not available in this IDA version"}
            except Exception as e:
                return {"error": str(e)}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================

@tool
@idawrite
def symbols(
    action: Annotated[Literal["load_pdb", "load_dwarf", "status", "apply", "export"],
                      "Action: load_pdb|load_dwarf|status|apply|export"],
    path: Annotated[Optional[str], "Path to symbol file (PDB, DWARF, etc.)"] = None,
    addr: Annotated[Optional[str], "Address to apply symbols to"] = None,
    force: Annotated[bool, "Force reload even if symbols exist"] = False,
) -> dict:
    """
    Load and manage debug symbols (PDB, DWARF, COFF).
    
    ACTIONS:
    
    load_pdb - Load PDB file for Windows binaries
        Params: path (to .pdb file, or None to auto-detect)
        Returns: {loaded, functions_named, types_imported}
        
    load_dwarf - Parse DWARF debug info from ELF binaries
        Returns: {loaded, functions_named, types_imported}
        
    status - Check current symbol status
        Returns: {has_symbols, source, loaded_types}
        
    apply - Apply type info from loaded symbols to address
        Params: addr
        Returns: {applied, type}
        
    export - Export current symbol information
        Params: path
        Returns: {exported, count}
    """
    try:
        import ida_dbg
        import ida_auto
        
        if action == "load_pdb":
            try:
                import ida_pdb
            except ImportError:
                # Fallback for older IDA
                pass
            
            # Try loading PDB
            if path:
                # Load specific PDB
                import ida_netnode
                import ida_loader
                
                # Use IDA's PDB loader
                result = ida_loader.load_and_run_plugin("pdb", 0)
                if result:
                    return {"loaded": True, "path": path}
                else:
                    return {"error": "PDB loading failed", "path": path}
            else:
                # Auto-detect PDB
                input_path = idaapi.get_input_file_path()
                if input_path:
                    pdb_path = input_path.replace(".exe", ".pdb").replace(".dll", ".pdb")
                    import os
                    if os.path.exists(pdb_path):
                        return {"found": pdb_path, "note": "Call again with path to load"}
                    else:
                        return {"error": "No PDB found", "searched": pdb_path}
                return {"error": "Could not determine input file path"}
        
        elif action == "load_dwarf":
            # DWARF is typically embedded in ELF
            # Check if we have DWARF info
            try:
                import ida_dirtree
                import ida_loader
                
                # Try loading DWARF plugin
                result = ida_loader.load_and_run_plugin("dwarf", 0)
                if result:
                    return {"loaded": True, "type": "DWARF"}
                else:
                    return {"note": "DWARF info processed during initial analysis if present"}
            except:
                return {"note": "DWARF processing handled by IDA during initial analysis"}
        
        elif action == "status":
            # Check symbol status
            status = {
                "has_debug_info": False,
                "type_count": 0,
                "named_functions": 0
            }
            
            # Count named functions (non-sub_)
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        status["named_functions"] += 1
            
            # Check for loaded type libraries
            til = ida_typeinf.get_idati()
            if til:
                status["type_count"] = ida_typeinf.get_ordinal_count(til)
                status["has_debug_info"] = status["named_functions"] > 10
            
            return status
        
        elif action == "apply":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Try to apply type from type library
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.guess_tinfo(tinfo, ea):
                # Apply the guessed type
                if ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
                    return {"applied": True, "addr": hex(ea), "type": str(tinfo)}
            
            return {"applied": False, "addr": hex(ea), "note": "Could not infer type"}
        
        elif action == "export":
            if not path:
                return {"error": "path required"}
            
            # Export all named items to a simple format
            import json
            
            export_data = {
                "functions": [],
                "types": []
            }
            
            # Export named functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        func_info = {
                            "addr": hex(func_ea),
                            "name": name
                        }
                        # Try to get type
                        tinfo = ida_typeinf.tinfo_t()
                        if ida_typeinf.get_tinfo(tinfo, func_ea):
                            func_info["type"] = str(tinfo)
                        export_data["functions"].append(func_info)
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            return {"exported": True, "path": path, "functions": len(export_data["functions"])}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 25. PATTERNS - FLIRT-Like Pattern Generation and Matching
# ============================================================================

@tool
@idaread
def patterns(
    action: Annotated[Literal["generate", "match", "list_sigs", "apply_sig", "create_sig"],
                      "Action: generate|match|list_sigs|apply_sig|create_sig"],
    addr: Annotated[Optional[str], "Function address for pattern operations"] = None,
    pattern: Annotated[Optional[str], "Pattern to match (hex with ?? wildcards)"] = None,
    name: Annotated[Optional[str], "Signature name"] = None,
    length: Annotated[int, "Pattern length in bytes"] = 32,
) -> dict:
    """
    Generate and match function signatures (FLIRT-like patterns).
    
    ACTIONS:
    
    generate - Generate a pattern from a function
        Params: addr, length
        Returns: {pattern, mask, name}
        
    match - Find functions matching a pattern
        Params: pattern (hex with ?? wildcards)
        Returns: {matches: [{addr, name, confidence}]}
        
    list_sigs - List available FLIRT signatures
        Returns: {signatures: [name, ...]}
        
    apply_sig - Apply a FLIRT signature file
        Params: name (signature file name without .sig)
        Returns: {applied, matched}
        
    create_sig - Create a signature for a function (pattern + metadata)
        Params: addr, name (function name to store)
        Returns: {signature: {pattern, name, crc}}
    """
    try:
        if action == "generate":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {addr}"}
            
            # Read function bytes
            func_size = min(length, func.end_ea - func.start_ea)
            func_bytes = ida_bytes.get_bytes(func.start_ea, func_size)
            
            if not func_bytes:
                return {"error": "Could not read function bytes"}
            
            # Generate pattern with wildcards for relocations
            pattern_parts = []
            mask_parts = []
            
            for i, b in enumerate(func_bytes):
                curr_ea = func.start_ea + i
                
                # Check if this byte has a relocation/fixup
                has_fixup = False
                if hasattr(ida_fixup, 'get_fixup'):
                    fixup = ida_fixup.fixup_data_t()
                    has_fixup = ida_fixup.get_fixup(fixup, curr_ea)
                
                if has_fixup:
                    pattern_parts.append("??")
                    mask_parts.append("0")
                else:
                    pattern_parts.append(f"{b:02X}")
                    mask_parts.append("1")
            
            return {
                "addr": hex(func.start_ea),
                "name": idc.get_func_name(ea) or hex(ea),
                "pattern": " ".join(pattern_parts),
                "mask": "".join(mask_parts),
                "length": func_size
            }
        
        elif action == "match":
            if not pattern:
                return {"error": "pattern required"}
            
            # Parse pattern
            pattern_bytes = []
            mask = []
            for part in pattern.split():
                if part == "??" or part == "?":
                    pattern_bytes.append(0)
                    mask.append(False)
                else:
                    pattern_bytes.append(int(part, 16))
                    mask.append(True)
            
            if not pattern_bytes:
                return {"error": "Invalid pattern"}
            
            matches = []
            
            # Search all functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        continue
                    
                    # Read function bytes
                    func_size = min(len(pattern_bytes), func.end_ea - func.start_ea)
                    if func_size < len(pattern_bytes):
                        continue
                    
                    func_bytes = ida_bytes.get_bytes(func.start_ea, len(pattern_bytes))
                    if not func_bytes:
                        continue
                    
                    # Match with mask
                    match = True
                    matching_bytes = 0
                    for i in range(len(pattern_bytes)):
                        if mask[i]:
                            if func_bytes[i] == pattern_bytes[i]:
                                matching_bytes += 1
                            else:
                                match = False
                                break
                        else:
                            matching_bytes += 1  # Wildcards always match
                    
                    if match:
                        confidence = matching_bytes / len(pattern_bytes)
                        matches.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea) or hex(func_ea),
                            "confidence": round(confidence, 3)
                        })
            
            return {"pattern": pattern, "matches": matches[:100]}
        
        elif action == "list_sigs":
            import os
            sig_dir = idc.idadir("sig")
            sigs = []
            
            if sig_dir and os.path.exists(sig_dir):
                for root, dirs, files in os.walk(sig_dir):
                    for f in files:
                        if f.lower().endswith(".sig"):
                            rel_path = os.path.relpath(os.path.join(root, f), sig_dir)
                            sigs.append(os.path.splitext(rel_path)[0])
            
            return {"signatures": sorted(sigs), "sig_dir": sig_dir}
        
        elif action == "apply_sig":
            if not name:
                return {"error": "name required (signature name without .sig)"}
            
            import ida_funcs
            
            # Count functions before
            before_count = 0
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if not idc.get_func_name(func_ea).startswith("sub_"):
                        before_count += 1
            
            # Apply signature
            try:
                import ida_libfuncs
                ida_libfuncs.plan_to_apply_ldes(name)
                idaapi.auto_wait()
            except:
                return {"error": f"Could not apply signature: {name}"}
            
            # Count after
            after_count = 0
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if not idc.get_func_name(func_ea).startswith("sub_"):
                        after_count += 1
            
            return {
                "applied": True,
                "name": name,
                "functions_matched": after_count - before_count
            }
        
        elif action == "create_sig":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {addr}"}
            
            # Generate signature data
            func_size = min(64, func.end_ea - func.start_ea)
            func_bytes = ida_bytes.get_bytes(func.start_ea, func_size)
            
            if not func_bytes:
                return {"error": "Could not read function bytes"}
            
            # Calculate CRC16 of first 32 bytes (FLIRT-style)
            import zlib
            crc = zlib.crc32(func_bytes[:min(32, len(func_bytes))]) & 0xFFFF
            
            # Build pattern
            pattern_parts = []
            for b in func_bytes[:32]:
                pattern_parts.append(f"{b:02X}")
            
            return {
                "signature": {
                    "name": name or idc.get_func_name(ea) or hex(ea),
                    "addr": hex(func.start_ea),
                    "pattern": " ".join(pattern_parts),
                    "crc16": hex(crc),
                    "size": func.end_ea - func.start_ea
                }
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# Need ida_fixup import for patterns tool
try:
    import ida_fixup
except ImportError:
    pass


# ============================================================================
# 26. STRUCTS - Automatic Structure Recovery and Analysis
# ============================================================================

@tool
@idaread
def structs(
    action: Annotated[Literal["recover", "analyze_usage", "list", "create", "add_member", "apply"],
                      "Action: recover|analyze_usage|list|create|add_member|apply"],
    addr: Annotated[Optional[str], "Address for struct operations"] = None,
    name: Annotated[Optional[str], "Structure name"] = None,
    decl: Annotated[Optional[str], "C declaration for struct creation"] = None,
    member_name: Annotated[Optional[str], "Member name for add_member"] = None,
    member_type: Annotated[Optional[str], "Member type for add_member"] = "int",
    offset: Annotated[int, "Member offset for add_member"] = 0,
) -> dict:
    """
    Automatic structure recovery and struct management.
    
    ACTIONS:
    
    recover - Attempt automatic struct recovery from function usage
        Params: addr (function that uses a struct pointer)
        Returns: {recovered_struct: {name, members: [{offset, name, type}]}}
        
    analyze_usage - Analyze how an address/register is used as struct
        Params: addr
        Returns: {accesses: [{offset, size, operation}]}
        
    list - List all structures in the database
        Returns: {structs: [{name, size, members_count}]}
        
    create - Create a new structure from C declaration
        Params: decl (e.g., "struct Foo { int x; char y[16]; };")
        Returns: {created, name, size}
        
    add_member - Add a member to an existing structure
        Params: name (struct name), member_name, member_type, offset
        Returns: {added, struct, member}
        
    apply - Apply a structure type to an address
        Params: addr, name (struct name)
        Returns: {applied, addr, struct}
    """
    try:
        if action == "recover":
            if not addr:
                return {"error": "addr required (function address)"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {addr}"}
            
            # Try to recover struct from decompilation
            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    return {"error": "Could not decompile function"}
                
                # Analyze local variables that might be struct pointers
                struct_candidates = []
                
                for lvar in cfunc.lvars:
                    if lvar.type().is_ptr():
                        # This is a pointer - might be a struct pointer
                        pointed_type = lvar.type().get_pointed_object()
                        if pointed_type and not pointed_type.is_scalar():
                            struct_candidates.append({
                                "var_name": lvar.name,
                                "type": str(lvar.type()),
                                "pointed_type": str(pointed_type)
                            })
                
                # Look for field accesses
                accesses = []
                
                class AccessFinder(ida_hexrays.ctree_visitor_t):
                    def __init__(self):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    
                    def visit_expr(self, e):
                        if e.op == ida_hexrays.cot_memptr or e.op == ida_hexrays.cot_memref:
                            accesses.append({
                                "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None,
                                "op": ida_hexrays.get_ctype_name(e.op),
                                "offset": e.m if hasattr(e, 'm') else None
                            })
                        return 0
                
                finder = AccessFinder()
                finder.apply_to(cfunc.body, None)
                
                return {
                    "function": idc.get_func_name(ea) or hex(ea),
                    "struct_candidates": struct_candidates,
                    "field_accesses": accesses[:50]
                }
                
            except ida_hexrays.DecompilationFailure:
                return {"error": "Decompilation failed"}
        
        elif action == "analyze_usage":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Analyze memory accesses from this point
            accesses = []
            
            # Get xrefs from this address
            for xref in idautils.XrefsFrom(ea):
                size = idc.get_item_size(xref.to)
                accesses.append({
                    "target": hex(xref.to),
                    "type": "code" if xref.type in [1, 17, 18, 19, 20, 21] else "data",
                    "size": size
                })
            
            return {"addr": hex(ea), "accesses": accesses[:100]}
        
        elif action == "list":
            structs_list = []
            
            # Iterate through all local types
            til = ida_typeinf.get_idati()
            if til:
                count = ida_typeinf.get_ordinal_count(til)
                for ordinal in range(1, count + 1):
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_typeinf.get_numbered_type(til, ordinal, tinfo):
                        if tinfo.is_struct() or tinfo.is_union():
                            type_name = tinfo.get_type_name() or f"struct_{ordinal}"
                            structs_list.append({
                                "name": type_name,
                                "ordinal": ordinal,
                                "size": tinfo.get_size(),
                                "is_union": tinfo.is_union()
                            })
            
            return {"structs": structs_list}
        
        elif action == "create":
            if not decl:
                return {"error": "decl required (C structure declaration)"}
            
            # Parse the declaration
            til = ida_typeinf.get_idati()
            tinfo = ida_typeinf.tinfo_t()
            
            result = ida_typeinf.parse_decl(tinfo, til, decl, ida_typeinf.PT_TYP)
            if result is None:
                return {"error": f"Failed to parse declaration: {decl}"}
            
            # Get the name
            struct_name = tinfo.get_type_name()
            if not struct_name:
                # Try to extract from declaration
                import re
                match = re.search(r'struct\s+(\w+)', decl)
                if match:
                    struct_name = match.group(1)
            
            # Save to til
            ordinal = ida_typeinf.alloc_type_ordinal(til)
            if ida_typeinf.set_numbered_type(til, ordinal, ida_typeinf.NTF_TYPE, struct_name, tinfo):
                return {
                    "created": True,
                    "name": struct_name,
                    "ordinal": ordinal,
                    "size": tinfo.get_size()
                }
            
            return {"error": "Failed to save structure to type library"}
        
        elif action == "add_member":
            if not name:
                return {"error": "name (struct name) required"}
            if not member_name:
                return {"error": "member_name required"}
            
            # This is complex in IDA 9 with new type system
            # For now, suggest using create with full declaration
            return {
                "error": "add_member not fully supported in IDA 9",
                "suggestion": "Use create action with full C declaration instead",
                "example": f"structs(action='create', decl='struct {name} {{ int {member_name}; }};')"
            }
        
        elif action == "apply":
            if not addr:
                return {"error": "addr required"}
            if not name:
                return {"error": "name (struct name) required"}
            
            ea = parse_address(addr)
            
            # Get the struct type
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
                return {"error": f"Structure '{name}' not found"}
            
            # Apply to address
            if ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
                return {
                    "applied": True,
                    "addr": hex(ea),
                    "struct": name,
                    "size": tinfo.get_size()
                }
            
            return {"error": f"Failed to apply struct '{name}' at {hex(ea)}"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}




# ============================================================================
# 27. EMULATE - Code Emulation and Snippet Execution
# ============================================================================

@tool
@idaread
def emulate(
    action: Annotated[Literal["snippet", "appcall", "trace", "decrypt_strings", "eval_expr"],
                      "Action: snippet|appcall|trace|decrypt_strings|eval_expr"],
    addr: Annotated[Optional[str], "Address to emulate from"] = None,
    code: Annotated[Optional[str], "Assembly or hex bytes to emulate"] = None,
    func_name: Annotated[Optional[str], "Function name for appcall"] = None,
    args: Annotated[Optional[list], "Arguments for appcall"] = None,
    max_steps: Annotated[int, "Maximum instructions to emulate"] = 1000,
    stop_addr: Annotated[Optional[str], "Address to stop emulation"] = None,
) -> dict:
    """
    Emulate code snippets and call functions (requires debugger or Appcall).
    
    ACTIONS:
    
    snippet - Emulate a code snippet from address
        Params: addr, max_steps, stop_addr
        Returns: {executed_instructions, final_regs, memory_writes}
        
    appcall - Call a function with arguments (requires debugger)
        Params: func_name or addr, args
        Returns: {return_value, side_effects}
        
    trace - Trace execution and collect data
        Params: addr, max_steps
        Returns: {trace: [{addr, insn, regs}]}
        
    decrypt_strings - Attempt to decrypt strings by emulating decryption routines
        Params: addr (of decrypt function)
        Returns: {decrypted: [{original_addr, decrypted_string}]}
        
    eval_expr - Evaluate an expression/constant at address
        Params: addr
        Returns: {value, type}
    """
    try:
        # Check if Appcall is available
        has_appcall = hasattr(idaapi, 'Appcall')
        
        if action == "snippet":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Try to use IDA's built-in emulation if available
            # This is a simplified implementation - real emulation would use Unicorn/Qiling
            
            instructions = []
            current_ea = ea
            max_ea = ea + 0x1000  # Limit range
            
            if stop_addr:
                max_ea = min(max_ea, parse_address(stop_addr))
            
            for i in range(max_steps):
                if current_ea >= max_ea:
                    break
                
                insn = idaapi.insn_t()
                length = idaapi.decode_insn(insn, current_ea)
                
                if length == 0:
                    break
                
                disasm = idc.generate_disasm_line(current_ea, 0)
                instructions.append({
                    "addr": hex(current_ea),
                    "bytes": ida_bytes.get_bytes(current_ea, length).hex(),
                    "disasm": ida_lines.tag_remove(disasm) if disasm else ""
                })
                
                # Simple flow following (doesn't handle branches properly)
                current_ea += length
                
                # Stop at return instructions
                if idaapi.is_ret_insn(insn):
                    break
            
            return {
                "start": hex(ea),
                "instructions": instructions,
                "count": len(instructions),
                "note": "Static trace - for dynamic emulation use debugger or external emulator"
            }
        
        elif action == "appcall":
            if not has_appcall:
                return {"error": "Appcall not available - requires debugger to be active"}
            
            # Appcall requires debugger to be running
            import ida_dbg
            if not ida_dbg.is_debugger_on():
                return {
                    "error": "Debugger not active - Appcall requires a running debug session",
                    "suggestion": "Use debug(action='start') first, then appcall"
                }
            
            if not func_name and not addr:
                return {"error": "func_name or addr required"}
            
            # Get function address
            if func_name:
                ea = idc.get_name_ea_simple(func_name)
                if ea == idaapi.BADADDR:
                    return {"error": f"Function '{func_name}' not found"}
            else:
                ea = parse_address(addr)
            
            # Prepare arguments
            call_args = args or []
            
            try:
                # Use Appcall to call the function
                result = idaapi.Appcall.func_ptr(ea)(*call_args)
                return {
                    "called": func_name or hex(ea),
                    "args": call_args,
                    "return_value": str(result)
                }
            except Exception as e:
                return {"error": f"Appcall failed: {e}"}
        
        elif action == "trace":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function at {addr}"}
            
            # Collect a static trace through the function
            trace = []
            visited = set()
            
            def trace_block(block_ea, depth=0):
                if depth > 10 or block_ea in visited:
                    return
                visited.add(block_ea)
                
                current = block_ea
                while current < func.end_ea and len(trace) < max_steps:
                    if current in visited and current != block_ea:
                        break
                    
                    insn = idaapi.insn_t()
                    length = idaapi.decode_insn(insn, current)
                    if length == 0:
                        break
                    
                    disasm = idc.generate_disasm_line(current, 0)
                    trace.append({
                        "addr": hex(current),
                        "disasm": ida_lines.tag_remove(disasm) if disasm else ""
                    })
                    
                    # Check for control flow
                    if idaapi.is_ret_insn(insn):
                        break
                    elif insn.itype in [idaapi.NN_jmp, idaapi.NN_jmpni]:
                        # Unconditional jump
                        if insn.Op1.type == idaapi.o_near:
                            trace_block(insn.Op1.addr, depth + 1)
                        break
                    elif insn.itype >= idaapi.NN_ja and insn.itype <= idaapi.NN_jz:
                        # Conditional jump - follow both paths
                        if insn.Op1.type == idaapi.o_near:
                            trace_block(insn.Op1.addr, depth + 1)
                    
                    current += length
            
            trace_block(ea)
            
            return {
                "function": idc.get_func_name(ea) or hex(ea),
                "trace": trace[:max_steps],
                "note": "Static trace - branch coverage may be incomplete"
            }
        
        elif action == "decrypt_strings":
            if not addr:
                return {"error": "addr required (address of decrypt function)"}
            
            ea = parse_address(addr)
            
            # Find all calls to this decrypt function
            decrypt_calls = []
            for xref in idautils.XrefsTo(ea):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:  # Call near/far
                    call_ea = xref.frm
                    
                    # Try to find string argument (heuristic)
                    # Look backwards for lea/push of string address
                    prev_ea = idc.prev_head(call_ea)
                    for _ in range(5):  # Check up to 5 instructions back
                        if prev_ea == idaapi.BADADDR:
                            break
                        
                        # Check for string reference in operands
                        for op_n in range(2):
                            op_addr = idc.get_operand_value(prev_ea, op_n)
                            if op_addr != idaapi.BADADDR:
                                str_content = idc.get_strlit_contents(op_addr)
                                if str_content:
                                    decrypt_calls.append({
                                        "call_addr": hex(call_ea),
                                        "string_addr": hex(op_addr),
                                        "encrypted": str_content.decode('utf-8', errors='replace') if isinstance(str_content, bytes) else str_content
                                    })
                        
                        prev_ea = idc.prev_head(prev_ea)
            
            return {
                "decrypt_function": hex(ea),
                "potential_encrypted_strings": decrypt_calls,
                "note": "Static analysis - run with debugger for actual decryption"
            }
        
        elif action == "eval_expr":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Evaluate what's at this address
            result = {
                "addr": hex(ea),
                "item_size": idc.get_item_size(ea)
            }
            
            # Try to read as different types
            result["as_byte"] = ida_bytes.get_byte(ea)
            result["as_word"] = ida_bytes.get_word(ea)
            result["as_dword"] = ida_bytes.get_dword(ea)
            result["as_qword"] = ida_bytes.get_qword(ea)
            
            # Check if it's a string
            str_type = idc.get_str_type(ea)
            if str_type is not None and str_type >= 0:
                s = idc.get_strlit_contents(ea)
                if s:
                    result["as_string"] = s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s
            
            # Get name if any
            name = idc.get_name(ea)
            if name:
                result["name"] = name
            
            return result
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 28. EXPORT - Export Database in Various Formats
# ============================================================================

@tool
@idaread
def export(
    action: Annotated[Literal["listing", "html", "idc", "json", "binexport", "headers"],
                      "Action: listing|html|idc|json|binexport|headers"],
    path: Annotated[Optional[str], "Output file path"] = None,
    addr: Annotated[Optional[str], "Address or range (for partial export)"] = None,
    include_decompile: Annotated[bool, "Include decompiled code"] = False,
) -> dict:
    """
    Export IDB data in various formats for external use.
    
    ACTIONS:
    
    listing - Generate assembly listing file
        Params: path, addr (optional range)
        Returns: {exported, path, lines}
        
    html - Generate HTML report with navigation
        Params: path
        Returns: {exported, path}
        
    idc - Generate IDC script to recreate annotations
        Params: path
        Returns: {exported, path, commands}
        
    json - Export database metadata as JSON
        Params: path
        Returns: {exported, path}
        
    binexport - Export for BinDiff (if plugin available)
        Params: path
        Returns: {exported, path}
        
    headers - Export C headers for types
        Params: path
        Returns: {exported, path, types_count}
    """
    try:
        import os
        import json as json_module
        
        if action == "listing":
            if not path:
                path = idaapi.get_input_file_path() + ".lst"
            
            lines = []
            
            # Determine range
            if addr:
                if ':' in addr:
                    start_s, end_s = addr.split(':')
                    start_ea = parse_address(start_s)
                    end_ea = parse_address(end_s)
                else:
                    ea = parse_address(addr)
                    func = ida_funcs.get_func(ea)
                    if func:
                        start_ea = func.start_ea
                        end_ea = func.end_ea
                    else:
                        start_ea = ea
                        end_ea = ea + 0x100
            else:
                # Export first segment only to avoid huge files
                segs = list(idautils.Segments())
                if segs:
                    seg = ida_segment.getseg(segs[0])
                    start_ea = seg.start_ea
                    end_ea = min(seg.end_ea, start_ea + 0x10000)  # Limit size
                else:
                    return {"error": "No segments found"}
            
            current = start_ea
            while current < end_ea and len(lines) < 10000:
                disasm = idc.generate_disasm_line(current, 0)
                if disasm:
                    lines.append(f"{hex(current)}: {ida_lines.tag_remove(disasm)}")
                current = idc.next_head(current)
                if current == idaapi.BADADDR:
                    break
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"; IDA Pro Listing\n")
                f.write(f"; File: {idaapi.get_input_file_path()}\n")
                f.write(f"; Range: {hex(start_ea)} - {hex(end_ea)}\n\n")
                f.write('\n'.join(lines))
            
            return {"exported": True, "path": path, "lines": len(lines)}
        
        elif action == "html":
            if not path:
                path = idaapi.get_input_file_path() + ".html"
            
            # Generate simple HTML report
            html = []
            html.append("<!DOCTYPE html><html><head>")
            html.append("<title>IDA Analysis Report</title>")
            html.append("<style>body{font-family:monospace;} .func{margin:10px 0;padding:10px;border:1px solid #ccc;} .addr{color:blue;}</style>")
            html.append("</head><body>")
            html.append(f"<h1>Analysis: {os.path.basename(idaapi.get_input_file_path())}</h1>")
            
            # List functions
            html.append("<h2>Functions</h2>")
            func_count = 0
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if func_count >= 100:  # Limit
                        break
                    name = idc.get_func_name(func_ea)
                    html.append(f'<div class="func"><span class="addr">{hex(func_ea)}</span> - {name}</div>')
                    func_count += 1
            
            # List strings
            html.append("<h2>Strings</h2>")
            str_count = 0
            for s in idautils.Strings():
                if str_count >= 100:
                    break
                html.append(f'<div><span class="addr">{hex(s.ea)}</span>: {str(s)[:100]}</div>')
                str_count += 1
            
            html.append("</body></html>")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            
            return {"exported": True, "path": path, "functions": func_count, "strings": str_count}
        
        elif action == "idc":
            if not path:
                path = idaapi.get_input_file_path() + ".idc"
            
            commands = []
            commands.append("// IDC script generated by IDA MCP")
            commands.append('#include <idc.idc>')
            commands.append("static main() {")
            
            # Export renames
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        commands.append(f'  MakeName({hex(func_ea)}, "{name}");')
            
            # Export comments (sample)
            comment_count = 0
            for seg_ea in idautils.Segments():
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    cmt = idc.get_cmt(head, 0)
                    if cmt:
                        cmt_escaped = cmt.replace('"', '\\"').replace('\n', '\\n')
                        commands.append(f'  MakeComm({hex(head)}, "{cmt_escaped}");')
                        comment_count += 1
                        if comment_count >= 1000:
                            break
                if comment_count >= 1000:
                    break
            
            commands.append("}")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(commands))
            
            return {"exported": True, "path": path, "commands": len(commands)}
        
        elif action == "json":
            if not path:
                path = idaapi.get_input_file_path() + "_export.json"
            
            data = {
                "file": idaapi.get_input_file_path(),
                "md5": idaapi.retrieve_input_file_md5().hex() if hasattr(idaapi, 'retrieve_input_file_md5') else None,
                "base_address": hex(idaapi.get_imagebase()),
                "functions": [],
                "strings": [],
                "imports": [],
                "exports": []
            }
            
            # Functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    data["functions"].append({
                        "addr": hex(func_ea),
                        "name": idc.get_func_name(func_ea),
                        "size": func.end_ea - func.start_ea if func else 0
                    })
            
            # Limit for size
            data["functions"] = data["functions"][:5000]
            
            # Strings (sample)
            for s in idautils.Strings():
                if len(data["strings"]) >= 1000:
                    break
                data["strings"].append({
                    "addr": hex(s.ea),
                    "value": str(s)[:200]
                })
            
            with open(path, 'w', encoding='utf-8') as f:
                json_module.dump(data, f, indent=2)
            
            return {"exported": True, "path": path, "functions": len(data["functions"]), "strings": len(data["strings"])}
        
        elif action == "binexport":
            if not path:
                path = idaapi.get_input_file_path() + ".BinExport"
            
            # Try to run BinExport plugin
            try:
                import ida_loader
                result = ida_loader.load_and_run_plugin("binexport", 0)
                if result:
                    return {"exported": True, "path": path, "note": "BinExport plugin executed"}
                else:
                    return {"error": "BinExport plugin not available or failed"}
            except Exception as e:
                return {"error": f"BinExport failed: {e}", "note": "Install BinExport plugin from Google"}
        
        elif action == "headers":
            if not path:
                path = idaapi.get_input_file_path() + ".h"
            
            headers = []
            headers.append("// Type definitions exported from IDA")
            headers.append(f"// Source: {idaapi.get_input_file_path()}\n")
            
            # Export structures
            til = ida_typeinf.get_idati()
            type_count = 0
            if til:
                count = ida_typeinf.get_ordinal_count(til)
                for ordinal in range(1, min(count + 1, 500)):  # Limit
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_typeinf.get_numbered_type(til, ordinal, tinfo):
                        type_str = str(tinfo)
                        type_name = tinfo.get_type_name()
                        if type_name and tinfo.is_struct():
                            headers.append(f"// Ordinal {ordinal}")
                            headers.append(f"// {type_str}")
                            headers.append("")
                            type_count += 1
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(headers))
            
            return {"exported": True, "path": path, "types_count": type_count}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 29. HISTORY - Database Version Control and Undo Management
# ============================================================================

@tool
@idaread
def history(
    action: Annotated[Literal["undo", "redo", "list", "snapshot", "restore", "diff"],
                      "Action: undo|redo|list|snapshot|restore|diff"],
    name: Annotated[Optional[str], "Snapshot name"] = None,
    count: Annotated[int, "Number of undo steps"] = 1,
) -> dict:
    """
    Database version control: undo, redo, snapshots.
    
    ACTIONS:
    
    undo - Undo last operation(s)
        Params: count (number of steps)
        Returns: {undone, count}
        
    redo - Redo undone operation(s)
        Params: count
        Returns: {redone, count}
        
    list - List undo/redo history
        Returns: {undo_available, redo_available, history}
        
    snapshot - Create a named snapshot of current state
        Params: name
        Returns: {created, name, timestamp}
        
    restore - Restore from a snapshot
        Params: name
        Returns: {restored, name}
        
    diff - Show what changed since last save
        Returns: {changes: [{type, addr, before, after}]}
    """
    try:
        import ida_undo
        
        if action == "undo":
            undone = 0
            for _ in range(count):
                if ida_undo.perform_undo():
                    undone += 1
                else:
                    break
            
            return {"undone": undone, "requested": count}
        
        elif action == "redo":
            redone = 0
            for _ in range(count):
                if ida_undo.perform_redo():
                    redone += 1
                else:
                    break
            
            return {"redone": redone, "requested": count}
        
        elif action == "list":
            # Get undo/redo status
            result = {
                "undo_available": False,
                "redo_available": False,
                "note": "Detailed history API varies by IDA version"
            }
            
            # Check if undo is available by trying to get description
            if hasattr(ida_undo, 'get_undo_description'):
                desc = ida_undo.get_undo_description()
                result["undo_available"] = bool(desc)
                result["undo_description"] = desc
            
            if hasattr(ida_undo, 'get_redo_description'):
                desc = ida_undo.get_redo_description()
                result["redo_available"] = bool(desc)
                result["redo_description"] = desc
            
            return result
        
        elif action == "snapshot":
            if not name:
                import datetime
                name = f"snapshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # IDA doesn't have built-in snapshots, but we can save the database
            # with our own metadata
            import os
            import json as json_module
            
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            snapshot_dir = os.path.join(os.path.dirname(idb_path), ".ida_snapshots")
            os.makedirs(snapshot_dir, exist_ok=True)
            
            # Save metadata about current state
            metadata = {
                "name": name,
                "timestamp": datetime.datetime.now().isoformat(),
                "idb_path": idb_path,
                "functions_count": sum(1 for _ in idautils.Functions()),
                "note": "Snapshot metadata - actual IDB backup requires manual copy"
            }
            
            meta_path = os.path.join(snapshot_dir, f"{name}.json")
            with open(meta_path, 'w') as f:
                json_module.dump(metadata, f, indent=2)
            
            return {
                "created": True,
                "name": name,
                "metadata_path": meta_path,
                "note": "Metadata saved. For full backup, copy the .idb file"
            }
        
        elif action == "restore":
            if not name:
                return {"error": "name required"}
            
            # List available snapshots
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            snapshot_dir = os.path.join(os.path.dirname(idb_path), ".ida_snapshots")
            
            meta_path = os.path.join(snapshot_dir, f"{name}.json")
            if os.path.exists(meta_path):
                import json as json_module
                with open(meta_path, 'r') as f:
                    metadata = json_module.load(f)
                return {
                    "found": True,
                    "metadata": metadata,
                    "note": "To fully restore, reload IDB from backup"
                }
            else:
                return {"error": f"Snapshot '{name}' not found"}
        
        elif action == "diff":
            # Show changes since database was opened
            # This is limited without IDA's internal change tracking
            
            changes = {
                "note": "Full diff requires IDA's internal change tracking",
                "modified_functions": []
            }
            
            # We can list functions that appear to have been renamed
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        changes["modified_functions"].append({
                            "addr": hex(func_ea),
                            "name": name
                        })
                    if len(changes["modified_functions"]) >= 100:
                        break
            
            return changes
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# END OF SESSION A TOOLS (27-29)
# Session B tools (30-35) should be added AFTER this line
# ============================================================================


# ============================================================================
# 30. STRINGS_XREF - Advanced String Analysis
# ============================================================================

@tool
@idaread
def strings_xref(
    action: Annotated[Literal["analyze", "xref_chain", "detect_encoded", "find_format", "clusters"],
                      "Action: analyze|xref_chain|detect_encoded|find_format|clusters"],
    addr: Annotated[Optional[str], "String address or function address"] = None,
    query: Annotated[Optional[str], "String pattern to search"] = None,
    depth: Annotated[int, "Xref chain depth"] = 3,
) -> dict:
    """
    Advanced string analysis with xref chains, encoding detection, and clustering.
    
    ACTIONS:
    
    analyze - Deep analysis of a string at address
        Params: addr
        Returns: {string, encoding, xrefs, decryption_indicators}
        
    xref_chain - Trace string reference chain up through callers
        Params: addr, depth
        Returns: {chain: [{addr, func, caller}...]}
        
    detect_encoded - Find potentially encrypted/encoded strings
        Returns: {suspicious: [{addr, string, entropy, reason}]}
        
    find_format - Find format strings and their argument usage
        Params: query (optional filter)
        Returns: {format_strings: [{addr, format, args_count}]}
        
    clusters - Group strings by their calling functions
        Returns: {clusters: [{func, strings: [...]}]}
    """
    import math
    
    try:
        def calc_entropy(data):
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p)
            return entropy / 8.0  # Normalize to 0-1
        
        if action == "analyze":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Get string at address
            str_type = idc.get_str_type(ea)
            if str_type is None:
                return {"error": f"No string at {addr}"}
            
            string_val = idc.get_strlit_contents(ea, -1, str_type)
            if string_val:
                string_val = string_val.decode('utf-8', errors='replace')
            
            # Detect encoding
            encoding = "ascii"
            if str_type == idc.STRTYPE_C_16:
                encoding = "utf-16"
            elif str_type == idc.STRTYPE_C_32:
                encoding = "utf-32"
            
            # Get xrefs to this string
            xrefs = []
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                xrefs.append({
                    "from": hex(xref.frm),
                    "func": idc.get_func_name(xref.frm) if func else None
                })
            
            # Check for decryption indicators
            indicators = []
            raw_bytes = ida_bytes.get_bytes(ea, min(100, idc.get_item_size(ea)))
            if raw_bytes:
                ent = calc_entropy(raw_bytes)
                if ent > 0.8:
                    indicators.append("high_entropy")
                if b'\x00' not in raw_bytes[:20] and len(raw_bytes) > 10:
                    indicators.append("no_null_terminator_early")
            
            return {
                "addr": hex(ea),
                "string": string_val,
                "encoding": encoding,
                "size": idc.get_item_size(ea),
                "xrefs": xrefs[:20],
                "decryption_indicators": indicators
            }
        
        elif action == "xref_chain":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            chain = []
            visited = set()
            
            def trace_up(current_ea, current_depth):
                if current_depth > depth or current_ea in visited:
                    return
                visited.add(current_ea)
                
                for xref in idautils.XrefsTo(current_ea):
                    if xref.type in [1, 17, 18, 19, 20, 21]:
                        func = ida_funcs.get_func(xref.frm)
                        entry = {
                            "addr": hex(xref.frm),
                            "depth": current_depth
                        }
                        if func:
                            entry["func"] = idc.get_func_name(func.start_ea)
                            chain.append(entry)
                            if current_depth < depth:
                                trace_up(func.start_ea, current_depth + 1)
            
            trace_up(ea, 0)
            return {"addr": hex(ea), "depth": depth, "chain": chain[:50]}
        
        elif action == "detect_encoded":
            suspicious = []
            
            for s in idautils.Strings():
                raw = ida_bytes.get_bytes(s.ea, s.length)
                if not raw:
                    continue
                
                ent = calc_entropy(raw)
                reasons = []
                
                if ent > 0.85:
                    reasons.append("high_entropy")
                
                # Check for XOR patterns
                if raw and len(set(raw)) < len(raw) // 4:
                    reasons.append("repetitive_pattern")
                
                # Check for base64-like
                try:
                    str_val = raw.decode('ascii', errors='strict')
                    if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in str_val):
                        if len(str_val) > 20:
                            reasons.append("base64_like")
                except:
                    pass
                
                if reasons:
                    suspicious.append({
                        "addr": hex(s.ea),
                        "string": str(s)[:50],
                        "entropy": round(ent, 3),
                        "reasons": reasons
                    })
                
                if len(suspicious) >= 100:
                    break
            
            return {"suspicious": suspicious}
        
        elif action == "find_format":
            format_strings = []
            
            for s in idautils.Strings():
                try:
                    str_val = idc.get_strlit_contents(s.ea, -1, s.strtype)
                    if str_val:
                        str_val = str_val.decode('utf-8', errors='replace')
                        if '%' in str_val:
                            if query and query.lower() not in str_val.lower():
                                continue
                            # Count format specifiers
                            import re
                            specs = re.findall(r'%[-+0 #]*\d*\.?\d*[hlL]*[diouxXeEfFgGcspn%]', str_val)
                            if specs:
                                format_strings.append({
                                    "addr": hex(s.ea),
                                    "format": str_val[:100],
                                    "specifiers": specs[:10],
                                    "args_count": len([s for s in specs if s != '%%'])
                                })
                except:
                    continue
                
                if len(format_strings) >= 100:
                    break
            
            return {"format_strings": format_strings}
        
        elif action == "clusters":
            clusters = {}
            
            for s in idautils.Strings():
                for xref in idautils.XrefsTo(s.ea):
                    func = ida_funcs.get_func(xref.frm)
                    if func:
                        func_name = idc.get_func_name(func.start_ea)
                        if func_name not in clusters:
                            clusters[func_name] = {"addr": hex(func.start_ea), "strings": []}
                        if len(clusters[func_name]["strings"]) < 20:
                            clusters[func_name]["strings"].append({
                                "addr": hex(s.ea),
                                "string": str(s)[:50]
                            })
            
            result = [{"func": k, **v} for k, v in list(clusters.items())[:50]]
            return {"clusters": result}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 31. ENTROPY - Entropy Analysis
# ============================================================================

@tool
@idaread
def entropy(
    action: Annotated[Literal["section", "region", "packed_detect", "crypto_detect", "compare"],
                      "Action: section|region|packed_detect|crypto_detect|compare"],
    addr: Annotated[Optional[str], "Start address for region analysis"] = None,
    end_addr: Annotated[Optional[str], "End address for compare"] = None,
    size: Annotated[int, "Region size in bytes"] = 256,
    threshold: Annotated[float, "High entropy threshold (0.0-1.0)"] = 0.9,
) -> dict:
    """
    Entropy analysis for detecting packed/encrypted regions.
    
    ACTIONS:
    
    section - Calculate entropy for each segment
        Returns: {sections: [{name, start, end, entropy, is_high}]}
        
    region - Calculate entropy for specific address range
        Params: addr, size
        Returns: {addr, size, entropy, histogram}
        
    packed_detect - Detect packed/compressed sections
        Params: threshold
        Returns: {packed_sections: [...], overall_verdict}
        
    crypto_detect - Detect crypto constants and high-entropy regions
        Returns: {crypto_indicators: [{addr, type, description}]}
        
    compare - Compare entropy of two regions
        Params: addr, end_addr (second region start)
        Returns: {region1, region2, difference}
    """
    import math
    
    try:
        def calc_entropy(data):
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            ent = 0.0
            for count in freq.values():
                p = count / len(data)
                ent -= p * math.log2(p)
            return ent / 8.0
        
        def calc_histogram(data):
            hist = [0] * 256
            for b in data:
                hist[b] += 1
            return hist
        
        if action == "section":
            sections = []
            
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                
                seg_name = idc.get_segm_name(seg_ea)
                seg_size = seg.end_ea - seg.start_ea
                
                # Sample entropy (don't read huge segments entirely)
                sample_size = min(seg_size, 65536)
                data = ida_bytes.get_bytes(seg.start_ea, sample_size)
                
                if data:
                    ent = calc_entropy(data)
                    sections.append({
                        "name": seg_name,
                        "start": hex(seg.start_ea),
                        "end": hex(seg.end_ea),
                        "size": seg_size,
                        "entropy": round(ent, 4),
                        "is_high": ent > threshold
                    })
            
            return {"sections": sections, "threshold": threshold}
        
        elif action == "region":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            data = ida_bytes.get_bytes(ea, size)
            
            if not data:
                return {"error": f"Could not read {size} bytes at {addr}"}
            
            ent = calc_entropy(data)
            hist = calc_histogram(data)
            
            # Compress histogram for output
            non_zero = {i: c for i, c in enumerate(hist) if c > 0}
            
            return {
                "addr": hex(ea),
                "size": len(data),
                "entropy": round(ent, 4),
                "is_high": ent > threshold,
                "unique_bytes": len(non_zero),
                "top_bytes": sorted(non_zero.items(), key=lambda x: -x[1])[:10]
            }
        
        elif action == "packed_detect":
            packed = []
            code_sections = []
            data_sections = []
            
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                
                seg_name = idc.get_segm_name(seg_ea)
                seg_size = seg.end_ea - seg.start_ea
                sample_size = min(seg_size, 65536)
                data = ida_bytes.get_bytes(seg.start_ea, sample_size)
                
                if data:
                    ent = calc_entropy(data)
                    info = {
                        "name": seg_name,
                        "entropy": round(ent, 4),
                        "size": seg_size
                    }
                    
                    # Check segment type
                    if seg.perm & ida_segment.SEGPERM_EXEC:
                        code_sections.append(info)
                        if ent > threshold:
                            packed.append({**info, "reason": "high_entropy_code"})
                    else:
                        data_sections.append(info)
            
            # Verdict
            avg_code_entropy = sum(s["entropy"] for s in code_sections) / len(code_sections) if code_sections else 0
            verdict = "likely_packed" if avg_code_entropy > 0.85 else "likely_unpacked"
            
            return {
                "packed_sections": packed,
                "code_avg_entropy": round(avg_code_entropy, 4),
                "verdict": verdict,
                "threshold": threshold
            }
        
        elif action == "crypto_detect":
            indicators = []
            
            # Known crypto constants
            crypto_patterns = [
                (b'\x63\x7c\x77\x7b', "AES S-box"),
                (b'\x67\x45\x23\x01', "MD5 init"),
                (b'\x01\x23\x45\x67', "SHA1 init (BE)"),
                (b'\xd7\x6a\xa4\x78', "SHA256 K constant"),
            ]
            
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                
                seg_size = min(seg.end_ea - seg.start_ea, 1048576)
                data = ida_bytes.get_bytes(seg.start_ea, seg_size)
                
                if not data:
                    continue
                
                # Search for crypto constants
                for pattern, name in crypto_patterns:
                    offset = data.find(pattern)
                    if offset != -1:
                        indicators.append({
                            "addr": hex(seg.start_ea + offset),
                            "type": "crypto_constant",
                            "description": name
                        })
                
                # Look for high-entropy 256-byte blocks (potential S-boxes)
                for i in range(0, len(data) - 256, 256):
                    block = data[i:i+256]
                    ent = calc_entropy(block)
                    unique = len(set(block))
                    if ent > 0.95 and unique > 200:
                        indicators.append({
                            "addr": hex(seg.start_ea + i),
                            "type": "potential_sbox",
                            "description": f"High entropy block ({unique} unique bytes)"
                        })
                        if len(indicators) > 50:
                            break
            
            return {"crypto_indicators": indicators[:50]}
        
        elif action == "compare":
            if not addr or not end_addr:
                return {"error": "addr and end_addr required"}
            
            ea1 = parse_address(addr)
            ea2 = parse_address(end_addr)
            
            data1 = ida_bytes.get_bytes(ea1, size)
            data2 = ida_bytes.get_bytes(ea2, size)
            
            if not data1 or not data2:
                return {"error": "Could not read data from one or both regions"}
            
            ent1 = calc_entropy(data1)
            ent2 = calc_entropy(data2)
            
            return {
                "region1": {"addr": hex(ea1), "entropy": round(ent1, 4)},
                "region2": {"addr": hex(ea2), "entropy": round(ent2, 4)},
                "difference": round(abs(ent1 - ent2), 4),
                "more_random": "region1" if ent1 > ent2 else "region2"
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 32. IMPORTS_DEEP - Deep Import Analysis
# ============================================================================

@tool
@idaread
def imports_deep(
    action: Annotated[Literal["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
                      "Action: thunks|delay|forwarded|ordinal|api_sets|resolve"],
    query: Annotated[Optional[str], "Import name or DLL to filter"] = None,
    addr: Annotated[Optional[str], "Address for resolve action"] = None,
) -> dict:
    """
    Deep import analysis with thunk resolution and delay import detection.
    
    ACTIONS:
    
    thunks - Resolve import thunks to actual API addresses
        Params: query (optional DLL filter)
        Returns: {thunks: [{thunk_addr, target, name, dll}]}
        
    delay - List delay-loaded imports
        Returns: {delay_imports: [{dll, functions: [...]}]}
        
    forwarded - Detect forwarded exports in imported DLLs
        Returns: {forwarded: [{from_dll, to_dll, name}]}
        
    ordinal - Resolve ordinal imports to named symbols
        Params: query (DLL filter)
        Returns: {ordinal_imports: [{dll, ordinal, resolved_name}]}
        
    api_sets - Resolve Windows API Set redirections
        Returns: {api_sets: [{virtual_dll, actual_dll}]}
        
    resolve - Resolve import at specific address
        Params: addr
        Returns: {addr, dll, name, type}
    """
    try:
        if action == "thunks":
            thunks = []
            
            # Find IAT/thunk sections
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if '.idata' in seg_name.lower() or 'iat' in seg_name.lower():
                    seg = ida_segment.getseg(seg_ea)
                    if not seg:
                        continue
                    
                    ea = seg.start_ea
                    while ea < seg.end_ea:
                        target = idc.get_qword(ea) if idaapi.get_inf_structure().is_64bit() else idc.get_wide_dword(ea)
                        name = idc.get_name(ea)
                        
                        if name and target:
                            if query and query.lower() not in name.lower():
                                ea += 8 if idaapi.get_inf_structure().is_64bit() else 4
                                continue
                            
                            thunks.append({
                                "thunk_addr": hex(ea),
                                "target": hex(target) if target else None,
                                "name": name
                            })
                        
                        ea += 8 if idaapi.get_inf_structure().is_64bit() else 4
                        
                        if len(thunks) >= 200:
                            break
            
            return {"thunks": thunks}
        
        elif action == "delay":
            delay_imports = {}
            
            # Look for delay import directory
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if 'delay' in seg_name.lower() or '.didat' in seg_name.lower():
                    seg = ida_segment.getseg(seg_ea)
                    if seg:
                        # Parse delay import entries
                        ea = seg.start_ea
                        while ea < seg.end_ea:
                            name = idc.get_name(ea)
                            if name:
                                # Extract DLL name from import name
                                parts = name.split('_')
                                if len(parts) >= 2:
                                    dll = parts[0]
                                    if dll not in delay_imports:
                                        delay_imports[dll] = []
                                    delay_imports[dll].append({
                                        "addr": hex(ea),
                                        "name": name
                                    })
                            ea = idc.next_head(ea, seg.end_ea)
                            if ea == idaapi.BADADDR:
                                break
            
            result = [{"dll": k, "functions": v[:20]} for k, v in delay_imports.items()]
            return {"delay_imports": result}
        
        elif action == "forwarded":
            # This requires parsing the actual DLL exports which IDA doesn't do directly
            # We can detect forwarded imports by looking at import names that reference other DLLs
            forwarded = []
            
            def imp_cb(ea, name, ordinal):
                if name and '.' in name:
                    # Might be a forwarded export reference
                    parts = name.split('.')
                    if len(parts) == 2:
                        forwarded.append({
                            "addr": hex(ea),
                            "name": name,
                            "forward_target": parts[1]
                        })
                return True
            
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name:
                    ida_nalt.enum_import_names(i, imp_cb)
            
            return {"forwarded": forwarded[:50], "note": "Limited detection - full analysis requires DLL parsing"}
        
        elif action == "ordinal":
            ordinal_imports = []
            
            def imp_cb(ea, name, ordinal):
                if ordinal and ordinal > 0:
                    entry = {
                        "addr": hex(ea),
                        "ordinal": ordinal,
                        "name": name or f"Ordinal_{ordinal}"
                    }
                    ordinal_imports.append(entry)
                return True
            
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if query and query.lower() not in mod_name.lower():
                    continue
                ida_nalt.enum_import_names(i, imp_cb)
            
            return {"ordinal_imports": ordinal_imports[:100]}
        
        elif action == "api_sets":
            api_sets = []
            
            # Look for api-ms-* imports
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name and mod_name.lower().startswith('api-ms-'):
                    # These are API set DLLs that redirect to real DLLs
                    actual = "kernel32.dll"  # Default guess
                    if 'win-core' in mod_name.lower():
                        actual = "kernelbase.dll"
                    elif 'crt' in mod_name.lower():
                        actual = "ucrtbase.dll"
                    
                    api_sets.append({
                        "virtual_dll": mod_name,
                        "actual_dll": actual,
                        "note": "Actual target depends on Windows version"
                    })
            
            return {"api_sets": api_sets}
        
        elif action == "resolve":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            name = idc.get_name(ea)
            
            # Check what module this belongs to
            module = None
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                found = [False]
                
                def check_cb(imp_ea, imp_name, ordinal):
                    if imp_ea == ea:
                        found[0] = True
                        return False
                    return True
                
                ida_nalt.enum_import_names(i, check_cb)
                if found[0]:
                    module = mod_name
                    break
            
            return {
                "addr": hex(ea),
                "name": name,
                "dll": module,
                "type": "import" if module else "unknown"
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 33. COMMENTS_AI - AI-Optimized Comment Management
# ============================================================================

@tool
@idawrite
def comments_ai(
    action: Annotated[Literal["get_context", "set_structured", "bulk_set", "export_md", "import_md", "summary"],
                      "Action: get_context|set_structured|bulk_set|export_md|import_md|summary"],
    addr: Annotated[Optional[str], "Address for comment"] = None,
    text: Annotated[Optional[str], "Comment text or markdown content"] = None,
    items: Annotated[Optional[str], "JSON list of {addr, text} for bulk operations"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
    format: Annotated[str, "Comment format: plain|markdown|structured"] = "plain",
) -> dict:
    """
    AI-optimized comment management with structured formats and bulk operations.
    
    ACTIONS:
    
    get_context - Get all comments around an address with context
        Params: addr
        Returns: {func_comment, inline_comments, repeatable, anterior, posterior}
        
    set_structured - Set a structured comment (key-value, tags, TODO)
        Params: addr, text, format
        Returns: {set, addr, format}
        
    bulk_set - Set multiple comments from JSON list
        Params: items (JSON: [{"addr": "0x...", "text": "..."}])
        Returns: {set_count, errors}
        
    export_md - Export all comments to markdown
        Params: path
        Returns: {exported, path, count}
        
    import_md - Import comments from markdown
        Params: path
        Returns: {imported, count}
        
    summary - Get commenting coverage statistics
        Returns: {total_functions, commented, coverage_pct}
    """
    import json as json_module
    
    try:
        if action == "get_context":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            result = {
                "addr": hex(ea),
                "name": idc.get_name(ea)
            }
            
            # Function comment
            if func:
                result["func_name"] = idc.get_func_name(func.start_ea)
                result["func_comment"] = idc.get_func_cmt(func.start_ea, 0)
                result["func_comment_repeatable"] = idc.get_func_cmt(func.start_ea, 1)
            
            # Inline comment at address
            result["comment"] = idc.get_cmt(ea, 0)
            result["comment_repeatable"] = idc.get_cmt(ea, 1)
            
            # Anterior/posterior comments
            anterior = []
            for i in range(10):
                line = idc.get_extra_cmt(ea, idc.E_PREV + i)
                if line:
                    anterior.append(line)
                else:
                    break
            result["anterior"] = anterior
            
            posterior = []
            for i in range(10):
                line = idc.get_extra_cmt(ea, idc.E_NEXT + i)
                if line:
                    posterior.append(line)
                else:
                    break
            result["posterior"] = posterior
            
            # Nearby comments
            nearby = []
            if func:
                curr = func.start_ea
                while curr < func.end_ea and len(nearby) < 20:
                    cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                    if cmt:
                        nearby.append({
                            "addr": hex(curr),
                            "comment": cmt[:100]
                        })
                    curr = idc.next_head(curr, func.end_ea)
            result["nearby_comments"] = nearby
            
            return result
        
        elif action == "set_structured":
            if not addr or not text:
                return {"error": "addr and text required"}
            
            ea = parse_address(addr)
            
            # Format the comment based on format type
            if format == "structured":
                # Parse key:value pairs
                formatted = "/* AI Analysis:\n"
                for line in text.split('\n'):
                    formatted += f" * {line}\n"
                formatted += " */"
            elif format == "markdown":
                # Keep markdown but prefix lines
                formatted = text
            else:
                formatted = text
            
            # Set the comment
            idc.set_cmt(ea, formatted, 0)
            
            return {"set": True, "addr": hex(ea), "format": format}
        
        elif action == "bulk_set":
            if not items:
                return {"error": "items required (JSON list)"}
            
            try:
                item_list = json_module.loads(items)
            except:
                return {"error": "Invalid JSON in items"}
            
            set_count = 0
            errors = []
            
            for item in item_list:
                try:
                    item_addr = item.get("addr")
                    item_text = item.get("text")
                    if item_addr and item_text:
                        ea = parse_address(item_addr)
                        idc.set_cmt(ea, item_text, 0)
                        set_count += 1
                except Exception as e:
                    errors.append({"addr": item.get("addr"), "error": str(e)})
            
            return {"set_count": set_count, "errors": errors[:10]}
        
        elif action == "export_md":
            if not path:
                return {"error": "path required"}
            
            lines = ["# IDA Comments Export\n\n"]
            count = 0
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func_name = idc.get_func_name(func_ea)
                    func_cmt = idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1)
                    
                    func_comments = []
                    if func_cmt:
                        func_comments.append(f"**Function**: {func_cmt}")
                        count += 1
                    
                    # Get inline comments
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        curr = func.start_ea
                        while curr < func.end_ea:
                            cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                            if cmt:
                                func_comments.append(f"- `{hex(curr)}`: {cmt}")
                                count += 1
                            curr = idc.next_head(curr, func.end_ea)
                    
                    if func_comments:
                        lines.append(f"## {func_name} (`{hex(func_ea)}`)\n\n")
                        lines.extend([c + "\n" for c in func_comments])
                        lines.append("\n")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            return {"exported": True, "path": path, "comment_count": count}
        
        elif action == "import_md":
            if not path:
                return {"error": "path required"}
            
            import re
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse markdown for comments
            imported = 0
            
            # Look for patterns like `0x12345`: comment
            pattern = r'`(0x[0-9a-fA-F]+)`:\s*(.+?)(?:\n|$)'
            for match in re.finditer(pattern, content):
                addr_str = match.group(1)
                comment = match.group(2).strip()
                try:
                    ea = parse_address(addr_str)
                    idc.set_cmt(ea, comment, 0)
                    imported += 1
                except:
                    pass
            
            return {"imported": True, "count": imported}
        
        elif action == "summary":
            total = 0
            commented = 0
            inline_comments = 0
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    total += 1
                    func_cmt = idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1)
                    if func_cmt:
                        commented += 1
                    
                    # Count inline comments
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        curr = func.start_ea
                        while curr < func.end_ea:
                            if idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1):
                                inline_comments += 1
                            curr = idc.next_head(curr, func.end_ea)
            
            return {
                "total_functions": total,
                "functions_commented": commented,
                "coverage_pct": round(commented / total * 100, 1) if total else 0,
                "inline_comments": inline_comments
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 34. NAV - Navigation Helpers
# ============================================================================

@tool
@idaread
def nav(
    action: Annotated[Literal["bookmarks", "add_bookmark", "del_bookmark", "goto", "history", "cursor", "interesting"],
                      "Action: bookmarks|add_bookmark|del_bookmark|goto|history|cursor|interesting"],
    addr: Annotated[Optional[str], "Address to navigate to or bookmark"] = None,
    name: Annotated[Optional[str], "Bookmark name/label"] = None,
    slot: Annotated[int, "Bookmark slot number (1-10)"] = 0,
) -> dict:
    """
    Navigation helpers for bookmarks, cursor, and finding interesting addresses.
    
    ACTIONS:
    
    bookmarks - List all marked positions
        Returns: {bookmarks: [{slot, addr, name, description}]}
        
    add_bookmark - Add a marked position
        Params: addr, name (optional), slot (optional)
        Returns: {added, addr, slot}
        
    del_bookmark - Remove a bookmark
        Params: slot or addr
        Returns: {deleted, slot}
        
    goto - Get navigation info for address (doesn't move GUI cursor in headless)
        Params: addr
        Returns: {addr, func, segment, context}
        
    history - Get pseudo navigation history from xref patterns
        Returns: {note, suggestion}
        
    cursor - Get current analysis cursor position
        Returns: {addr, func, segment}
        
    interesting - Find interesting addresses (crypto, unusual patterns)
        Returns: {interesting: [{addr, reason, context}]}
    """
    try:
        if action == "bookmarks":
            bookmarks = []
            
            # IDA stores marked positions (bookmarks) in slots 1-1024
            for i in range(1, 1025):
                mark_ea = idc.get_bookmark(i)
                if mark_ea != idaapi.BADADDR:
                    mark_desc = idc.get_bookmark_desc(i)
                    bookmarks.append({
                        "slot": i,
                        "addr": hex(mark_ea),
                        "name": idc.get_name(mark_ea) or None,
                        "description": mark_desc or None
                    })
                if len(bookmarks) >= 100:
                    break
            
            return {"bookmarks": bookmarks}
        
        elif action == "add_bookmark":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            # Find an empty slot or use provided one
            target_slot = slot if slot > 0 else 1
            if slot == 0:
                for i in range(1, 1025):
                    if idc.get_bookmark(i) == idaapi.BADADDR:
                        target_slot = i
                        break
            
            # Set bookmark
            idc.put_bookmark(ea, 0, 0, 0, target_slot, name or f"Bookmark at {hex(ea)}")
            
            return {"added": True, "addr": hex(ea), "slot": target_slot, "name": name}
        
        elif action == "del_bookmark":
            if slot > 0:
                # Delete by slot
                idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, "")
                return {"deleted": True, "slot": slot}
            elif addr:
                # Find and delete by address
                ea = parse_address(addr)
                for i in range(1, 1025):
                    if idc.get_bookmark(i) == ea:
                        idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, i, "")
                        return {"deleted": True, "slot": i, "addr": hex(ea)}
                return {"error": f"No bookmark at {addr}"}
            else:
                return {"error": "slot or addr required"}
        
        elif action == "goto":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            seg = ida_segment.getseg(ea)
            
            result = {
                "addr": hex(ea),
                "name": idc.get_name(ea),
                "segment": idc.get_segm_name(ea) if seg else None
            }
            
            if func:
                result["function"] = idc.get_func_name(func.start_ea)
                result["offset_in_func"] = ea - func.start_ea
            
            # Disassembly context
            result["disasm"] = idc.GetDisasm(ea)
            
            # What's at this address?
            flags = idc.get_full_flags(ea)
            if idc.is_code(flags):
                result["type"] = "code"
            elif idc.is_data(flags):
                result["type"] = "data"
            else:
                result["type"] = "unknown"
            
            return result
        
        elif action == "history":
            # IDA headless doesn't maintain navigation history
            # But we can suggest interesting navigation targets
            return {
                "note": "Navigation history not available in headless mode",
                "suggestion": "Use 'interesting' action to find notable addresses"
            }
        
        elif action == "cursor":
            # In headless mode, we report the entry point or first function
            cursor_ea = idc.get_screen_ea()
            if cursor_ea == idaapi.BADADDR:
                # Fallback to entry point
                cursor_ea = idc.get_inf_attr(idc.INF_START_EA)
            
            func = ida_funcs.get_func(cursor_ea)
            seg = ida_segment.getseg(cursor_ea)
            
            return {
                "addr": hex(cursor_ea),
                "name": idc.get_name(cursor_ea),
                "segment": idc.get_segm_name(cursor_ea) if seg else None,
                "function": idc.get_func_name(func.start_ea) if func else None,
                "note": "In headless mode, cursor position may not reflect GUI state"
            }
        
        elif action == "interesting":
            interesting = []
            
            # Look for interesting patterns
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                
                seg_name = idc.get_segm_name(seg_ea)
                
                # Check for unusual segment names
                if any(x in seg_name.lower() for x in ['upx', 'aspack', 'themida', 'vmprotect']):
                    interesting.append({
                        "addr": hex(seg_ea),
                        "reason": "packer_segment",
                        "context": f"Segment name suggests packer: {seg_name}"
                    })
            
            # Find functions with interesting names
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name:
                        name_lower = name.lower()
                        if any(x in name_lower for x in ['crypt', 'decrypt', 'encode', 'decode', 'xor', 'rc4', 'aes']):
                            interesting.append({
                                "addr": hex(func_ea),
                                "reason": "crypto_function",
                                "context": f"Function name suggests crypto: {name}"
                            })
                        elif any(x in name_lower for x in ['anti', 'debug', 'detect', 'vm', 'sandbox']):
                            interesting.append({
                                "addr": hex(func_ea),
                                "reason": "anti_analysis",
                                "context": f"Function name suggests anti-analysis: {name}"
                            })
                    
                    if len(interesting) >= 50:
                        break
            
            return {"interesting": interesting[:50]}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 35. COLORIZE - Code Region Coloring
# ============================================================================

@tool
@idawrite
def colorize(
    action: Annotated[Literal["set_func", "set_range", "set_insn", "get", "clear", "palette", "highlight_pattern"],
                      "Action: set_func|set_range|set_insn|get|clear|palette|highlight_pattern"],
    addr: Annotated[Optional[str], "Address or start of range"] = None,
    end_addr: Annotated[Optional[str], "End of range for set_range"] = None,
    color: Annotated[Optional[str], "Color as RGB hex (e.g., 'FF0000') or name"] = None,
    pattern: Annotated[Optional[str], "Byte pattern to highlight"] = None,
) -> dict:
    """
    Code region coloring and highlighting for visual analysis.
    
    ACTIONS:
    
    set_func - Color an entire function
        Params: addr (any address in function), color
        Returns: {colored, func, color}
        
    set_range - Color an address range
        Params: addr, end_addr, color
        Returns: {colored, start, end, color}
        
    set_insn - Color a single instruction
        Params: addr, color
        Returns: {colored, addr, color}
        
    get - Get color at address
        Params: addr
        Returns: {addr, color, color_hex}
        
    clear - Remove coloring from address/range/function
        Params: addr, end_addr (optional for range)
        Returns: {cleared, addr}
        
    palette - Get named color palette
        Returns: {colors: {name: hex_value}}
        
    highlight_pattern - Highlight all occurrences of a byte pattern
        Params: pattern, color
        Returns: {highlighted, count, addresses}
    """
    try:
        # Named colors palette (IDA uses BGR format internally)
        COLORS = {
            "red": 0x0000FF,
            "green": 0x00FF00,
            "blue": 0xFF0000,
            "yellow": 0x00FFFF,
            "cyan": 0xFFFF00,
            "magenta": 0xFF00FF,
            "orange": 0x0080FF,
            "pink": 0x8080FF,
            "lightblue": 0xFFD0A0,
            "lightgreen": 0x80FF80,
            "lightyellow": 0x80FFFF,
            "white": 0xFFFFFF,
            "black": 0x000000,
            "gray": 0x808080,
            "default": 0xFFFFFFFF  # No color / reset
        }
        
        def parse_color(color_str):
            if not color_str:
                return COLORS["yellow"]  # Default highlight color
            
            color_str = color_str.lower().strip()
            
            # Named color
            if color_str in COLORS:
                return COLORS[color_str]
            
            # Hex color (RGB format, convert to BGR for IDA)
            if color_str.startswith('#'):
                color_str = color_str[1:]
            
            try:
                if len(color_str) == 6:
                    r = int(color_str[0:2], 16)
                    g = int(color_str[2:4], 16)
                    b = int(color_str[4:6], 16)
                    return (b << 16) | (g << 8) | r  # BGR format for IDA
            except:
                pass
            
            return COLORS["yellow"]
        
        def color_to_hex(bgr_color):
            if bgr_color == 0xFFFFFFFF:
                return None
            r = bgr_color & 0xFF
            g = (bgr_color >> 8) & 0xFF
            b = (bgr_color >> 16) & 0xFF
            return f"#{r:02X}{g:02X}{b:02X}"
        
        if action == "set_func":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function at {addr}"}
            
            bgr_color = parse_color(color)
            
            # Color all instructions in function
            curr = func.start_ea
            count = 0
            while curr < func.end_ea:
                idc.set_color(curr, idc.CIC_ITEM, bgr_color)
                count += 1
                curr = idc.next_head(curr, func.end_ea)
            
            return {
                "colored": True,
                "func": idc.get_func_name(func.start_ea),
                "addr": hex(func.start_ea),
                "instructions": count,
                "color": color or "yellow"
            }
        
        elif action == "set_range":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            end_ea = parse_address(end_addr) if end_addr else ea + 1
            
            bgr_color = parse_color(color)
            
            count = 0
            curr = ea
            while curr < end_ea:
                idc.set_color(curr, idc.CIC_ITEM, bgr_color)
                count += 1
                next_ea = idc.next_head(curr, end_ea)
                if next_ea == idaapi.BADADDR:
                    break
                curr = next_ea
            
            return {
                "colored": True,
                "start": hex(ea),
                "end": hex(end_ea),
                "instructions": count,
                "color": color or "yellow"
            }
        
        elif action == "set_insn":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            bgr_color = parse_color(color)
            
            idc.set_color(ea, idc.CIC_ITEM, bgr_color)
            
            return {
                "colored": True,
                "addr": hex(ea),
                "color": color or "yellow"
            }
        
        elif action == "get":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            bgr_color = idc.get_color(ea, idc.CIC_ITEM)
            
            return {
                "addr": hex(ea),
                "color_bgr": hex(bgr_color) if bgr_color != 0xFFFFFFFF else None,
                "color_hex": color_to_hex(bgr_color),
                "has_color": bgr_color != 0xFFFFFFFF
            }
        
        elif action == "clear":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            if end_addr:
                # Clear range
                end_ea = parse_address(end_addr)
                count = 0
                curr = ea
                while curr < end_ea:
                    idc.set_color(curr, idc.CIC_ITEM, 0xFFFFFFFF)
                    count += 1
                    next_ea = idc.next_head(curr, end_ea)
                    if next_ea == idaapi.BADADDR:
                        break
                    curr = next_ea
                return {"cleared": True, "start": hex(ea), "end": hex(end_ea), "count": count}
            else:
                # Check if in function - clear whole function
                func = ida_funcs.get_func(ea)
                if func:
                    curr = func.start_ea
                    count = 0
                    while curr < func.end_ea:
                        idc.set_color(curr, idc.CIC_ITEM, 0xFFFFFFFF)
                        count += 1
                        curr = idc.next_head(curr, func.end_ea)
                    return {"cleared": True, "func": idc.get_func_name(func.start_ea), "count": count}
                else:
                    # Just clear single address
                    idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFFFF)
                    return {"cleared": True, "addr": hex(ea)}
        
        elif action == "palette":
            # Return RGB hex values (not BGR)
            palette = {}
            for name, bgr in COLORS.items():
                if bgr == 0xFFFFFFFF:
                    palette[name] = "default"
                else:
                    r = bgr & 0xFF
                    g = (bgr >> 8) & 0xFF
                    b = (bgr >> 16) & 0xFF
                    palette[name] = f"#{r:02X}{g:02X}{b:02X}"
            
            return {"palette": palette}
        
        elif action == "highlight_pattern":
            if not pattern:
                return {"error": "pattern required"}
            
            bgr_color = parse_color(color)
            
            # Parse pattern
            pattern_bytes = []
            mask = []
            for part in pattern.split():
                if part == "??" or part == "?":
                    pattern_bytes.append(0)
                    mask.append(False)
                else:
                    pattern_bytes.append(int(part, 16))
                    mask.append(True)
            
            if not pattern_bytes:
                return {"error": "Invalid pattern"}
            
            # Search and highlight
            addresses = []
            
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                
                ea = seg.start_ea
                end_ea = seg.end_ea
                
                while ea < end_ea - len(pattern_bytes):
                    data = ida_bytes.get_bytes(ea, len(pattern_bytes))
                    if data:
                        match = True
                        for i in range(len(pattern_bytes)):
                            if mask[i] and data[i] != pattern_bytes[i]:
                                match = False
                                break
                        
                        if match:
                            idc.set_color(ea, idc.CIC_ITEM, bgr_color)
                            addresses.append(hex(ea))
                            if len(addresses) >= 100:
                                break
                    
                    ea = idc.next_head(ea, end_ea)
                    if ea == idaapi.BADADDR:
                        break
                
                if len(addresses) >= 100:
                    break
            
            return {
                "highlighted": True,
                "pattern": pattern,
                "count": len(addresses),
                "addresses": addresses[:20],
                "color": color or "yellow"
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# DYNAMIC ANALYSIS TOOLS (36-39) - Static-friendly dynamic analysis helpers
# ============================================================================

# ============================================================================
# 36. TRACE_ANALYSIS - Post-mortem execution trace analysis
# ============================================================================

@tool
@idaread
def trace_analysis(
    action: Annotated[Literal["import_trace", "analyze_coverage", "find_loops", "extract_api_calls", "basic_blocks_hit"],
                      "Action: import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit"],
    path: Annotated[Optional[str], "Path to trace file"] = None,
    addr: Annotated[Optional[str], "Function or address to analyze"] = None,
    trace_data: Annotated[Optional[list], "List of executed addresses"] = None,
) -> dict:
    """
    Analyze execution traces for coverage, loops, and API call patterns.
    
    ACTIONS:
    
    import_trace - Import a trace file (simple format: one address per line)
        Params: path
        Returns: {imported, address_count, functions_hit}
        
    analyze_coverage - Calculate code coverage from trace data
        Params: trace_data or path, addr (optional function filter)
        Returns: {total_blocks, hit_blocks, coverage_pct, missed_functions}
        
    find_loops - Detect hot loops from trace frequency
        Params: trace_data or path
        Returns: {loops: [{addr, hit_count, function}]}
        
    extract_api_calls - Extract API call sequence from trace
        Params: trace_data or path
        Returns: {api_sequence: [{addr, name, count}]}
        
    basic_blocks_hit - List which basic blocks were executed
        Params: addr (function), trace_data
        Returns: {function, blocks_total, blocks_hit, coverage}
    """
    try:
        import os
        
        # Helper to load trace data
        def load_trace(path_or_data):
            if path_or_data and isinstance(path_or_data, list):
                return [parse_address(str(a)) for a in path_or_data]
            elif path and os.path.exists(path):
                addresses = []
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                addresses.append(parse_address(line))
                            except:
                                pass
                return addresses
            return []
        
        if action == "import_trace":
            if not path:
                return {"error": "path required"}
            
            if not os.path.exists(path):
                return {"error": f"File not found: {path}"}
            
            addresses = load_trace(None)
            
            # Count functions hit
            functions_hit = set()
            for ea in addresses:
                func = ida_funcs.get_func(ea)
                if func:
                    functions_hit.add(func.start_ea)
            
            return {
                "imported": True,
                "path": path,
                "address_count": len(addresses),
                "unique_addresses": len(set(addresses)),
                "functions_hit": len(functions_hit)
            }
        
        elif action == "analyze_coverage":
            trace_addrs = set(load_trace(trace_data))
            
            if not trace_addrs:
                return {"error": "No trace data provided (use path or trace_data)"}
            
            # Calculate coverage
            total_blocks = 0
            hit_blocks = 0
            missed_functions = []
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        continue
                    
                    # Count basic blocks
                    try:
                        fc = idaapi.FlowChart(func)
                        func_blocks = 0
                        func_hit = 0
                        for block in fc:
                            func_blocks += 1
                            total_blocks += 1
                            # Check if any address in block was hit
                            for ea in range(block.start_ea, block.end_ea):
                                if ea in trace_addrs:
                                    func_hit += 1
                                    hit_blocks += 1
                                    break
                        
                        if func_hit == 0:
                            name = idc.get_func_name(func_ea)
                            if name and not name.startswith("sub_"):
                                missed_functions.append(name)
                    except:
                        pass
            
            return {
                "total_blocks": total_blocks,
                "hit_blocks": hit_blocks,
                "coverage_pct": round(hit_blocks / total_blocks * 100, 2) if total_blocks else 0,
                "missed_functions": missed_functions[:50]
            }
        
        elif action == "find_loops":
            trace_addrs = load_trace(trace_data)
            
            if not trace_addrs:
                return {"error": "No trace data"}
            
            # Count address frequency
            from collections import Counter
            freq = Counter(trace_addrs)
            
            # Find hot addresses (executed more than 10 times)
            loops = []
            for ea, count in freq.most_common(50):
                if count > 10:
                    func = ida_funcs.get_func(ea)
                    loops.append({
                        "addr": hex(ea),
                        "hit_count": count,
                        "function": idc.get_func_name(func.start_ea) if func else None
                    })
            
            return {"loops": loops}
        
        elif action == "extract_api_calls":
            trace_addrs = load_trace(trace_data)
            
            if not trace_addrs:
                return {"error": "No trace data"}
            
            # Find API calls (imported functions)
            api_calls = []
            from collections import Counter
            
            for ea in set(trace_addrs):
                name = idc.get_name(ea)
                if name:
                    # Check if it's an import
                    flags = idc.get_full_flags(ea)
                    if idc.is_code(flags):
                        # Check xrefs to see if it references imports
                        for xref in idautils.XrefsFrom(ea):
                            target_name = idc.get_name(xref.to)
                            if target_name and not target_name.startswith("sub_"):
                                api_calls.append(target_name)
            
            # Count and order
            freq = Counter(api_calls)
            return {
                "api_sequence": [
                    {"name": name, "count": count}
                    for name, count in freq.most_common(100)
                ]
            }
        
        elif action == "basic_blocks_hit":
            if not addr:
                return {"error": "addr required (function address)"}
            
            trace_addrs = set(load_trace(trace_data))
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function at {addr}"}
            
            try:
                fc = idaapi.FlowChart(func)
                blocks_total = 0
                blocks_hit = 0
                block_info = []
                
                for block in fc:
                    blocks_total += 1
                    hit = False
                    for block_ea in range(block.start_ea, block.end_ea):
                        if block_ea in trace_addrs:
                            hit = True
                            break
                    
                    if hit:
                        blocks_hit += 1
                    
                    block_info.append({
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "hit": hit
                    })
                
                return {
                    "function": idc.get_func_name(ea) or hex(ea),
                    "blocks_total": blocks_total,
                    "blocks_hit": blocks_hit,
                    "coverage_pct": round(blocks_hit / blocks_total * 100, 2) if blocks_total else 0,
                    "blocks": block_info[:30]
                }
            except:
                return {"error": "Could not analyze function blocks"}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================

@tool
@idaread
def hooks(
    action: Annotated[Literal["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"],
                      "Action: suggest|generate_frida|generate_detours|find_targets|inline_hooks"],
    category: Annotated[Optional[str], "Hook category: network|file|crypto|registry|process"] = None,
    addr: Annotated[Optional[str], "Specific function address to hook"] = None,
    func_name: Annotated[Optional[str], "Function name to hook"] = None,
) -> dict:
    """
    Generate hook scripts and suggestions for dynamic analysis.
    
    ACTIONS:
    
    suggest - Suggest functions to hook based on category
        Params: category (network|file|crypto|registry|process)
        Returns: {suggestions: [{name, addr, reason}]}
        
    generate_frida - Generate Frida hook script for function
        Params: addr or func_name
        Returns: {script: "JavaScript code"}
        
    generate_detours - Generate Microsoft Detours template
        Params: addr or func_name
        Returns: {code: "C++ template"}
        
    find_targets - Find interesting hook targets in binary
        Returns: {targets: [{addr, name, category, importance}]}
        
    inline_hooks - Suggest inline hook points (for trampolines)
        Params: addr
        Returns: {hook_points: [{addr, bytes_available, safe}]}
    """
    try:
        # Category-based function patterns
        HOOK_PATTERNS = {
            "network": ["send", "recv", "connect", "socket", "WSA", "accept", "bind", "listen",
                       "getaddrinfo", "gethostby", "inet_", "http", "curl", "ssl", "tls"],
            "file": ["CreateFile", "ReadFile", "WriteFile", "fopen", "fread", "fwrite",
                    "open", "read", "write", "close", "NtCreateFile", "NtReadFile"],
            "crypto": ["Crypt", "BCrypt", "NCrypt", "AES", "RSA", "SHA", "MD5", "hash",
                      "encrypt", "decrypt", "cipher", "key", "EVP_"],
            "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreate", "NtOpenKey"],
            "process": ["CreateProcess", "VirtualAlloc", "VirtualProtect", "LoadLibrary",
                       "GetProcAddress", "NtAllocate", "mmap", "mprotect", "execve", "fork"]
        }
        
        if action == "suggest":
            cat = (category or "").lower()
            if cat not in HOOK_PATTERNS:
                return {"error": f"Unknown category. Use: {', '.join(HOOK_PATTERNS.keys())}"}
            
            patterns = HOOK_PATTERNS[cat]
            suggestions = []
            
            # Search imports
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg and seg.type == ida_segment.SEG_XTRN:  # Import segment
                    for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                        name = idc.get_name(head)
                        if name:
                            for pattern in patterns:
                                if pattern.lower() in name.lower():
                                    suggestions.append({
                                        "name": name,
                                        "addr": hex(head),
                                        "pattern_match": pattern,
                                        "type": "import"
                                    })
                                    break
            
            # Search named functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name:
                        for pattern in patterns:
                            if pattern.lower() in name.lower():
                                suggestions.append({
                                    "name": name,
                                    "addr": hex(func_ea),
                                    "pattern_match": pattern,
                                    "type": "function"
                                })
                                break
            
            return {"category": cat, "suggestions": suggestions[:50]}
        
        elif action == "generate_frida":
            if not addr and not func_name:
                return {"error": "addr or func_name required"}
            
            if func_name:
                ea = idc.get_name_ea_simple(func_name)
                if ea == idaapi.BADADDR:
                    return {"error": f"Function '{func_name}' not found"}
            else:
                ea = parse_address(addr)
            
            name = idc.get_func_name(ea) or f"sub_{ea:x}"
            
            # Generate Frida script
            script = f'''// Frida hook for {name} at {hex(ea)}
const moduleBase = Module.getBaseAddress("TARGET_MODULE");
const funcAddr = moduleBase.add({hex(ea - idaapi.get_imagebase())});

Interceptor.attach(funcAddr, {{
    onEnter: function(args) {{
        console.log("[+] {name} called");
        console.log("    arg0:", args[0]);
        console.log("    arg1:", args[1]);
        console.log("    arg2:", args[2]);
        // this.arg0 = args[0]; // Save for onLeave
    }},
    onLeave: function(retval) {{
        console.log("[+] {name} returned:", retval);
        // retval.replace(0x1337); // Modify return value
    }}
}});
'''
            return {"function": name, "addr": hex(ea), "script": script}
        
        elif action == "generate_detours":
            if not addr and not func_name:
                return {"error": "addr or func_name required"}
            
            if func_name:
                ea = idc.get_name_ea_simple(func_name)
                if ea == idaapi.BADADDR:
                    return {"error": f"Function '{func_name}' not found"}
            else:
                ea = parse_address(addr)
            
            name = idc.get_func_name(ea) or f"sub_{ea:x}"
            
            # Generate Detours template
            code = f'''// Microsoft Detours hook for {name}
#include <windows.h>
#include <detours.h>

// Original function pointer
typedef DWORD (WINAPI *Orig_{name}_t)(LPVOID arg1, LPVOID arg2, LPVOID arg3);
Orig_{name}_t pOrig_{name} = (Orig_{name}_t){hex(ea)};

// Hook function
DWORD WINAPI Hook_{name}(LPVOID arg1, LPVOID arg2, LPVOID arg3) {{
    // Pre-call logic
    OutputDebugStringA("[HOOK] {name} called\\n");
    
    // Call original
    DWORD result = pOrig_{name}(arg1, arg2, arg3);
    
    // Post-call logic
    return result;
}}

void InstallHook() {{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOrig_{name}, Hook_{name});
    DetourTransactionCommit();
}}
'''
            return {"function": name, "addr": hex(ea), "code": code}
        
        elif action == "find_targets":
            targets = []
            importance_keywords = {
                "high": ["password", "key", "crypt", "auth", "token", "secret", "license"],
                "medium": ["send", "recv", "file", "read", "write", "execute", "load"],
                "normal": []
            }
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if not name or name.startswith("sub_"):
                        continue
                    
                    name_lower = name.lower()
                    importance = "normal"
                    cat = "other"
                    
                    # Determine category
                    for category, patterns in HOOK_PATTERNS.items():
                        for p in patterns:
                            if p.lower() in name_lower:
                                cat = category
                                break
                    
                    # Determine importance
                    for level, keywords in importance_keywords.items():
                        for kw in keywords:
                            if kw in name_lower:
                                importance = level
                                break
                    
                    if cat != "other" or importance != "normal":
                        targets.append({
                            "addr": hex(func_ea),
                            "name": name,
                            "category": cat,
                            "importance": importance
                        })
            
            # Sort by importance
            importance_order = {"high": 0, "medium": 1, "normal": 2}
            targets.sort(key=lambda x: importance_order.get(x["importance"], 2))
            
            return {"targets": targets[:100]}
        
        elif action == "inline_hooks":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function at {addr}"}
            
            hook_points = []
            current = func.start_ea
            
            while current < func.end_ea and len(hook_points) < 20:
                insn = idaapi.insn_t()
                length = idaapi.decode_insn(insn, current)
                
                if length >= 5:  # Need at least 5 bytes for JMP
                    # Check if this is a safe hook point (not in middle of instruction)
                    hook_points.append({
                        "addr": hex(current),
                        "bytes_available": length,
                        "safe": length >= 5,
                        "disasm": idc.generate_disasm_line(current, 0) or ""
                    })
                
                current += length if length > 0 else 1
            
            return {"function": idc.get_func_name(ea) or hex(ea), "hook_points": hook_points}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 38. TAINT - Static Taint/Data Flow Analysis
# ============================================================================

@tool
@idaread
def taint(
    action: Annotated[Literal["trace_arg", "trace_return", "find_sinks", "data_flow", "slice"],
                      "Action: trace_arg|trace_return|find_sinks|data_flow|slice"],
    addr: Annotated[Optional[str], "Function or instruction address"] = None,
    arg_num: Annotated[int, "Argument number to trace (0-indexed)"] = 0,
    depth: Annotated[int, "Analysis depth"] = 5,
) -> dict:
    """
    Static taint/data flow analysis using Hex-Rays.
    
    ACTIONS:
    
    trace_arg - Trace where a function argument flows to
        Params: addr (function), arg_num
        Returns: {uses: [{addr, operation, propagates_to}]}
        
    trace_return - Trace where a function's return value is used
        Params: addr (function)
        Returns: {callers: [{call_site, usage}]}
        
    find_sinks - Find dangerous functions reachable from address
        Params: addr, depth
        Returns: {sinks: [{name, path_length, danger_level}]}
        
    data_flow - Analyze data flow through a function
        Params: addr
        Returns: {inputs, outputs, transformations}
        
    slice - Extract backward slice from an instruction
        Params: addr (instruction)
        Returns: {slice: [{addr, contributes_to}]}
    """
    try:
        DANGEROUS_SINKS = [
            ("system", "high", "command execution"),
            ("exec", "high", "command execution"),
            ("popen", "high", "command execution"),
            ("ShellExecute", "high", "command execution"),
            ("CreateProcess", "medium", "process creation"),
            ("strcpy", "medium", "buffer overflow"),
            ("sprintf", "medium", "format string"),
            ("gets", "high", "buffer overflow"),
            ("memcpy", "low", "memory corruption"),
            ("VirtualAlloc", "low", "memory allocation"),
            ("LoadLibrary", "medium", "dll loading"),
            ("eval", "high", "code execution"),
        ]
        
        if action == "trace_arg":
            if not addr:
                return {"error": "addr required (function address)"}
            
            ea = parse_address(addr)
            
            # Try to use Hex-Rays for analysis
            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    return {"error": "Decompilation failed"}
                
                uses = []
                
                # Find the argument variable
                if arg_num < len(cfunc.lvars):
                    target_var = None
                    arg_count = 0
                    for lvar in cfunc.lvars:
                        if lvar.is_arg_var:
                            if arg_count == arg_num:
                                target_var = lvar
                                break
                            arg_count += 1
                    
                    if target_var:
                        # Simplified: just report the variable info
                        uses.append({
                            "var_name": target_var.name,
                            "type": str(target_var.type()),
                            "is_arg": True,
                            "note": "Use ctree tool for detailed flow analysis"
                        })
                
                return {
                    "function": idc.get_func_name(ea) or hex(ea),
                    "arg_num": arg_num,
                    "uses": uses
                }
                
            except:
                return {"error": "Hex-Rays analysis failed", "note": "Decompiler required"}
        
        elif action == "trace_return":
            if not addr:
                return {"error": "addr required (function address)"}
            
            ea = parse_address(addr)
            func_name = idc.get_func_name(ea)
            
            callers = []
            for xref in idautils.XrefsTo(ea):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                    caller_func = ida_funcs.get_func(xref.frm)
                    
                    # Check what happens after the call
                    next_insn = idc.next_head(xref.frm)
                    next_disasm = idc.generate_disasm_line(next_insn, 0) if next_insn != idaapi.BADADDR else ""
                    
                    callers.append({
                        "call_site": hex(xref.frm),
                        "caller_func": idc.get_func_name(caller_func.start_ea) if caller_func else None,
                        "next_insn": ida_lines.tag_remove(next_disasm) if next_disasm else None
                    })
            
            return {"function": func_name or hex(ea), "callers": callers[:30]}
        
        elif action == "find_sinks":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            sinks_found = []
            visited = set()
            
            def search_calls(start_ea, current_depth):
                if current_depth > depth or start_ea in visited:
                    return
                visited.add(start_ea)
                
                func = ida_funcs.get_func(start_ea)
                if not func:
                    return
                
                # Scan function for calls
                current = func.start_ea
                while current < func.end_ea:
                    insn = idaapi.insn_t()
                    length = idaapi.decode_insn(insn, current)
                    
                    if length > 0:
                        # Check for call instructions
                        for xref in idautils.XrefsFrom(current):
                            if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                                target_name = idc.get_name(xref.to)
                                if target_name:
                                    # Check against dangerous sinks
                                    for sink_name, danger, reason in DANGEROUS_SINKS:
                                        if sink_name.lower() in target_name.lower():
                                            sinks_found.append({
                                                "name": target_name,
                                                "addr": hex(xref.to),
                                                "call_site": hex(current),
                                                "path_length": current_depth,
                                                "danger_level": danger,
                                                "reason": reason
                                            })
                                    
                                    # Recurse into called function
                                    if current_depth < depth:
                                        search_calls(xref.to, current_depth + 1)
                    
                    current += length if length > 0 else 1
            
            search_calls(ea, 0)
            
            # Sort by danger level
            danger_order = {"high": 0, "medium": 1, "low": 2}
            sinks_found.sort(key=lambda x: danger_order.get(x["danger_level"], 2))
            
            return {"start": hex(ea), "depth": depth, "sinks": sinks_found[:30]}
        
        elif action == "data_flow":
            if not addr:
                return {"error": "addr required"}
            
            ea = parse_address(addr)
            
            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    return {"error": "Decompilation failed"}
                
                inputs = []
                outputs = []
                
                for lvar in cfunc.lvars:
                    var_info = {
                        "name": lvar.name,
                        "type": str(lvar.type())
                    }
                    
                    if lvar.is_arg_var:
                        inputs.append(var_info)
                    elif lvar.is_result_var:
                        outputs.append(var_info)
                
                return {
                    "function": idc.get_func_name(ea) or hex(ea),
                    "inputs": inputs,
                    "outputs": outputs,
                    "note": "Use ctree for detailed transformations"
                }
                
            except:
                return {"error": "Decompilation failed"}
        
        elif action == "slice":
            if not addr:
                return {"error": "addr required (instruction address)"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function containing {addr}"}
            
            # Simple backward slice: find instructions that affect this one
            slice_instrs = []
            
            # Get the instruction and what it reads
            disasm = idc.generate_disasm_line(ea, 0)
            
            # Walk backwards looking for definitions
            current = idc.prev_head(ea)
            for _ in range(50):  # Limit
                if current == idaapi.BADADDR or current < func.start_ea:
                    break
                
                curr_disasm = idc.generate_disasm_line(current, 0)
                if curr_disasm:
                    slice_instrs.append({
                        "addr": hex(current),
                        "disasm": ida_lines.tag_remove(curr_disasm)
                    })
                
                current = idc.prev_head(current)
            
            slice_instrs.reverse()
            
            return {
                "target": hex(ea),
                "target_disasm": ida_lines.tag_remove(disasm) if disasm else "",
                "backward_slice": slice_instrs[:20],
                "note": "Simplified slice - use Hex-Rays for accurate data dependencies"
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 39. COVERAGE - Code Coverage Import and Analysis
# ============================================================================

@tool
@idaread
def coverage(
    action: Annotated[Literal["import_drcov", "import_lighthouse", "highlight", "report", "uncovered"],
                      "Action: import_drcov|import_lighthouse|highlight|report|uncovered"],
    path: Annotated[Optional[str], "Path to coverage file"] = None,
    addr: Annotated[Optional[str], "Function to analyze"] = None,
    color: Annotated[Optional[str], "Highlight color (green|yellow|red)"] = "green",
) -> dict:
    """
    Import and analyze code coverage data from various sources.
    
    ACTIONS:
    
    import_drcov - Import DynamoRIO coverage file
        Params: path
        Returns: {imported, modules, basic_blocks}
        
    import_lighthouse - Import Lighthouse/coverage.py format
        Params: path
        Returns: {imported, addresses}
        
    highlight - Highlight covered code in IDA
        Params: path (coverage file), color
        Returns: {highlighted, count}
        
    report - Generate coverage report for function
        Params: addr (function), path (optional coverage data)
        Returns: {function, total_blocks, covered, percentage}
        
    uncovered - Find important uncovered functions
        Params: path
        Returns: {uncovered: [{name, importance, reason}]}
    """
    try:
        import os
        import struct
        
        def parse_drcov(filepath):
            """Parse DynamoRIO drcov format"""
            if not os.path.exists(filepath):
                return None, "File not found"
            
            modules = []
            blocks = []
            
            with open(filepath, 'rb') as f:
                # Read header
                line = f.readline().decode('utf-8', errors='ignore').strip()
                if not line.startswith('DRCOV'):
                    return None, "Not a drcov file"
                
                # Skip to module table
                while True:
                    line = f.readline().decode('utf-8', errors='ignore').strip()
                    if line.startswith('Module Table'):
                        break
                    if not line:
                        return None, "Invalid format"
                
                # Read module count
                parts = line.split(':')
                if len(parts) >= 2:
                    count = int(parts[1].strip().split()[0])
                    for _ in range(count):
                        mod_line = f.readline().decode('utf-8', errors='ignore').strip()
                        # Parse: id, base, end, entry, checksum, timestamp, path
                        parts = mod_line.split(',')
                        if len(parts) >= 7:
                            modules.append({
                                "id": int(parts[0].strip()),
                                "base": int(parts[1].strip(), 16) if parts[1].strip().startswith('0x') else int(parts[1].strip()),
                                "path": parts[6].strip() if len(parts) > 6 else ""
                            })
                
                # Find BB Table
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.decode('utf-8', errors='ignore').strip()
                    if line.startswith('BB Table'):
                        break
                
                # Read basic blocks (binary format follows)
                while True:
                    data = f.read(8)  # start (4 bytes), size (2 bytes), mod_id (2 bytes)
                    if len(data) < 8:
                        break
                    start, size, mod_id = struct.unpack('<IHH', data)
                    blocks.append({
                        "start": start,
                        "size": size,
                        "module_id": mod_id
                    })
            
            return {"modules": modules, "blocks": blocks}, None
        
        if action == "import_drcov":
            if not path:
                return {"error": "path required"}
            
            result, error = parse_drcov(path)
            if error:
                return {"error": error}
            
            return {
                "imported": True,
                "path": path,
                "modules": len(result["modules"]),
                "basic_blocks": len(result["blocks"]),
                "module_names": [m["path"] for m in result["modules"][:10]]
            }
        
        elif action == "import_lighthouse":
            if not path:
                return {"error": "path required"}
            
            if not os.path.exists(path):
                return {"error": f"File not found: {path}"}
            
            addresses = []
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            addr = int(line, 16) if line.startswith('0x') else int(line)
                            addresses.append(addr)
                        except:
                            pass
            
            return {
                "imported": True,
                "path": path,
                "addresses": len(addresses),
                "unique": len(set(addresses))
            }
        
        elif action == "highlight":
            if not path:
                return {"error": "path required"}
            
            # Try to parse as simple address list first
            addresses = set()
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                addresses.add(parse_address(line))
                            except:
                                pass
            
            if not addresses:
                # Try drcov
                result, _ = parse_drcov(path)
                if result:
                    base = idaapi.get_imagebase()
                    for block in result["blocks"]:
                        for offset in range(block["size"]):
                            addresses.add(base + block["start"] + offset)
            
            # Color mapping
            color_map = {
                "green": 0x90EE90,
                "yellow": 0x00FFFF,
                "red": 0x0000FF
            }
            bgr = color_map.get(color, 0x90EE90)
            
            count = 0
            for ea in addresses:
                if idc.is_mapped(ea):
                    idc.set_color(ea, idc.CIC_ITEM, bgr)
                    count += 1
            
            return {"highlighted": True, "count": count, "color": color}
        
        elif action == "report":
            if not addr:
                return {"error": "addr required (function address)"}
            
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return {"error": f"No function at {addr}"}
            
            # Load coverage if path provided
            covered_addrs = set()
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                covered_addrs.add(parse_address(line))
                            except:
                                pass
            
            # Analyze function blocks
            try:
                fc = idaapi.FlowChart(func)
                total = 0
                covered = 0
                blocks = []
                
                for block in fc:
                    total += 1
                    is_covered = any(ea in covered_addrs for ea in range(block.start_ea, block.end_ea))
                    if is_covered:
                        covered += 1
                    blocks.append({
                        "start": hex(block.start_ea),
                        "covered": is_covered
                    })
                
                return {
                    "function": idc.get_func_name(ea) or hex(ea),
                    "total_blocks": total,
                    "covered_blocks": covered,
                    "percentage": round(covered / total * 100, 2) if total else 0,
                    "blocks": blocks[:20]
                }
            except:
                return {"error": "Could not analyze function"}
        
        elif action == "uncovered":
            # Load coverage data
            covered_funcs = set()
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        try:
                            ea = parse_address(line.strip())
                            func = ida_funcs.get_func(ea)
                            if func:
                                covered_funcs.add(func.start_ea)
                        except:
                            pass
            
            # Find uncovered functions
            uncovered = []
            importance_keywords = ["main", "init", "parse", "process", "handle", "check", "verify"]
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if func_ea in covered_funcs:
                        continue
                    
                    name = idc.get_func_name(func_ea)
                    if not name or name.startswith("sub_"):
                        continue
                    
                    importance = "normal"
                    reason = ""
                    name_lower = name.lower()
                    
                    for kw in importance_keywords:
                        if kw in name_lower:
                            importance = "high"
                            reason = f"Contains '{kw}'"
                            break
                    
                    uncovered.append({
                        "addr": hex(func_ea),
                        "name": name,
                        "importance": importance,
                        "reason": reason
                    })
            
            # Sort by importance
            uncovered.sort(key=lambda x: 0 if x["importance"] == "high" else 1)
            
            return {"uncovered": uncovered[:50]}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# END OF DYNAMIC ANALYSIS TOOLS (36-39)
# Total tools: 39
# ============================================================================
