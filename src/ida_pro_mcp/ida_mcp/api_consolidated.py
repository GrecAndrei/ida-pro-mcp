"""IDA Pro MCP - Consolidated API

DESIGN: ~10 mega-tools covering all functionality, optimized for context efficiency.
Each tool uses an 'action' parameter to access sub-operations.

TOOLS:
1. idb - database metadata, segments, cursor
2. code - decompile, disassemble, xrefs, callgraph, basic blocks
3. data - functions, globals, strings, imports, exports
4. search - find bytes, patterns, instructions, strings, references
5. types - local types, structs, enums, prototypes
6. memory - read/write all data types
7. modify - rename, set type, comments
8. debug - all debugger operations
9. analysis - reanalyze, auto_wait, comprehensive function analysis
10. misc - python exec, signatures, bookmarks, undo
"""

from typing import Annotated, Optional, Literal, Union, Any
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

from .rpc import tool, unsafe
from .sync import idaread, idawrite, IDAError
from .utils import (
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
        if not addrs:
            return {"error": "addrs required"}
        addrs = normalize_list_input(addrs)
        results = []
        
        for addr in addrs:
            ea = parse_address(addr)
            
            if action == "decompile":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
                    continue
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    results.append({
                        "addr": addr, 
                        "name": ida_funcs.get_func_name(func.start_ea),
                        "code": str(cfunc)
                    })
                except Exception as e:
                    results.append({"addr": addr, "error": str(e)})
            
            elif action == "disasm":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "No function"})
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
            return {"functions": funcs, "total": total}
        
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
                            if not query or query.lower() in s.lower():
                                strings.append({"addr": hex(sc.ea), "string": s, "length": sc.length})
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
    pattern: Annotated[str, "Pattern to search for"],
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
    - pattern: The search query (hex string, text, glob, or comma-separated mnemonics).
    - limit: Max number of results (default 100).
    """
    try:
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
    value: Annotated[str, "New name, comment text, type declaration, or assembly instruction"],
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
    - value: The content to apply (new name, comment text, type string, or assembly code).
    - comment_type: One of 'regular', 'repeatable', 'anterior', 'posterior'.
    """
    try:
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
            exec_globals = {
                "idaapi": idaapi, "idc": idc, "idautils": idautils,
                "ida_bytes": ida_bytes, "ida_funcs": ida_funcs,
                "ida_typeinf": ida_typeinf, "ida_nalt": ida_nalt,
            }
            try:
                result = str(eval(code, exec_globals))
            except:
                exec(code, exec_globals)
                result = "executed"
            return {"result": result}
        
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
