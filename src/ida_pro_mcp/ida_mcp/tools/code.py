
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 2. CODE - Decompilation & Disassembly
# ============================================================================

@tool
@idaread
def code(
    action: Annotated[Literal[
        "decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field",
        "callees", "callers", "blocks", "analyze", "callgraph", "export",
        "find_paths", "strings_in_func", "diff_functions"
    ], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es) - hex string or name"] = None,
    addr: Annotated[Optional[str], "Single address (alias for addrs)"] = None,  # Alias for compatibility
    max_items: Annotated[int, "Max items to return"] = 1000,
    max_depth: Annotated[int, "Max depth for callgraph/find_paths"] = 5,
    format: Annotated[Literal["json", "c_header", "prototypes"], "Export format"] = "json",
    field_name: Annotated[Optional[str], "Struct field name (for xrefs_to_field)"] = None,
    target: Annotated[Optional[str], "Target address (for find_paths)"] = None,
    **kwargs
) -> list[dict] | dict:
    """
    Perform code analysis, decompilation, and graph traversal.
    
    ACTIONS:
    
    decompile - Decompile function to Pseudo-C (requires Hex-Rays)
        Params: addrs (REQUIRED)
        Returns: [{addr, code, prototype}] or {addr, error}
        Example: code(action="decompile", addrs="0x401000")
        Example: code(action="decompile", addrs=["main", "0x402000"])
        
    disasm - Get assembly listing (compact text, one line per instruction)
        Params: addrs (REQUIRED)
        Returns: [{addr, name, disasm: "addr  instr\\naddr  instr\\n...", count}]
        Example: code(action="disasm", addrs="0x401000")
        
    xrefs_to - Get cross-references TO an address (compact text, includes function names)
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: "addr  type  func_name\\n...", count}]
        Example: code(action="xrefs_to", addrs="0x401000")
        
    xrefs_from - Get cross-references FROM an address (compact text, includes names)
        Params: addrs (REQUIRED)  
        Returns: [{addr, xrefs: "addr  type  name\\n...", count}]
        Example: code(action="xrefs_from", addrs="0x401000")
        
    callees - List functions called BY this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callees: "addr  name\\n...", count}]
        Example: code(action="callees", addrs="main")
        
    callers - List functions that CALL this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callers: "addr  name\\n...", count}]
        Example: code(action="callers", addrs="printf")
        
    blocks - Get basic blocks (compact text with successors/predecessors)
        Params: addrs (REQUIRED)
        Returns: [{addr, blocks: "start-end  succs=[...]  preds=[...]\\n...", count}]
        Example: code(action="blocks", addrs="0x401000")
        
    analyze - Comprehensive analysis (decompile + callees + callers + strings)
        Params: addrs (REQUIRED)
        Returns: [{addr, pseudocode, prototype, callees, callers, strings}]
        Example: code(action="analyze", addrs="main")
        Best for: Getting full context about a function in one call
        
    callgraph - Generate call graph from starting function (compact text)
        Params: addrs (REQUIRED), max_depth (default 5)
        Returns: [{addr, nodes: "addr  depth=N  name\\n...", edges: "addr -> addr\\n..."}]
        Example: code(action="callgraph", addrs="main", max_depth=3)
        
    find_paths - Find control flow paths between two addresses
        Params: addrs (REQUIRED), target (REQUIRED)
        Returns: [{addr, paths: [[addr1, addr2, ...], ...]}]
        Example: code(action="find_paths", addrs="0x401000", target="0x402000")
        
    strings_in_func - List strings referenced in function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, strings: "addr  string_value\\n...", count}]
        Example: code(action="strings_in_func", addrs="main")

    diff_functions - Compare two functions' decompilation side by side
        Params: addrs (REQUIRED - exactly 2 addresses)
        Returns: {func_a, func_b, diff: "unified diff text", similarity: float}
        Example: code(action="diff_functions", addrs=["0x401000", "0x402000"])
    """
    try:
        # Support both addr (singular) and addrs (plural) for compatibility
        if not addrs and addr:
            addrs = addr
        if not addrs:
            return make_error(MCPError.INVALID_ARGS, "addrs or addr parameter required")
        addrs = normalize_list_input(addrs)
        results = []
        
        for addr in addrs:
            ea, error = validate_addr(addr)
            if error:
                results.append({"addr": addr, **error})
                continue
            
            if action == "decompile":
                func = idaapi.get_func(ea)
                if not func:
                    # Find nearest function for better error
                    prev_func = idaapi.get_prev_func(ea)
                    next_func = idaapi.get_next_func(ea)
                    suggestion = ""
                    if prev_func:
                        suggestion = f" Try {hex_ea(prev_func.start_ea)} ({ida_funcs.get_func_name(prev_func.start_ea) or 'unnamed'})"
                    elif next_func:
                        suggestion = f" Try {hex_ea(next_func.start_ea)} ({ida_funcs.get_func_name(next_func.start_ea) or 'unnamed'})"
                    
                    results.append({"addr": addr, "error": f"No function at {hex_ea(ea)}.{suggestion}"})
                    continue
                
                try:
                    if not ida_hexrays.init_hexrays_plugin():
                        results.append({"addr": addr, "error": "Hex-Rays decompiler not available"})
                        continue
                        
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        results.append({
                            "ok": True,
                            "addr": hex_ea(func.start_ea),
                            "code": str(cfunc),
                            "prototype": get_prototype(func)
                        })
                    else:
                        results.append({"addr": addr, "error": "Decompilation failed"})
                except Exception as e:
                    results.append({"addr": addr, "error": str(e)})
            
            elif action == "disasm":
                func = idaapi.get_func(ea)
                if not func:
                    # Disassemble raw bytes even without function
                    lines = []
                    curr = ea
                    for _ in range(50):  # Show 50 lines anyway
                        line = idc.generate_disasm_line(curr, 0)
                        if line:
                            lines.append(f"{hex_ea(curr)}  {line}")
                        next_ea = idc.next_head(curr, ea + 0x1000)
                        if next_ea == idaapi.BADADDR or next_ea <= curr:
                            break
                        curr = next_ea
                    results.append({
                        "addr": addr, 
                        "warning": "Address is not within a defined function. Showing raw disassembly.",
                        "disasm": "\n".join(lines),
                        "count": len(lines)
                    })
                    continue
                lines = []
                curr = func.start_ea
                count = 0
                while curr < func.end_ea and count < max_items:
                    lines.append(f"{hex_ea(curr)}  {idc.generate_disasm_line(curr, 0)}")
                    curr = idc.next_head(curr, func.end_ea)
                    count += 1
                fname = ida_funcs.get_func_name(func.start_ea)
                results.append({"ok": True, "addr": hex_ea(func.start_ea), "name": fname, "disasm": "\n".join(lines), "count": count})
            
            elif action == "xrefs_to":
                xref_lines = []
                for x in idautils.XrefsTo(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    fn = idaapi.get_func(x.frm)
                    fn_name = ida_funcs.get_func_name(fn.start_ea) if fn else ""
                    xref_lines.append(f"{hex_ea(x.frm)}  {kind}  {fn_name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})
            
            elif action == "xrefs_from":
                xref_lines = []
                for x in idautils.XrefsFrom(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    name = ida_name.get_name(x.to) or ""
                    xref_lines.append(f"{hex_ea(x.to)}  {kind}  {name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})
            
            elif action == "callees":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}", "Use 'funcs.create' to define a function here first"))
                    continue
                callees = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.iscode:
                            target_func = idaapi.get_func(xref.to)
                            if target_func and target_func.start_ea != func.start_ea:
                                callees.add((hex_ea(target_func.start_ea), 
                                            ida_funcs.get_func_name(target_func.start_ea)))
                callee_lines = [f"{a}  {n}" for a, n in sorted(callees)]
                results.append({"ok": True, "addr": addr, "callees": "\n".join(callee_lines), "count": len(callee_lines)})
            
            elif action == "callers":
                func = idaapi.get_func(ea)
                start = func.start_ea if func else ea
                callers = set()
                for xref in idautils.XrefsTo(start, 0):
                    if xref.iscode:
                        caller_func = idaapi.get_func(xref.frm)
                        if caller_func:
                            callers.add((hex_ea(caller_func.start_ea),
                                        ida_funcs.get_func_name(caller_func.start_ea)))
                caller_lines = [f"{a}  {n}" for a, n in sorted(callers)]
                results.append({"ok": True, "addr": addr, "callers": "\n".join(caller_lines), "count": len(caller_lines)})
            
            elif action == "blocks":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                fc = idaapi.FlowChart(func)
                block_lines = []
                block_count = 0
                for block in fc:
                    succs = ",".join(hex_ea(s.start_ea) for s in block.succs())
                    preds = ",".join(hex_ea(p.start_ea) for p in block.preds())
                    block_lines.append(f"{hex_ea(block.start_ea)}-{hex_ea(block.end_ea)}  succs=[{succs}]  preds=[{preds}]")
                    block_count += 1
                    if block_count >= max_items:
                        break
                results.append({"ok": True, "addr": addr, "blocks": "\n".join(block_lines), "count": block_count})
            
            elif action == "analyze":
                # Comprehensive function analysis
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                
                fname = ida_funcs.get_func_name(func.start_ea)
                info = {"ok": True, "addr": hex_ea(func.start_ea), "name": fname, "size": hex_size(func.end_ea - func.start_ea)}
                
                # Decompile
                try:
                    if ida_hexrays.init_hexrays_plugin():
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        info["pseudocode"] = str(cfunc) if cfunc else None
                    else:
                        info["pseudocode"] = "Decompiler not available"
                except Exception:
                    info["pseudocode"] = None
                
                # Prototype
                try:
                    info["prototype"] = get_prototype(func)
                except Exception:
                    info["prototype"] = None
                
                # Callees
                try:
                    callees = set()
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != func.start_ea:
                                    callees.add((hex_ea(tf.start_ea), ida_funcs.get_func_name(tf.start_ea)))
                    info["callees"] = "\n".join(f"{a}  {n}" for a, n in sorted(list(callees))[:50])
                except Exception:
                    info["callees"] = ""
                
                # Callers
                try:
                    callers = set()
                    for xref in idautils.XrefsTo(func.start_ea, 0):
                        if xref.iscode:
                            cf = idaapi.get_func(xref.frm)
                            if cf:
                                callers.add((hex_ea(cf.start_ea), ida_funcs.get_func_name(cf.start_ea)))
                    info["callers"] = "\n".join(f"{a}  {n}" for a, n in sorted(list(callers))[:50])
                except Exception:
                    info["callers"] = ""
                
                # Strings
                try:
                    strings = []
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if not xref.iscode:
                                s = idc.get_strlit_contents(xref.to)
                                if s:
                                    strings.append(f"{hex_ea(xref.to)}  {s.decode('utf-8', errors='replace')}")
                    info["strings"] = "\n".join(strings[:25])
                except Exception:
                    info["strings"] = ""
                
                # Stack vars
                try:
                    info["stack_vars"] = get_stack_frame_variables_internal(func.start_ea, False)
                except Exception:
                    info["stack_vars"] = []
                
                results.append(info)
            
            elif action == "callgraph":
                # BFS for call graph
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                
                visited = {func.start_ea: 0}
                queue = [(func.start_ea, 0)]
                edge_set = set()
                
                while queue and len(edge_set) < max_items:
                    curr_ea, dist = queue.pop(0)
                    if dist >= max_depth:
                        continue
                    
                    for item_ea in idautils.FuncItems(curr_ea):
                        for xref in idautils.XrefsFrom(item_ea, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != curr_ea:
                                    target_ea = tf.start_ea
                                    edge_set.add((curr_ea, target_ea))
                                    if target_ea not in visited:
                                        visited[target_ea] = dist + 1
                                        queue.append((target_ea, dist + 1))
                
                # Compact: nodes with depth, then edges
                node_lines = [f"{hex_ea(k)}  depth={v}  {ida_funcs.get_func_name(k)}" for k, v in sorted(visited.items(), key=lambda x: x[1])]
                edge_lines = [f"{hex_ea(c)} -> {hex_ea(t)}" for c, t in sorted(edge_set)]
                results.append({"ok": True, "addr": hex_ea(func.start_ea), "nodes": "\n".join(node_lines), "edges": "\n".join(edge_lines)})
            
            elif action == "export":
                # Export function info
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                
                name = ida_funcs.get_func_name(func.start_ea)
                proto = get_prototype(func)
                
                if format == "c_header":
                    results.append({"addr": addr, "header": f"{proto};"})
                elif format == "prototypes":
                    results.append({"addr": addr, "prototype": proto})
                else:
                    results.append({"addr": addr, "name": name, "prototype": proto, 
                                   "start": hex_ea(func.start_ea), "end": hex_ea(func.end_ea)})
            
            elif action == "xrefs_to_field":
                # Find xrefs to a struct field
                if not field_name:
                    results.append(make_error(MCPError.INVALID_ARGS, "field_name required"))
                    continue
                
                # Parse field_name in format "struct_name.field_name" or just "field_name"
                struct_name = None
                actual_field = field_name
                if "." in field_name:
                    struct_name, actual_field = field_name.rsplit(".", 1)
                
                xrefs_found = []
                try:
                    # Get type info library
                    til = ida_typeinf.get_idati()
                    
                    # Search through all local types for matching fields
                    qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
                    for ordinal in range(1, qty_func(til) + 1):
                        tinfo = ida_typeinf.tinfo_t()
                        if tinfo.get_numbered_type(til, ordinal):
                            type_name = tinfo.get_type_name()
                            
                            # Filter by struct name if specified
                            if struct_name and type_name != struct_name:
                                continue
                            
                            # Check if it's a struct/union
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            # Found the field, now find xrefs to addresses using this struct
                                            # member.offset is already in bytes in IDA 9
                                            xrefs_found.append({
                                                "struct": type_name,
                                                "field": actual_field,
                                                "offset": member.offset,
                                                "field_type": str(member.type)
                                            })
                    
                    if not xrefs_found:
                        results.append({"addr": addr, "field": field_name, "xrefs": [], "note": "Field not found in any struct"})
                    else:
                        results.append({"addr": addr, "field": field_name, "struct_info": xrefs_found})
                except Exception as e:
                    results.append(make_error(MCPError.IDA_ERROR, f"Error searching for field: {str(e)}", details={"addr": addr}))
                continue

            elif action == "find_paths":
                # Find path(s) from addr to target
                if not target:
                    results.append(make_error(MCPError.INVALID_ARGS, "target required"))
                    continue
                
                target_ea, error = validate_addr(target)
                if error:
                    results.append({"addr": addr, **error})
                    continue
                
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
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}"))
                    continue
                
                str_lines = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            # Check if string
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                str_lines.append(f"{hex(xref.to)}  {s.decode('utf-8', errors='replace')}")
                results.append({"ok": True, "addr": addr, "strings": "\n".join(str_lines), "count": len(str_lines)})

            elif action == "diff_functions":
                # Compare two functions' decompilation
                addr_list = normalize_list_input(addrs)
                if len(addr_list) != 2:
                    return make_error(MCPError.INVALID_ARGS, "diff_functions requires exactly 2 addresses",
                                    hint='Use addrs=["0x401000", "0x402000"]')
                ea_a, err = validate_addr(addr_list[0], require_func=True)
                if err: return err
                ea_b, err = validate_addr(addr_list[1], require_func=True)
                if err: return err

                import difflib
                try:
                    cfunc_a = ida_hexrays.decompile(ea_a)
                    cfunc_b = ida_hexrays.decompile(ea_b)
                except Exception as e:
                    return make_error(MCPError.IDA_ERROR, f"Decompilation failed: {e}")

                code_a = str(cfunc_a) if cfunc_a else ""
                code_b = str(cfunc_b) if cfunc_b else ""
                name_a = idc.get_func_name(ea_a) or hex(ea_a)
                name_b = idc.get_func_name(ea_b) or hex(ea_b)

                diff = difflib.unified_diff(
                    code_a.splitlines(), code_b.splitlines(),
                    fromfile=name_a, tofile=name_b, lineterm=""
                )
                diff_text = "\n".join(diff)

                # Compute similarity ratio
                ratio = difflib.SequenceMatcher(None, code_a, code_b).ratio()

                return {
                    "ok": True,
                    "func_a": {"addr": hex(ea_a), "name": name_a, "lines": len(code_a.splitlines())},
                    "func_b": {"addr": hex(ea_b), "name": name_b, "lines": len(code_b.splitlines())},
                    "diff": diff_text if diff_text else "(identical)",
                    "similarity": round(ratio, 4),
                }

            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
        
        return results[0] if len(results) == 1 else results
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================
