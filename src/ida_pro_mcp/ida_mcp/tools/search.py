
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal["bytes", "string", "immediate", "name", "insns", "text", "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig", "find", "callers", "callees", "api", "vulnerable", "constants", "decompiled"],
                      "Action: bytes|string|immediate|name|insns|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern (for compatibility)"] = None,
    limit: Annotated[int, "Max results"] = 100,
    offset: Annotated[int, "Results offset (skip first N matches)"] = 0,
    start: Annotated[Optional[str], "Start address for bounded searches"] = None,
    end: Annotated[Optional[str], "End address for bounded searches"] = None,
    case_sensitive: Annotated[bool, "Case sensitive search (for string/text/comment)"] = False,
    include_context: Annotated[bool, "Include surrounding context in results"] = False,
    **kwargs
) -> dict:
    """
    Search for patterns, specific bytes, or references in the binary.
    All results use compact text format (one match per line) to minimize LLM context usage.
    
    QUICK ACTIONS (LLM-friendly):
    
    find - Smart unified search (auto-detects what you want)
        Params: pattern (any text, address, or name)
        Returns: {names, strings, imports, code_refs?, data_refs?} as compact text
        Example: search(action="find", pattern="malloc") - finds all malloc-related items
        
    callers - Find all functions that call a target function
        Params: pattern (function name or address)
        Returns: {callers: "addr  name  call@site\\n...", count}
        Example: search(action="callers", pattern="malloc")
        
    callees - Find all functions called by a target function
        Params: pattern (function name or address)
        Returns: {callees: "addr  name  call@site\\n...", count}
        Example: search(action="callees", pattern="main")
        
    api - Find all uses of an API/import function
        Params: pattern (API name, supports wildcards)
        Returns: {usages: "call_addr  func_name\\n...", total_calls}
        Example: search(action="api", pattern="*alloc*")
    
    vulnerable - Find potentially vulnerable code patterns
        Params: limit, include_context
        Returns: {findings: "addr  vuln_type  dangerous_func  in:caller\\n...", total_findings}
        Example: search(action="vulnerable") - finds strcpy, printf format strings, etc.
        
    constants - Find crypto/magic constants in code
        Params: limit, include_context, start, end
        Returns: {findings: "addr  value  const_name  in:func\\n...", total_found}
        Example: search(action="constants") - finds MD5/SHA/AES constants, magic numbers
    
    DETAILED ACTIONS (all return {matches: "line\\nline\\n...", count, total, truncated}):
    
    bytes - Search for byte patterns with wildcards
        Params: pattern (e.g. "55 8B EC" or "E8 ?? ?? ?? ??"), start, end
        
    string - Search string literals by content
        Params: pattern (substring), case_sensitive
        
    immediate - Search for immediate value usage in code
        Params: pattern/query (value as hex or decimal)
        
    name - Search symbol names by glob pattern
        Params: pattern (e.g. "*printf*", "sub_*")
        
    insns - Search for instruction mnemonic sequences
        Params: pattern (comma-separated, e.g. "push, mov, sub"), wildcards supported (*)
        
    text - Search disassembly text
        Params: pattern (substring), case_sensitive, include_context
        
    operand - Search operands for patterns
        Params: pattern (e.g. "rsp", "qword ptr")
        
    comment - Search comments
        Params: pattern
        
    data_ref - Find data references to target
        Params: pattern (address or name)
        
    code_ref - Find code references to target
        Params: pattern (address or name)
        
    regex - Search with regular expression in disassembly
        Params: pattern (regex)
        
    func_by_sig - Find functions by signature characteristics
        Params: pattern (e.g. "args:3+", "calls:malloc", "size:>100")

    decompiled - Search through decompiled pseudocode (Hex-Rays)
        Params: pattern (regex), case_sensitive, limit
        Returns: {matches: "addr  func_name  L42: matching line\\n...", count}
        Example: search(action="decompiled", pattern="memcpy.*sizeof")
    """
    try:
        # Support both pattern and query for compatibility
        if not pattern and query:
            pattern = query
        
        # Some actions don't need pattern parameter
        pattern_not_required = ["vulnerable", "constants"]
        if not pattern and action not in pattern_not_required:
            return make_error(MCPError.INVALID_ARGS, "pattern or query parameter required")
            
        import ida_search
        import fnmatch
        import re as re_module

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
            
        def _search_result(**extra):
            """Common return format for search results."""
            return {"ok": True, "matches": "\n".join(results), "offset": offset, "count": len(results), "total": matches_seen, "truncated": truncated, **extra}

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
                        
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    pt = ida_bytes.compiled_binpat_vec_t()
                    err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
                    if err:
                        return make_error(MCPError.INVALID_ARGS, f"Invalid pattern: {err}")

                    ea, _ = ida_bytes.bin_search(seg_start, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
                    while ea != idaapi.BADADDR:
                        line = hex(ea)
                        if include_context:
                            match_bytes = ida_bytes.get_bytes(ea, min(32, seg_end - ea))
                            if match_bytes:
                                line += f"  {match_bytes.hex()}"
                            line += f"  {idc.generate_disasm_line(ea, 0)}"
                        if maybe_add(line):
                            break
                        ea, _ = ida_bytes.bin_search(ea + 1, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
                else:
                    pass
                        
                if range_end is not None and seg.end_ea >= range_end:
                    break
                seg = idaapi.get_next_seg(seg.end_ea)
            return _search_result(pattern=pattern)
        
        elif action == "string":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            for i in range(idaapi.get_strlist_qty()):
                if truncated:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if _matcher(s):
                                line = f"{hex(sc.ea)}  {s[:500]}"
                                if include_context:
                                    xref_count = len(list(idautils.XrefsTo(sc.ea)))
                                    line += f"  xrefs={xref_count}"
                                if maybe_add(line):
                                    break
                    except Exception:
                        pass
            return _search_result(pattern=pattern)
        
        elif action == "immediate":
            try: 
                value = int(pattern, 0)
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "Invalid immediate value")

            import ida_ua
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                curr = seg_ea
                seg_end = range_end if range_end is not None else idc.get_segm_end(seg_ea)
                while curr < seg_end:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, curr) > 0:
                        for op in insn.ops:
                            if op.type == ida_ua.o_imm and op.value == value:
                                line = f"{hex(curr)}  {hex(value)}"
                                if include_context:
                                    line += f"  {idc.generate_disasm_line(curr, 0)}"
                                    func = idaapi.get_func(curr)
                                    if func:
                                        line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                                if maybe_add(line):
                                    break
                                break
                        curr += insn.size
                    else:
                        curr = idc.next_head(curr, seg_end)
                    if truncated:
                        break
                if truncated:
                    break
            return _search_result(value=hex(value))
        
        elif action == "name":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            for ea, name in idautils.Names():
                if truncated:
                    break
                if _matcher(name):
                    kind = "func" if idaapi.get_func(ea) else ("data" if ida_bytes.is_data(ida_bytes.get_flags(ea)) else "label")
                    if maybe_add(f"{hex(ea)}  {kind}  {name}"):
                        break
            return _search_result(pattern=pattern)
        
        elif action == "insns":
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
                    flags_val = ida_bytes.get_flags(ea)
                    if ida_bytes.is_code(flags_val):
                        match = True
                        check_ea = ea
                        sequence = []
                        for mnem in mnemonics:
                            curr_mnem = idc.print_insn_mnem(check_ea).lower()
                            if mnem != "*" and curr_mnem != mnem:
                                match = False
                                break
                            sequence.append(curr_mnem)
                            check_ea = idc.next_head(check_ea, seg_end)
                            if check_ea == idaapi.BADADDR:
                                match = False
                                break
                        if match:
                            line = hex(ea)
                            if include_context:
                                line += f"  [{','.join(sequence)}]"
                                func = idaapi.get_func(ea)
                                if func:
                                    line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "text":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
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
                    if line:
                        line_clean = ida_lines.tag_remove(line)
                        if _matcher(line_clean):
                            result_line = f"{hex(ea)}  {line_clean}"
                            if include_context:
                                func = idaapi.get_func(ea)
                                if func:
                                    result_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(result_line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "operand":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
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
                    if op_text and _matcher(op_text):
                        line = f"{hex(ea)}  {idc.print_insn_mnem(ea)}  {op_text}"
                        if include_context:
                            line += f"  {idc.generate_disasm_line(ea, 0)}"
                        if maybe_add(line):
                            break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "comment":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
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
                    cmt_type = "regular"
                    if not cmt:
                        cmt = idc.get_cmt(ea, 1)
                        cmt_type = "repeatable"
                    if cmt:
                        if _matcher(cmt):
                            if maybe_add(f"{hex(ea)}  {cmt_type}  {cmt}"):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "data_ref":
            target_ea, error = validate_addr(pattern)
            if error:
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"Target '{pattern}' not found")

            for xref in idautils.XrefsTo(target_ea, 0):
                if truncated:
                    break
                if not xref.iscode:
                    line = f"{hex(xref.frm)} -> {hex(xref.to)}  data"
                    if include_context:
                        from_name = idc.get_name(xref.frm)
                        if from_name:
                            line += f"  {from_name}"
                    if maybe_add(line):
                        break
            return _search_result(target=pattern)
        
        elif action == "code_ref":
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
                    fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                    line = f"{hex(xref.frm)} -> {hex(xref.to)}  code  {fn_name}"
                    if include_context:
                        line += f"  {idc.generate_disasm_line(xref.frm, 0)}"
                    if maybe_add(line):
                        break
            return _search_result(target=pattern)
        
        elif action == "regex":
            try:
                regex = re_module.compile(pattern, 0 if case_sensitive else re_module.IGNORECASE)
            except re_module.error as e:
                return make_error(MCPError.INVALID_ARGS, f"Invalid regex: {e}")
                
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
                ea = seg_start
                while ea < seg_end and not truncated:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        line_clean = ida_lines.tag_remove(line)
                        match = regex.search(line_clean)
                        if match:
                            result_line = f"{hex(ea)}  {line_clean}"
                            if include_context:
                                func = idaapi.get_func(ea)
                                if func:
                                    result_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(result_line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)
            
        elif action == "func_by_sig":
            # Parse signature criteria
            criteria = pattern.lower()
            
            for ea in idautils.Functions():
                if truncated:
                    break
                    
                func = idaapi.get_func(ea)
                if not func:
                    continue
                    
                name = ida_funcs.get_func_name(ea)
                size = func.end_ea - func.start_ea
                matched = False
                reason = []
                
                # Size filter: size:>100, size:<50, size:100-500
                if "size:" in criteria:
                    import re as r
                    m = r.search(r'size:([<>]?)(\d+)(?:-(\d+))?', criteria)
                    if m:
                        op, val1, val2 = m.groups()
                        val1 = int(val1)
                        if op == '>':
                            if size > val1:
                                matched = True
                                reason.append(f"size={size}>{val1}")
                        elif op == '<':
                            if size < val1:
                                matched = True
                                reason.append(f"size={size}<{val1}")
                        elif val2:
                            val2 = int(val2)
                            if val1 <= size <= val2:
                                matched = True
                                reason.append(f"size={size} in [{val1},{val2}]")
                        else:
                            if size == val1:
                                matched = True
                                reason.append(f"size={size}")
                
                # Calls filter: calls:malloc, calls:*alloc*
                if "calls:" in criteria:
                    import re as r
                    m = r.search(r'calls:(\S+)', criteria)
                    if m:
                        call_pat = m.group(1)
                        # Check callees
                        for xref in idautils.XrefsFrom(ea):
                            if xref.type in [17, 18, 19, 20, 21]:  # Call types
                                callee_name = idc.get_name(xref.to) or ""
                                if fnmatch.fnmatch(callee_name.lower(), call_pat):
                                    matched = True
                                    reason.append(f"calls:{callee_name}")
                                    break
                
                # Args filter: args:3+, args:0
                if "args:" in criteria:
                    import re as r
                    m = r.search(r'args:(\d+)(\+)?', criteria)
                    if m:
                        arg_count, plus = m.groups()
                        arg_count = int(arg_count)
                        # Try to get prototype
                        tif = ida_typeinf.tinfo_t()
                        if ida_nalt.get_tinfo(tif, ea):
                            func_data = ida_typeinf.func_type_data_t()
                            if tif.get_func_details(func_data):
                                actual_args = func_data.size()
                                if plus and actual_args >= arg_count:
                                    matched = True
                                    reason.append(f"args={actual_args}>={arg_count}")
                                elif not plus and actual_args == arg_count:
                                    matched = True
                                    reason.append(f"args={actual_args}")
                
                if matched:
                    if maybe_add(f"{hex(ea)}  {name}  size={size}  {', '.join(reason)}"):
                        break
                        
            return _search_result(pattern=pattern)
        
        elif action == "find":
            # Smart unified search - auto-detects what user wants
            _find_matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            
            results_by_type = {}
            
            # 1. If looks like hex/address, search xrefs
            if pattern.startswith("0x") or (len(pattern) >= 6 and all(c in "0123456789abcdefABCDEF" for c in pattern)):
                try:
                    ea = int(pattern, 16)
                    code_lines = []
                    data_lines = []
                    for xref in idautils.XrefsTo(ea, 0):
                        if len(code_lines) + len(data_lines) >= limit:
                            break
                        func = idaapi.get_func(xref.frm)
                        fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                        if xref.iscode:
                            code_lines.append(f"{hex(xref.frm)}  {fn_name}")
                        else:
                            data_lines.append(f"{hex(xref.frm)}  {fn_name}")
                    if code_lines:
                        results_by_type["code_refs"] = "\n".join(code_lines)
                    if data_lines:
                        results_by_type["data_refs"] = "\n".join(data_lines)
                except Exception:
                    pass
            
            # 2. Search names (functions, globals)
            name_lines = []
            for ea, name in idautils.Names():
                if len(name_lines) >= limit:
                    break
                if _find_matcher(name):
                    kind = "func" if idaapi.get_func(ea) else "data"
                    name_lines.append(f"{hex(ea)}  {kind}  {name}")
            results_by_type["names"] = "\n".join(name_lines)
            
            # 3. Search strings
            string_lines = []
            for i in range(idaapi.get_strlist_qty()):
                if len(string_lines) >= limit:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if _find_matcher(s):
                                xref_count = len(list(idautils.XrefsTo(sc.ea)))
                                string_lines.append(f"{hex(sc.ea)}  xrefs={xref_count}  {s[:200]}")
                    except Exception:
                        pass
            results_by_type["strings"] = "\n".join(string_lines)
            
            # 4. Search imports
            import_lines = []
            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i)
                def cb(ea, name, ordinal):
                    if len(import_lines) >= limit:
                        return False
                    if name and _find_matcher(name):
                        xref_count = len(list(idautils.XrefsTo(ea)))
                        import_lines.append(f"{hex(ea)}  {mod_name}  {name}  xrefs={xref_count}")
                    return True
                ida_nalt.enum_import_names(i, cb)
            results_by_type["imports"] = "\n".join(import_lines)
            
            return {
                "ok": True,
                "query": pattern,
                **results_by_type
            }
        
        elif action == "callers":
            # Find all functions that call the target
            target_ea, error = validate_addr(pattern)
            if error:
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"Target '{pattern}' not found")
            
            func = idaapi.get_func(target_ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")
            
            caller_lines = []
            seen = set()
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if len(caller_lines) >= limit:
                    truncated = True
                    break
                if xref.iscode:
                    caller_func = idaapi.get_func(xref.frm)
                    if caller_func and caller_func.start_ea not in seen:
                        seen.add(caller_func.start_ea)
                        line = f"{hex(caller_func.start_ea)}  {ida_funcs.get_func_name(caller_func.start_ea)}  call@{hex(xref.frm)}"
                        if include_context:
                            line += f"  {idc.generate_disasm_line(xref.frm, 0)}"
                        caller_lines.append(line)
            
            return {
                "ok": True,
                "target": idc.get_name(target_ea) or hex(target_ea),
                "target_addr": hex(func.start_ea),
                "callers": "\n".join(caller_lines),
                "count": len(caller_lines),
                "truncated": len(caller_lines) >= limit
            }
        
        elif action == "callees":
            # Find all functions called by the target
            target_ea, error = validate_addr(pattern)
            if error:
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"Target '{pattern}' not found")
            
            func = idaapi.get_func(target_ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")
            
            callee_lines = []
            seen = set()
            for item in idautils.FuncItems(func.start_ea):
                if len(callee_lines) >= limit:
                    truncated = True
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in [17, 18, 19, 20, 21]:  # Call types
                        callee_func = idaapi.get_func(xref.to)
                        if callee_func and callee_func.start_ea not in seen:
                            seen.add(callee_func.start_ea)
                            name = ida_funcs.get_func_name(callee_func.start_ea)
                            callee_lines.append(f"{hex(callee_func.start_ea)}  {name}  call@{hex(item)}")
            
            callee_lines.sort()
            
            return {
                "ok": True,
                "target": idc.get_name(target_ea) or hex(target_ea),
                "target_addr": hex(func.start_ea),
                "callees": "\n".join(callee_lines),
                "count": len(callee_lines),
                "truncated": len(callee_lines) >= limit
            }
        
        elif action == "api":
            # Find all uses of an API/import function
            import fnmatch
            
            # Find the import
            target_ea = None
            target_name = None
            pattern_lower = pattern.lower()
            
            for i in range(ida_nalt.get_import_module_qty()):
                if target_ea:
                    break
                def cb(ea, name, ordinal):
                    nonlocal target_ea, target_name
                    if name and (pattern_lower == name.lower() or fnmatch.fnmatch(name.lower(), pattern_lower)):
                        target_ea = ea
                        target_name = name
                        return False  # Stop enumeration
                    return True
                ida_nalt.enum_import_names(i, cb)
            
            if not target_ea:
                # Try as a name
                target_ea = idc.get_name_ea_simple(pattern)
                if target_ea != idaapi.BADADDR:
                    target_name = pattern
            
            if not target_ea or target_ea == idaapi.BADADDR:
                return make_error(MCPError.NOT_FOUND, f"API '{pattern}' not found")
            
            # Find all call sites
            usage_lines = []
            for xref in idautils.XrefsTo(target_ea, 0):
                if len(usage_lines) >= limit:
                    truncated = True
                    break
                if xref.iscode:
                    func = idaapi.get_func(xref.frm)
                    fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                    line = f"{hex(xref.frm)}  {fn_name}"
                    if include_context:
                        line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(xref.frm, 0))}"
                    usage_lines.append(line)
            
            return {
                "ok": True,
                "api": target_name,
                "api_addr": hex(target_ea),
                "total_calls": len(usage_lines),
                "usages": "\n".join(usage_lines),
                "truncated": len(usage_lines) >= limit
            }
        
        elif action == "vulnerable":
            # Find potentially vulnerable patterns
            DANGEROUS_FUNCS = {
                # Format string vulnerabilities
                "printf": "format_string",
                "sprintf": "format_string", 
                "fprintf": "format_string",
                "snprintf": "format_string",
                "vprintf": "format_string",
                "vsprintf": "format_string",
                "vsnprintf": "format_string",
                "syslog": "format_string",
                # Buffer overflow risks
                "strcpy": "buffer_overflow",
                "strcat": "buffer_overflow",
                "gets": "buffer_overflow",
                "scanf": "buffer_overflow",
                "sscanf": "buffer_overflow",
                "fscanf": "buffer_overflow",
                "vscanf": "buffer_overflow",
                "strncpy": "potential_overflow",  # Still risky if not null-terminated
                "strncat": "potential_overflow",
                "memcpy": "buffer_overflow",
                "memmove": "buffer_overflow",
                # Integer overflow
                "atoi": "integer_overflow",
                "atol": "integer_overflow", 
                "atoll": "integer_overflow",
                # Command injection
                "system": "command_injection",
                "popen": "command_injection",
                "execl": "command_injection",
                "execle": "command_injection",
                "execlp": "command_injection",
                "execv": "command_injection",
                "execve": "command_injection",
                "execvp": "command_injection",
                "ShellExecute": "command_injection",
                "ShellExecuteA": "command_injection",
                "ShellExecuteW": "command_injection",
                "WinExec": "command_injection",
                "CreateProcess": "command_injection",
                "CreateProcessA": "command_injection",
                "CreateProcessW": "command_injection",
                # Memory issues
                "malloc": "memory_alloc",
                "calloc": "memory_alloc",
                "realloc": "memory_alloc",
                "free": "use_after_free",
                "HeapAlloc": "memory_alloc",
                "HeapFree": "use_after_free",
                "VirtualAlloc": "memory_alloc",
                "VirtualFree": "use_after_free",
                # File operations (path traversal)
                "fopen": "path_traversal",
                "open": "path_traversal",
                "CreateFile": "path_traversal",
                "CreateFileA": "path_traversal",
                "CreateFileW": "path_traversal",
                # Crypto weaknesses
                "rand": "weak_random",
                "srand": "weak_random",
                "random": "weak_random",
                "MD5": "weak_crypto",
                "SHA1": "weak_crypto",
                "DES": "weak_crypto",
                "RC4": "weak_crypto",
            }
            
            findings = []
            truncated = False
            
            # Search for dangerous function calls
            for i in range(ida_nalt.get_import_module_qty()):
                def cb(ea, name, ordinal):
                    if len(findings) >= limit:
                        return False
                    if not name:
                        return True
                    
                    # Check if this is a dangerous function
                    vuln_type = None
                    for dangerous, vtype in DANGEROUS_FUNCS.items():
                        if dangerous.lower() in name.lower():
                            vuln_type = vtype
                            break
                    
                    if vuln_type:
                        # Find all callers of this dangerous function
                        for xref in idautils.XrefsTo(ea, 0):
                            if len(findings) >= limit:
                                return False
                            if xref.iscode:
                                func = idaapi.get_func(xref.frm)
                                fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                                line = f"{hex(xref.frm)}  {vuln_type}  {name}  in:{fn_name}"
                                if include_context:
                                    line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(xref.frm, 0))}"
                                findings.append(line)
                    return True
                ida_nalt.enum_import_names(i, cb)
            
            return {
                "ok": True,
                "total_findings": len(findings),
                "findings": "\n".join(findings),
                "truncated": len(findings) >= limit
            }
        
        elif action == "constants":
            # Find crypto/magic constants
            import ida_ua
            
            KNOWN_CONSTANTS = {
                # MD5 initialization constants
                0x67452301: "MD5_A",
                0xEFCDAB89: "MD5_B",
                0x98BADCFE: "MD5_C",
                0x10325476: "MD5_D",
                # SHA-1 initialization constants (overlap with MD5)
                0xC3D2E1F0: "SHA1_H4",
                # SHA-256 initialization constants
                0x6A09E667: "SHA256_H0",
                0xBB67AE85: "SHA256_H1",
                0x3C6EF372: "SHA256_H2",
                0xA54FF53A: "SHA256_H3",
                0x510E527F: "SHA256_H4",
                0x9B05688C: "SHA256_H5",
                0x1F83D9AB: "SHA256_H6",
                0x5BE0CD19: "SHA256_H7",
                # AES S-box first/last values
                0x63: "AES_SBOX_0",
                0x7C: "AES_SBOX_1",
                0x16: "AES_SBOX_LAST",
                # AES round constants
                0x01000000: "AES_RCON_1",
                0x02000000: "AES_RCON_2",
                # RC4 
                0x100: "RC4_STATE_SIZE",
                # RSA common exponent
                0x10001: "RSA_E_65537",
                0x3: "RSA_E_3",
                # CRC32 polynomial
                0xEDB88320: "CRC32_POLY",
                0x04C11DB7: "CRC32_POLY_REV",
                # Blowfish P-array
                0x243F6A88: "BLOWFISH_P0",
                0x85A308D3: "BLOWFISH_P1",
                # TEA/XTEA
                0x9E3779B9: "TEA_DELTA",
                # Salsa20/ChaCha
                0x61707865: "SALSA_CONST_0",
                0x3320646E: "SALSA_CONST_1", 
                0x79622D32: "SALSA_CONST_2",
                0x6B206574: "SALSA_CONST_3",
                # Common magic numbers
                0xDEADBEEF: "MAGIC_DEADBEEF",
                0xCAFEBABE: "MAGIC_CAFEBABE",
                0xFEEDFACE: "MAGIC_FEEDFACE",
                0xC0FFEE: "MAGIC_COFFEE",
                0xBADC0DE: "MAGIC_BADCODE",
                # Windows PE
                0x5A4D: "MZ_HEADER",
                0x00004550: "PE_SIGNATURE",
                # ELF
                0x464C457F: "ELF_MAGIC",
                # ZIP
                0x04034B50: "ZIP_LOCAL_HEADER",
                0x02014B50: "ZIP_CENTRAL_HEADER",
            }
            
            found_lines = []
            truncated = False
            
            # Search for immediates matching known constants
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            
            for const_val, const_name in KNOWN_CONSTANTS.items():
                if len(found_lines) >= limit:
                    truncated = True
                    break
                
                # Search each segment for this constant
                for seg_ea in segments:
                    if len(found_lines) >= limit:
                        truncated = True
                        break
                    
                    curr = range_start if range_start and range_start >= seg_ea else seg_ea
                    seg_end = range_end if range_end else idc.get_segm_end(seg_ea)
                    
                    search_count = 0
                    while curr < seg_end and search_count < 10:  # Max 10 per constant per segment
                        insn = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn, curr) > 0:
                            for op in insn.ops:
                                if op.type == ida_ua.o_imm and op.value == const_val:
                                    func = idaapi.get_func(curr)
                                    fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                                    line = f"{hex(curr)}  {hex(const_val)}  {const_name}  in:{fn_name}"
                                    if include_context:
                                        line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))}"
                                    found_lines.append(line)
                                    search_count += 1
                                    
                                    if len(found_lines) >= limit:
                                        truncated = True
                                        break
                                    break
                            curr += insn.size
                        else:
                            curr = idc.next_head(curr, seg_end)
                        
                        if truncated:
                            break
            
            return {
                "ok": True,
                "total_found": len(found_lines),
                "findings": "\n".join(found_lines),
                "truncated": truncated
            }

        elif action == "decompiled":
            # Search through decompiled pseudocode of all functions
            if not pat:
                return make_error(MCPError.INVALID_ARGS, "pattern required for decompiled search")
            import re
            try:
                search_re = re.compile(pat, 0 if case_sensitive else re.IGNORECASE)
            except re.error as e:
                return make_error(MCPError.INVALID_ARGS, f"Invalid regex: {e}")

            matches = []
            skipped = 0
            for func_ea in idautils.Functions():
                if len(matches) >= limit + offset:
                    break
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    pseudocode = str(cfunc)
                    for line_num, line in enumerate(pseudocode.splitlines(), 1):
                        if search_re.search(line):
                            if skipped < offset:
                                skipped += 1
                                continue
                            if len(matches) >= limit:
                                break
                            func_name = idc.get_func_name(func_ea) or hex(func_ea)
                            matches.append(f"{hex(func_ea)}  {func_name}  L{line_num}: {line.strip()}")
                except Exception:
                    continue

            return {
                "ok": True,
                "action": "decompiled",
                "pattern": pat,
                "matches": "\n".join(matches),
                "count": len(matches),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================
