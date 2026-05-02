import time

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# Absolute imports for sub-tools to prevent IDA -S context issues
from ida_mcp.tools.code import code as code_tool
from ida_mcp.tools.ctree import ctree as ctree_tool
from ida_mcp.tools.graph import graph as graph_tool

_FUNC_SUMMARY_CACHE = {}

# ============================================================================
# 17. AGENT - High-level analysis helpers
# ============================================================================

@tool
@idaread
def agent(
    action: Annotated[Literal["analyze_function", "explore_address", "find_references", "search_all", "search_structs", "context_pack", "quick", "rename_suggestions", "batch_context", "similar", "bridge_query", "reflect"],
                      "Action: analyze_function|explore_address|find_references|search_all|search_structs|context_pack|quick|rename_suggestions|batch_context|similar|bridge_query|reflect"],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Search query or comma-separated addresses"] = None,
    depth: Annotated[int, "Exploration depth"] = 1,
    include_pseudocode: Annotated[bool, "Include decompiler pseudocode in context pack"] = False,
    max_items: Annotated[int, "Max items for context pack lists"] = 25,
    use_cache: Annotated[bool, "Use cached decompiler summaries when possible"] = True,
    **kwargs
) -> dict:
    """
    High-level agent helpers for efficient binary analysis.
    
    QUICK ACTIONS (fastest, use these first):
    
    quick - One-shot "what is this?" for any address
        Params: addr
        Returns: {type, name, pseudocode_preview?, callers?, string?, bytes?}
        Use when: You need to understand what's at an address quickly
        
    rename_suggestions - Get context to suggest better names
        Params: addr (must be a function)
        Returns: {current_name, strings_used, apis_called, callers, callees, signature}
        Use when: You want to rename a sub_XXXX function
        
    batch_context - Get context for multiple addresses at once
        Params: query (comma-separated addresses like "0x401000,0x401100,0x402000")
        Returns: {items: [{addr, type, name, size?}]}
        Use when: You have a list of addresses to understand
        
    similar - Find functions with similar structure/API usage
        Params: addr, max_items
        Returns: {similar_functions: [{addr, name, score, reasons, shared_apis}]}
        Use when: You found one function and want to find related ones
        Example: Found decrypt_string, use similar to find other crypto functions

    bridge_query - Bridge-conditioned multi-hop search (VOERA-inspired).
        Params: query (natural language query requiring intermediate bridge entity),
                addr (optional bridge address), max_items
        Returns: {bridge, expanded_queries, candidates, ranked}
        Use when: The answer requires chaining through an intermediate entity.
        Example: "Who decrypts strings referenced by the function calling InternetOpenA?"

    reflect - ReasoningBank-style reflection: analyze attempted strategies and distill insights.
        Params: query (task description), items (list of attempted strategies with outcomes)
        Returns: {insights, guardrails, distilled_strategy}
        Use when: You want to learn from successes and failures to build reusable playbooks.
    
    DETAILED ANALYSIS:
    
    context_pack - Full function context (pseudocode, xrefs, callers, callees, strings)
        Params: addr, include_pseudocode=True for full code
        Returns: {prototype, summary, callers, xrefs_to, xrefs_from, pseudocode?}
        
    analyze_function - Deep analysis (code, logic flow, CFG)
        Params: addr
        Returns: {code_analysis, logic_skeleton, control_flow_graph}
        Note: Slower, use context_pack or quick first
        
    explore_address - Basic address exploration
        Params: addr
        Returns: {type, segment, bytes, disasm, xrefs counts}
        
    find_references - Get all code and data refs to address
        Params: addr
        Returns: {code_refs, data_refs}
        
    search_all - Universal search across names, strings, functions
        Params: query
        Returns: {functions, strings, names}
        
    search_structs - Find structs by field or type name
        Params: query
        Returns: matching struct definitions
    """
    try:
        def _lines(value):
            if value is None:
                return []
            if isinstance(value, list):
                return [str(x) for x in value if str(x).strip()]
            text = str(value)
            if not text:
                return []
            return [line for line in text.splitlines() if line.strip()]

        if action == "analyze_function":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            def debug_log_agent(msg):
                try:
                    import tempfile
                    with open(os.path.join(tempfile.gettempdir(), "ida_mcp_emergency.log"), "a") as f:
                        f.write(f"[{time.ctime()}] AGENT: {msg}\n")
                except Exception:
                    return False
                return True

            # Aggregate multi-modal analysis
            debug_log_agent(f"Starting code analysis for {addr}...")
            code_res = code_tool(action="analyze", addrs=addr)
            
            debug_log_agent(f"Starting logic flow analysis for {addr}...")
            logic_res = ctree_tool(action="get_logic_flow", addr=addr)
            
            debug_log_agent(f"Starting graph analysis for {addr}...")
            graph_res = graph_tool(action="cfg", addr=addr, format="mermaid")
            
            debug_log_agent(f"Analysis complete for {addr}")
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_func_name(ea),
                "code_analysis": code_res,
                "logic_skeleton": logic_res.get("logic_flow", []),
                "control_flow_graph": graph_res.get("mermaid", "")
            }
        
        elif action == "explore_address":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = idaapi.get_func(ea)
            seg = idaapi.getseg(ea)
            
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea) or "",
                "type": "function" if func else "data",
                "segment": ida_segment.get_segm_name(seg) if seg else "none",
                "bytes": ida_bytes.get_bytes(ea, 16).hex(" ") if ida_bytes.get_bytes(ea, 16) else "",
                "disasm": ida_lines.tag_remove(idc.generate_disasm_line(ea, 0)),
                "xrefs_to_count": len(list(idautils.XrefsTo(ea, 0))),
                "xrefs_from_count": len(list(idautils.XrefsFrom(ea, 0)))
            }
        
        elif action == "find_references":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            from .search import search as search_tool
            code_refs = search_tool(action="code_ref", pattern=addr, limit=20)
            data_refs = search_tool(action="data_ref", pattern=addr, limit=20)
            code_text = code_refs.get("matches", "")
            data_text = data_refs.get("matches", "")
            return {
                "ok": True,
                "addr": hex(ea),
                "code_refs": _lines(code_text),
                "data_refs": _lines(data_text),
                "code_refs_text": code_text,
                "data_refs_text": data_text,
            }
        
        elif action == "search_all":
            if not query: return make_error(MCPError.INVALID_ARGS, "query required")
            from .data import data as data_tool
            funcs = data_tool(action="functions", query=query, count=10)
            strings = data_tool(action="strings", query=query, count=10)
            names = data_tool(action="globals", query=query, count=10)
            funcs_text = funcs.get("functions", "")
            strings_text = strings.get("strings", "")
            names_text = names.get("globals", "")
            return {
                "ok": True,
                "query": query,
                "functions": _lines(funcs_text),
                "strings": _lines(strings_text),
                "names": _lines(names_text),
                "functions_text": funcs_text,
                "strings_text": strings_text,
                "names_text": names_text,
            }

        elif action == "search_structs":
            if not query: return make_error(MCPError.INVALID_ARGS, "query required")
            from .types import types as types_tool
            return types_tool(action="search_structs", query=query)

        elif action == "context_pack":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            name = ida_funcs.get_func_name(func.start_ea)
            proto = get_prototype(func)

            cfunc = None
            pseudocode = None
            cache_key = None
            if ida_hexrays.init_hexrays_plugin():
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        pseudocode = str(cfunc)
                except Exception:
                    cfunc = None

            if pseudocode is not None:
                import hashlib
                digest = hashlib.sha256(pseudocode.encode("utf-8", errors="ignore")).hexdigest()
                cache_key = (func.start_ea, digest)

            if use_cache and cache_key in _FUNC_SUMMARY_CACHE:
                summary = _FUNC_SUMMARY_CACHE[cache_key]
            else:
                summary = {"args": [], "locals": [], "calls": [], "strings": []}
                if cfunc:
                    try:
                        args = [v for v in cfunc.lvars if v.is_arg_var]
                        summary["args"] = [{"name": v.name, "type": str(v.type())} for v in args][:max_items]
                        locals_ = [v for v in cfunc.lvars if not v.is_arg_var]
                        summary["locals"] = [{"name": v.name, "type": str(v.type())} for v in locals_][:max_items]
                    except Exception:
                        pass

                # Callees and strings
                try:
                    calls = set()
                    strings = []
                    _item_count = 0
                    for item in idautils.FuncItems(func.start_ea):
                        _item_count += 1
                        if _item_count > 5000:
                            break
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != func.start_ea:
                                    calls.add((hex(tf.start_ea), ida_funcs.get_func_name(tf.start_ea)))
                            else:
                                s = idc.get_strlit_contents(xref.to)
                                if s:
                                    strings.append({"addr": hex(xref.to), "string": s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)})
                    summary["calls"] = [{"addr": a, "name": n} for a, n in sorted(calls)[:max_items]]
                    summary["strings"] = strings[:max_items]
                except Exception:
                    pass

                if cache_key:
                    _FUNC_SUMMARY_CACHE[cache_key] = summary

            # Callers
            callers = []
            try:
                caller_set = set()
                _xref_count = 0
                for xref in idautils.XrefsTo(func.start_ea, 0):
                    _xref_count += 1
                    if _xref_count > 5000:
                        break
                    if xref.iscode:
                        cf = idaapi.get_func(xref.frm)
                        if cf:
                            caller_set.add((hex(cf.start_ea), ida_funcs.get_func_name(cf.start_ea)))
                callers = [{"addr": a, "name": n} for a, n in sorted(caller_set)[:max_items]]
            except Exception:
                pass

            # Xrefs
            xrefs_to = []
            xrefs_from = []
            try:
                for xref in idautils.XrefsTo(func.start_ea, 0):
                    if len(xrefs_to) >= max_items:
                        break
                    xrefs_to.append({"from": hex(xref.frm), "type": xref.type})
            except Exception:
                pass
            try:
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if len(xrefs_from) >= max_items:
                            break
                        xrefs_from.append({"to": hex(xref.to), "type": xref.type})
                    if len(xrefs_from) >= max_items:
                        break
            except Exception:
                pass

            pack = {
                "ok": True,
                "addr": hex(func.start_ea),
                "name": name,
                "prototype": proto,
                "summary": summary,
                "callers": callers,
                "xrefs_to": xrefs_to,
                "xrefs_from": xrefs_from,
            }
            if include_pseudocode:
                pack["pseudocode"] = pseudocode
            return pack
        
        elif action == "quick":
            # One-shot "what is this?" query for any address
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            
            result = {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea) or None,
            }
            
            func = idaapi.get_func(ea)
            seg = idaapi.getseg(ea)
            
            if func:
                result["type"] = "function"
                result["func_name"] = ida_funcs.get_func_name(func.start_ea)
                result["func_start"] = hex(func.start_ea)
                result["func_size"] = func.end_ea - func.start_ea
                
                # Quick decompile
                if ida_hexrays.init_hexrays_plugin():
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            lines = str(cfunc).split('\n')
                            # Get first 15 lines
                            result["pseudocode_preview"] = '\n'.join(lines[:15])
                            if len(lines) > 15:
                                result["pseudocode_preview"] += f"\n... ({len(lines) - 15} more lines)"
                    except Exception:
                        pass
                
                # Quick xrefs
                callers = set()
                _xref_count = 0
                for xref in idautils.XrefsTo(func.start_ea, 0):
                    _xref_count += 1
                    if _xref_count > 2000:
                        break
                    if xref.iscode:
                        cf = idaapi.get_func(xref.frm)
                        if cf:
                            callers.add(ida_funcs.get_func_name(cf.start_ea))
                result["callers"] = list(callers)[:10]
                result["caller_count"] = len(callers)
                
            elif ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
                result["type"] = "string"
                content = idc.get_strlit_contents(ea)
                if content:
                    result["string"] = (content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content))[:500]
                result["xref_count"] = len(list(idautils.XrefsTo(ea)))
                
            elif ida_bytes.is_data(ida_bytes.get_flags(ea)):
                result["type"] = "data"
                result["size"] = idc.get_item_size(ea)
                result["bytes"] = ida_bytes.get_bytes(ea, min(32, idc.get_item_size(ea))).hex() if ida_bytes.get_bytes(ea, 1) else None
                result["xref_count"] = len(list(idautils.XrefsTo(ea)))
                
            else:
                result["type"] = "unknown"
                result["bytes"] = ida_bytes.get_bytes(ea, 16).hex() if ida_bytes.get_bytes(ea, 16) else None
                result["disasm"] = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            
            if seg:
                result["segment"] = ida_segment.get_segm_name(seg)
                
            return result
        
        elif action == "rename_suggestions":
            # Get AI-friendly context for renaming
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            
            func = idaapi.get_func(ea)
            name = ida_funcs.get_func_name(func.start_ea)
            
            context = {
                "ok": True,
                "addr": hex(func.start_ea),
                "current_name": name,
                "is_auto_named": name.startswith("sub_"),
                "size": func.end_ea - func.start_ea,
                "strings_used": [],
                "apis_called": [],
                "callers": [],
                "callees": []
            }
            
            # Gather strings
            _fi_count = 0
            for item in idautils.FuncItems(func.start_ea):
                _fi_count += 1
                if _fi_count > 2000:
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if not xref.iscode:
                        s = idc.get_strlit_contents(xref.to)
                        if s:
                            context["strings_used"].append((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:100])
            context["strings_used"] = context["strings_used"][:10]
            
            # Gather API calls
            _fi_count = 0
            for item in idautils.FuncItems(func.start_ea):
                _fi_count += 1
                if _fi_count > 2000:
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in [17, 18, 19, 20, 21]:
                        callee_name = idc.get_name(xref.to)
                        if callee_name and not callee_name.startswith("sub_"):
                            context["apis_called"].append(callee_name)
            context["apis_called"] = list(set(context["apis_called"]))[:15]
            
            # Callers
            _xref_count = 0
            for xref in idautils.XrefsTo(func.start_ea, 0):
                _xref_count += 1
                if _xref_count > 2000:
                    break
                if xref.iscode:
                    cf = idaapi.get_func(xref.frm)
                    if cf:
                        caller_name = ida_funcs.get_func_name(cf.start_ea)
                        if not caller_name.startswith("sub_"):
                            context["callers"].append(caller_name)
            context["callers"] = list(set(context["callers"]))[:10]
            
            # Callees (non-API)
            seen = set()
            _fi_count = 0
            for item in idautils.FuncItems(func.start_ea):
                _fi_count += 1
                if _fi_count > 2000:
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in [17, 18, 19, 20, 21]:
                        callee = idaapi.get_func(xref.to)
                        if callee and callee.start_ea not in seen:
                            seen.add(callee.start_ea)
                            callee_name = ida_funcs.get_func_name(callee.start_ea)
                            if not callee_name.startswith("sub_") and callee_name not in context["apis_called"]:
                                context["callees"].append(callee_name)
            context["callees"] = context["callees"][:10]
            
            # Pseudocode signature if available
            if ida_hexrays.init_hexrays_plugin():
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        lines = str(cfunc).split('\n')
                        # Get signature line
                        for line in lines[:5]:
                            if '(' in line and ')' in line:
                                context["signature"] = line.strip()
                                break
                except Exception:
                    pass
            
            return context
        
        elif action == "batch_context":
            # Get context for multiple addresses at once
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required (comma-separated addresses)")
            
            addresses = [a.strip() for a in query.split(",")]
            results = []
            
            for addr_str in addresses[:20]:  # Limit to 20
                ea, err = validate_addr(addr_str)
                if err:
                    results.append({"addr": addr_str, "error": "invalid address"})
                    continue
                
                func = idaapi.get_func(ea)
                if func:
                    results.append({
                        "addr": hex(ea),
                        "type": "function",
                        "name": ida_funcs.get_func_name(func.start_ea),
                        "size": func.end_ea - func.start_ea
                    })
                else:
                    results.append({
                        "addr": hex(ea),
                        "type": "data" if ida_bytes.is_data(ida_bytes.get_flags(ea)) else "code",
                        "name": idc.get_name(ea)
                    })
            
            return {"ok": True, "items": results, "count": len(results)}
        
        elif action == "similar":
            # Find functions with similar characteristics to a target function
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            
            ea, err = validate_addr(addr)
            if err:
                return err
            
            func = idaapi.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            
            # Collect characteristics of target function
            target_name = ida_funcs.get_func_name(func.start_ea)
            target_size = func.end_ea - func.start_ea
            
            # Get APIs called by target
            target_apis = set()
            _fi_count = 0
            for item in idautils.FuncItems(func.start_ea):
                _fi_count += 1
                if _fi_count > 5000:
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in [17, 18, 19, 20, 21]:  # Call types
                        callee_name = idc.get_name(xref.to)
                        if callee_name and not callee_name.startswith("sub_"):
                            target_apis.add(callee_name)
            
            # Get strings used by target
            target_strings = set()
            _fi_count = 0
            for item in idautils.FuncItems(func.start_ea):
                _fi_count += 1
                if _fi_count > 5000:
                    break
                for xref in idautils.XrefsFrom(item, 0):
                    if not xref.iscode:
                        s = idc.get_strlit_contents(xref.to)
                        if s:
                            target_strings.add((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:50])
            
            # Get instruction count of target
            target_insn_count = 0
            for _ in idautils.FuncItems(func.start_ea):
                target_insn_count += 1
                if target_insn_count > 10000:
                    break
            
            # Score all other functions
            similar_funcs = []
            _max_candidates = max_items * 10
            for other_ea in idautils.Functions():
                if len(similar_funcs) >= _max_candidates * 2:
                    break
                if other_ea == func.start_ea:
                    continue
                
                other_func = idaapi.get_func(other_ea)
                if not other_func:
                    continue
                
                score = 0
                reasons = []
                
                # Size similarity (within 50%)
                other_size = other_func.end_ea - other_func.start_ea
                size_ratio = min(target_size, other_size) / max(target_size, other_size) if max(target_size, other_size) > 0 else 0
                if size_ratio > 0.5:
                    score += int(size_ratio * 30)
                    if size_ratio > 0.8:
                        reasons.append("similar_size")
                
                # API overlap
                other_apis = set()
                _fi_count = 0
                for item in idautils.FuncItems(other_ea):
                    _fi_count += 1
                    if _fi_count > 2000:
                        break
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in [17, 18, 19, 20, 21]:
                            callee_name = idc.get_name(xref.to)
                            if callee_name and not callee_name.startswith("sub_"):
                                other_apis.add(callee_name)
                
                if target_apis and other_apis:
                    api_overlap = len(target_apis & other_apis) / len(target_apis | other_apis)
                    if api_overlap > 0.3:
                        score += int(api_overlap * 50)
                        if api_overlap > 0.5:
                            reasons.append(f"api_overlap:{int(api_overlap*100)}%")
                
                # String overlap
                other_strings = set()
                _fi_count = 0
                for item in idautils.FuncItems(other_ea):
                    _fi_count += 1
                    if _fi_count > 2000:
                        break
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                other_strings.add((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:50])
                
                if target_strings and other_strings:
                    string_overlap = len(target_strings & other_strings) / len(target_strings | other_strings)
                    if string_overlap > 0.2:
                        score += int(string_overlap * 20)
                        if string_overlap > 0.4:
                            reasons.append(f"string_overlap:{int(string_overlap*100)}%")
                
                # Instruction count similarity
                other_insn_count = 0
                for _ in idautils.FuncItems(other_ea):
                    other_insn_count += 1
                    if other_insn_count > 10000:
                        break
                insn_ratio = min(target_insn_count, other_insn_count) / max(target_insn_count, other_insn_count) if max(target_insn_count, other_insn_count) > 0 else 0
                if insn_ratio > 0.7:
                    score += int(insn_ratio * 10)
                
                if score >= 20 and reasons:  # Minimum score threshold
                    similar_funcs.append({
                        "addr": hex(other_ea),
                        "name": ida_funcs.get_func_name(other_ea),
                        "score": score,
                        "reasons": reasons,
                        "size": other_size,
                        "shared_apis": list(target_apis & other_apis)[:5] if target_apis else []
                    })
            
            # Sort by score descending
            similar_funcs.sort(key=lambda x: x["score"], reverse=True)
            similar_funcs = similar_funcs[:max_items]
            
            return {
                "ok": True,
                "target": target_name,
                "target_addr": hex(func.start_ea),
                "target_apis": list(target_apis)[:10],
                "target_strings": list(target_strings)[:5],
                "similar_functions": similar_funcs,
                "count": len(similar_funcs)
            }

        elif action == "bridge_query":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for bridge_query")
            
            # Stage 1: Bridge Selection
            bridge_addr = None
            bridge_name = None
            if addr:
                bridge_ea, err = validate_addr(addr)
                if err:
                    return err
                bridge_addr = bridge_ea
                bridge_name = idc.get_func_name(bridge_ea) or hex(bridge_ea)
            else:
                # Try to extract a likely bridge from the query via semantic search
                from .search import search as search_tool
                find_res = search_tool(action="find", pattern=query, limit=5)
                names = find_res.get("names", "")
                for line in names.splitlines()[:3]:
                    parts = line.split()
                    if parts:
                        try:
                            candidate_ea = int(parts[0], 16)
                            if idaapi.get_func(candidate_ea):
                                bridge_addr = candidate_ea
                                bridge_name = idc.get_func_name(candidate_ea) or hex(candidate_ea)
                                break
                        except Exception:
                            continue
            
            if not bridge_addr:
                return make_error(MCPError.NOT_FOUND, "Could not identify bridge entity for query", "Try providing addr explicitly or use a more specific query.")
            
            # Stage 2: Extract entities from bridge (string refs, callees)
            bridge_strings = []
            bridge_apis = []
            bridge_func = idaapi.get_func(bridge_addr)
            if bridge_func:
                _fi_count = 0
                for item in idautils.FuncItems(bridge_func.start_ea):
                    _fi_count += 1
                    if _fi_count > 2000:
                        break
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                bridge_strings.append((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:50])
                        else:
                            callee = idc.get_func_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                bridge_apis.append(callee)
            
            # Stage 3: Dual-entity expansion
            candidate_pool = {}
            
            # Search for functions referencing bridge strings
            for s in bridge_strings[:5]:
                from .search import search as search_tool
                res = search_tool(action="string", pattern=s, limit=10)
                for line in res.get("matches", "").splitlines():
                    parts = line.split()
                    if parts:
                        try:
                            candidate_ea = int(parts[0], 16)
                            func = idaapi.get_func(candidate_ea)
                            if func and func.start_ea != bridge_addr:
                                candidate_pool.setdefault(func.start_ea, {"score": 0, "reasons": set()})
                                candidate_pool[func.start_ea]["score"] += 10
                                candidate_pool[func.start_ea]["reasons"].add(f"string_ref:{s[:20]}")
                        except Exception:
                            continue
            
            # Search for callers of bridge APIs
            for api in bridge_apis[:5]:
                from .search import search as search_tool
                res = search_tool(action="api", pattern=api, limit=10)
                for line in res.get("matches", "").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            call_ea = int(parts[0], 16)
                            func = idaapi.get_func(call_ea)
                            if func and func.start_ea != bridge_addr:
                                candidate_pool.setdefault(func.start_ea, {"score": 0, "reasons": set()})
                                candidate_pool[func.start_ea]["score"] += 15
                                candidate_pool[func.start_ea]["reasons"].add(f"api_call:{api}")
                        except Exception:
                            continue
            
            # Stage 4: Rank candidates
            ranked = []
            for candidate_ea, data in candidate_pool.items():
                fname = idc.get_func_name(candidate_ea) or f"sub_{candidate_ea:x}"
                # Bonus for crypto/string manipulation patterns
                _fi_count = 0
                for item in idautils.FuncItems(candidate_ea):
                    _fi_count += 1
                    if _fi_count > 1000:
                        break
                    mnem = idc.print_insn_mnem(item)
                    if mnem and mnem.lower() in ("xor", "rol", "ror", "shl", "shr"):
                        data["score"] += 3
                        data["reasons"].add("crypto_pattern")
                        break
                ranked.append({
                    "addr": hex(candidate_ea),
                    "name": fname,
                    "score": data["score"],
                    "reasons": sorted(data["reasons"]),
                })
            
            ranked.sort(key=lambda x: -x["score"])
            ranked = ranked[:max_items]
            
            return {
                "ok": True,
                "query": query,
                "bridge": {
                    "addr": hex(bridge_addr),
                    "name": bridge_name,
                    "strings": bridge_strings[:5],
                    "apis": bridge_apis[:5],
                },
                "expanded_queries": [f"functions referencing strings from {bridge_name}", f"callers of APIs used by {bridge_name}"],
                "candidates": ranked,
                "count": len(ranked),
                "note": "Bridge-conditioned multi-hop search: finds entities connected to the bridge through shared strings or API usage.",
            }

        elif action == "reflect":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for reflect (task description)")
            strategies = kwargs.get("items", [])
            if not isinstance(strategies, list):
                return make_error(MCPError.INVALID_ARGS, "items must be a list of {strategy, outcome, notes} dicts")

            successes = []
            failures = []
            for s in strategies:
                if not isinstance(s, dict):
                    continue
                outcome = str(s.get("outcome", "")).lower()
                if outcome in ("success", "true", "yes", "1", "found"):
                    successes.append(s)
                else:
                    failures.append(s)

            insights = []
            guardrails = []

            # Analyze success patterns
            if successes:
                success_tools = {}
                for s in successes:
                    tool = s.get("tool", "unknown")
                    success_tools[tool] = success_tools.get(tool, 0) + 1
                top_tool = max(success_tools, key=success_tools.get) if success_tools else "unknown"
                insights.append(f"Most successful tool: {top_tool} ({success_tools.get(top_tool, 0)} successes)")

            # Analyze failure patterns
            if failures:
                failure_reasons = {}
                for f in failures:
                    reason = f.get("notes", f.get("reason", "unknown"))
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
                for reason, count in sorted(failure_reasons.items(), key=lambda x: -x[1])[:3]:
                    insights.append(f"Common failure: {reason} ({count} times)")
                    guardrails.append(f"Avoid: {reason}")

            # Distill a generalized strategy
            distilled = {
                "task": query,
                "recommended_first_step": successes[0].get("strategy", "search for entry points") if successes else "start with broad search",
                "fallback_steps": [f.get("strategy", "") for f in failures[:2]],
                "success_indicators": [s.get("notes", "") for s in successes[:3]],
                "failure_indicators": [f.get("notes", "") for f in failures[:3]],
            }

            return {
                "ok": True,
                "query": query,
                "total_attempts": len(strategies),
                "successes": len(successes),
                "failures": len(failures),
                "insights": insights,
                "guardrails": guardrails,
                "distilled_strategy": distilled,
                "note": "Store distilled_strategy as a crystallized skill using session(action='crystallize_skill') for future reuse.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================
