import hashlib
import json
import os
import time

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# Absolute imports for sub-tools to prevent IDA -S context issues
from ida_mcp.tools.code import code as code_tool
from ida_mcp.tools.ctree import ctree as ctree_tool
from ida_mcp.tools.graph import graph as graph_tool

_FUNC_SUMMARY_CACHE: dict = {}
_FUNC_SUMMARY_CACHE_MAX = 512  # prevent unbounded growth

# ============================================================================
# 17. AGENT - High-level analysis helpers
# ============================================================================

@tool
@idaread
def agent(
    action: Annotated[Literal["analyze_function", "explore_address", "find_references", "search_all", "search_structs", "context_pack", "quick", "rename_suggestions", "batch_context", "similar", "bridge_query", "reflect", "cluster", "fingerprint", "intelligence_status", "embedder_status", "anchor_status", "refresh_anchors", "classify_text", "classify_function", "index_function", "index_batch", "similar_functions", "export_index_summary", "evidence_card"],
                      "Action: analyze_function|explore_address|find_references|search_all|search_structs|context_pack|quick|rename_suggestions|batch_context|similar|bridge_query|reflect|cluster|fingerprint|intelligence_status|embedder_status|anchor_status|refresh_anchors|classify_text|classify_function|index_function|index_batch|similar_functions|export_index_summary|evidence_card"],
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

            # Aggregate multi-modal analysis
            code_res = code_tool(action="analyze", addrs=addr)
            logic_res = ctree_tool(action="get_logic_flow", addr=addr)
            graph_res = graph_tool(action="cfg", addr=addr, format="mermaid")
            ctx_res = agent(action="context_pack", addr=addr, include_pseudocode=False, max_items=max_items, use_cache=use_cache)
            callee_chain = []
            try:
                seen = set()
                q = [(ea, 0)]
                while q:
                    cur, d = q.pop(0)
                    if d >= 2:
                        continue
                    fn = idaapi.get_func(cur)
                    if not fn:
                        continue
                    for item in idautils.FuncItems(fn.start_ea):
                        for xr in idautils.XrefsFrom(item, 0):
                            if not xr.iscode:
                                continue
                            tf = idaapi.get_func(xr.to)
                            if not tf:
                                continue
                            k = (int(cur), int(tf.start_ea))
                            if k in seen:
                                continue
                            seen.add(k)
                            callee_chain.append({
                                "from": hex(cur),
                                "to": hex(tf.start_ea),
                                "from_name": ida_funcs.get_func_name(cur),
                                "to_name": ida_funcs.get_func_name(tf.start_ea),
                                "depth": d + 1,
                            })
                            q.append((tf.start_ea, d + 1))
                        if len(callee_chain) >= 256:
                            break
                    if len(callee_chain) >= 256:
                        break
            except Exception:
                pass
            behavior_tags = []
            rename_suggestion = ""
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                pseudo = ""
                if isinstance(ctx_res, dict):
                    pseudo = str(ctx_res.get("pseudocode") or "")
                if pseudo:
                    bc = BehaviorClassifier.instance(BgeCodeEmbedder())
                    behavior_tags = bc.classify(pseudo, threshold=0.25, top_k=4, block=False)
                    if behavior_tags:
                        top = behavior_tags[0].get("behavior", "analyzed")
                        rename_suggestion = f"{top}_{ea:x}"
            except Exception:
                pass
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_func_name(ea),
                "code_analysis": code_res,
                "logic_skeleton": logic_res.get("logic_flow", []),
                "control_flow_graph": graph_res.get("mermaid", ""),
                "call_graph_depth2": callee_chain[:max_items * 6],
                "strings": (ctx_res.get("summary", {}) or {}).get("strings", []) if isinstance(ctx_res, dict) else [],
                "behavior_tags": behavior_tags,
                "rename_suggestion": rename_suggestion,
            }
        
        elif action == "explore_address":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = idaapi.get_func(ea)
            seg = idaapi.getseg(ea)
            
            item_sz = int(idc.get_item_size(ea) or 0)
            flags = ida_bytes.get_flags(ea)
            kind = "unknown"
            if func:
                kind = "function"
            elif ida_bytes.is_strlit(flags):
                kind = "string"
            elif ida_bytes.is_code(flags):
                kind = "code"
            elif ida_bytes.is_data(flags):
                kind = "data"
            # Heuristic table typing
            if kind in ("data", "unknown") and item_sz >= 8:
                try:
                    ptr = ida_bytes.get_qword(ea)
                    if idaapi.get_func(ptr):
                        kind = "vtable_or_jump_table"
                except Exception:
                    pass
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea) or "",
                "type": kind,
                "segment": ida_segment.get_segm_name(seg) if seg else "none",
                "item_size": item_sz,
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
            code_refs = search_tool(action="code_ref", pattern=addr, limit=200)
            data_refs = search_tool(action="data_ref", pattern=addr, limit=200)
            code_text = code_refs.get("matches", "")
            data_text = data_refs.get("matches", "")
            call_chain = []
            seen = set()
            q = [(ea, 0)]
            while q:
                cur, d = q.pop(0)
                if d >= 3:
                    continue
                for xr in idautils.XrefsTo(cur, 0):
                    if not xr.iscode:
                        continue
                    cf = idaapi.get_func(xr.frm)
                    if not cf:
                        continue
                    k = (int(cf.start_ea), int(cur))
                    if k in seen:
                        continue
                    seen.add(k)
                    call_chain.append({
                        "caller": hex(cf.start_ea),
                        "caller_name": ida_funcs.get_func_name(cf.start_ea),
                        "callee": hex(cur),
                        "callee_name": ida_funcs.get_func_name(cur) or idc.get_name(cur) or hex(cur),
                        "depth": d + 1,
                    })
                    q.append((cf.start_ea, d + 1))
                if len(call_chain) >= 256:
                    break
            return {
                "ok": True,
                "addr": hex(ea),
                "code_refs": _lines(code_text),
                "data_refs": _lines(data_text),
                "code_refs_text": code_text,
                "data_refs_text": data_text,
                "call_chain_depth3": call_chain,
            }
        
        elif action == "search_all":
            if not query: return make_error(MCPError.INVALID_ARGS, "query required")
            from .data import data as data_tool
            from .search import search as search_tool
            funcs = data_tool(action="functions", query=query, count=25)
            strings = data_tool(action="strings", query=query, count=25)
            names = data_tool(action="globals", query=query, count=25)
            comments = search_tool(action="comment", pattern=query, limit=25)
            xrefs = search_tool(action="code_ref", pattern=query, limit=25)
            types_res = search_tool(action="type", pattern=query, limit=25)
            funcs_text = funcs.get("functions", "")
            strings_text = strings.get("strings", "")
            names_text = names.get("globals", "")
            comments_text = comments.get("matches", "")
            xrefs_text = xrefs.get("matches", "")
            types_text = types_res.get("matches", "")
            merged = []
            for src, txt in (
                ("functions", funcs_text),
                ("strings", strings_text),
                ("names", names_text),
                ("comments", comments_text),
                ("xrefs", xrefs_text),
                ("types", types_text),
            ):
                for ln in _lines(txt):
                    score = 2 if query.lower() in ln.lower() else 1
                    merged.append({"source": src, "score": score, "text": ln})
            merged.sort(key=lambda x: x["score"], reverse=True)
            return {
                "ok": True,
                "query": query,
                "functions": _lines(funcs_text),
                "strings": _lines(strings_text),
                "names": _lines(names_text),
                "comments": _lines(comments_text),
                "xrefs": _lines(xrefs_text),
                "types": _lines(types_text),
                "results": merged[: max_items * 4],
                "functions_text": funcs_text,
                "strings_text": strings_text,
                "names_text": names_text,
            }

        elif action == "search_structs":
            if not query: return make_error(MCPError.INVALID_ARGS, "query required")
            query_l = query.lower()
            out = []
            qty = int(getattr(ida_typeinf, "get_ordinal_qty", lambda: 0)() or 0)
            tif = ida_typeinf.tinfo_t()
            for ord_ in range(1, qty + 1):
                try:
                    if not ida_typeinf.get_numbered_type(None, ord_, tif):
                        continue
                    if not tif.is_struct():
                        continue
                    sname = str(tif.get_type_name() or f"ord_{ord_}")
                    udt = ida_typeinf.udt_type_data_t()
                    if not tif.get_udt_details(udt):
                        continue
                    matched_fields = []
                    for m in udt:
                        mname = str(getattr(m, "name", "") or "")
                        moff = int(getattr(m, "offset", 0) or 0)
                        if query_l in mname.lower() or query_l == hex(moff // 8).lower():
                            matched_fields.append({"name": mname, "offset_bits": moff, "offset_bytes": moff // 8})
                    if matched_fields:
                        out.append({"name": sname, "ordinal": ord_, "matched_fields": matched_fields[:8]})
                except Exception:
                    continue
            return {"ok": True, "query": query, "matches": out[:max_items], "count": len(out)}

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
                    if len(_FUNC_SUMMARY_CACHE) >= _FUNC_SUMMARY_CACHE_MAX:
                        # Evict oldest entry (first key in insertion-order dict)
                        _FUNC_SUMMARY_CACHE.pop(next(iter(_FUNC_SUMMARY_CACHE)), None)
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
            # Evidence-backed rename suggestions for nearby unnamed functions.
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
                "callees": [],
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
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN, idaapi.fl_F):
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
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN, idaapi.fl_F):
                        callee = idaapi.get_func(xref.to)
                        if callee and callee.start_ea not in seen:
                            seen.add(callee.start_ea)
                            callee_name = ida_funcs.get_func_name(callee.start_ea)
                            if not callee_name.startswith("sub_") and callee_name not in context["apis_called"]:
                                context["callees"].append(callee_name)
            context["callees"] = context["callees"][:10]
            
            # Pseudocode signature if available
            pseudo = ""
            if ida_hexrays.init_hexrays_plugin():
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        pseudo = str(cfunc)
                        lines = str(cfunc).split('\n')
                        # Get signature line
                        for line in lines[:5]:
                            if '(' in line and ')' in line:
                                context["signature"] = line.strip()
                                break
                except Exception:
                    pass

            include_evidence = bool(kwargs.get("include_evidence", True))
            top_k = max(1, int(kwargs.get("top_k", max_items)))
            persist_blackboard = bool(kwargs.get("persist_blackboard", True))
            persist_capsule = bool(kwargs.get("persist_capsule", True))
            suggestions = []

            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex
            except ImportError:
                try:
                    from host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex  # type: ignore
                except ImportError:
                    BgeCodeEmbedder = None
                    BehaviorClassifier = None
                    FunctionEmbeddingIndex = None

            base_tokens = [
                t.lower()
                for t in re.split(r"[^a-zA-Z0-9]+", str(name or ""))
                if t and not t.lower().startswith("sub")
            ]
            api_token = ""
            if context["apis_called"]:
                api_token = re.sub(r"[^a-z0-9]", "", str(context["apis_called"][0]).lower())[:20]
            if not api_token:
                api_token = "handler"

            if FunctionEmbeddingIndex is not None and BgeCodeEmbedder is not None and pseudo:
                try:
                    embedder = BgeCodeEmbedder()
                    idx = FunctionEmbeddingIndex((idaapi.get_path(idaapi.PATH_TYPE_IDB) or "") + ".embeddings.db", embedder)
                    idx.index_async(hex(func.start_ea), name, pseudo)
                    nearest = idx.similar(
                        pseudo,
                        top_k=max(top_k * 4, 16),
                        exclude_ea=hex(func.start_ea),
                        threshold=0.0,
                    )
                    behavior_rows = []
                    if BehaviorClassifier is not None:
                        try:
                            behavior_rows = BehaviorClassifier.instance(embedder).classify(
                                pseudo,
                                threshold=0.0,
                                top_k=3,
                                block=False,
                            )
                        except Exception:
                            behavior_rows = []
                    behavior_tag = ""
                    if behavior_rows:
                        behavior_tag = str(behavior_rows[0].get("behavior") or "").replace("_", "-")

                    rank = 0
                    for row in nearest:
                        target = str(row.get("ea") or "")
                        current_name = str(row.get("name") or target)
                        if not current_name.startswith("sub_"):
                            continue
                        rank += 1
                        stem_parts = []
                        if base_tokens:
                            stem_parts.extend(base_tokens[:2])
                        if behavior_tag:
                            stem_parts.append(behavior_tag)
                        stem_parts.append(api_token)
                        stem = "_".join([p for p in stem_parts if p])[:48] or "semantic_handler"
                        suggested_name = f"{stem}_{target.replace('0x', '')[-4:]}"
                        conf = max(0.0, min(1.0, float(row.get("similarity") or 0.0)))
                        ev = []
                        if include_evidence:
                            ev = [
                                {
                                    "type": "embedding_similarity",
                                    "value": round(conf, 4),
                                    "source": "FunctionEmbeddingIndex",
                                },
                                {
                                    "type": "behavior_hint",
                                    "value": behavior_rows[0].get("behavior") if behavior_rows else "",
                                    "source": "BehaviorClassifier",
                                },
                                {
                                    "type": "api_token",
                                    "value": api_token,
                                    "source": "call-context",
                                },
                            ]
                        suggestions.append(
                            {
                                "target": target,
                                "current_name": current_name,
                                "suggested_name": suggested_name,
                                "confidence": round(conf, 4),
                                "evidence": ev,
                                "rank": rank,
                            }
                        )
                        if len(suggestions) >= top_k:
                            break
                except Exception:
                    pass

            context["suggestions"] = suggestions
            context["count"] = len(suggestions)

            if persist_blackboard and suggestions:
                try:
                    from ida_pro_mcp.ida_mcp.tools.blackboard import BlackboardStore

                    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
                    bb = BlackboardStore((idb_path + ".blackboard.db") if idb_path else None)
                    for s in suggestions[: min(6, len(suggestions))]:
                        bb.write(
                            title=f"Rename suggestion {s['target']} -> {s['suggested_name']}",
                            content=json.dumps(
                                {
                                    "addr": s["target"],
                                    "current_name": s["current_name"],
                                    "suggested_name": s["suggested_name"],
                                    "confidence": s["confidence"],
                                },
                                ensure_ascii=False,
                            ),
                            category="rename_suggestion",
                            tags=["rename", "semantic", "agent"],
                            embed=False,
                        )
                except Exception:
                    pass

            if persist_capsule and suggestions:
                capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
                if capsule_path:
                    try:
                        from ida_pro_mcp.capsule import CapsuleStore

                        with CapsuleStore.open(capsule_path) as cap:
                            if not cap.is_initialized():
                                cap.init(project_name="ida-session", created_by="ida-pro-mcp-agent")
                            for s in suggestions[: min(6, len(suggestions))]:
                                cap.add_note(
                                    kind="rename_suggestion",
                                    title=f"{s['target']} -> {s['suggested_name']}",
                                    body=f"current={s['current_name']} confidence={s['confidence']}",
                                    metadata={
                                        "source": "agent.rename_suggestions",
                                        "target": s["target"],
                                        "suggested_name": s["suggested_name"],
                                        "evidence": s.get("evidence", []),
                                    },
                                )
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

        elif action in ("intelligence_status", "embedder_status", "anchor_status", "refresh_anchors", "classify_text", "classify_function", "index_function", "index_batch", "similar_functions", "export_index_summary", "evidence_card"):
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex
            except ImportError:
                try:
                    from host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex  # type: ignore
                except ImportError:
                    return make_error(MCPError.IDA_ERROR, "intelligence components unavailable")

            embedder = BgeCodeEmbedder()
            classifier = BehaviorClassifier.instance(embedder)

            def _index_for_current_idb():
                idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
                db_path = idb_path + ".embeddings.db"
                return FunctionEmbeddingIndex(db_path, embedder), db_path

            def _persist_embedder_state(idx, action_name: str, thresholds: dict | None = None):
                capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
                if not capsule_path:
                    return {"persisted": False, "capsule_path": "", "embedding_state_id": ""}
                try:
                    from ida_pro_mcp.capsule import CapsuleStore

                    anchor_hash = hashlib.sha256(
                        json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                    anchor_meta = {
                        "anchor_count": len(classifier.ANCHORS),
                        "anchor_hash_sha256": anchor_hash,
                        "anchor_version": f"sha256:{anchor_hash[:16]}",
                    }
                    state = idx.capsule_state(
                        anchor_metadata=anchor_meta,
                        thresholds=(thresholds or {}),
                        recent_limit=64,
                    )
                    state.setdefault("index_metadata", {})["source_action"] = action_name
                    with CapsuleStore.open(capsule_path) as cap:
                        if not cap.is_initialized():
                            cap.init(project_name="ida-session", created_by="ida-pro-mcp-agent")
                        sid = cap.add_embedding_state(state)
                    return {"persisted": True, "capsule_path": capsule_path, "embedding_state_id": sid}
                except Exception:
                    return {"persisted": False, "capsule_path": capsule_path, "embedding_state_id": ""}

            if action in ("intelligence_status", "embedder_status"):
                est = embedder.status(probe=bool(kwargs.get("probe", False)), deep_hash=bool(kwargs.get("deep_hash", False)))
                loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
                total = len(getattr(classifier, "ANCHORS", {}) or {})
                idx_count = 0
                active_indexes = 0
                try:
                    idx, idx_path = _index_for_current_idb()
                    idx_count = int(idx.size)
                    active_indexes = 1 if idx_path else 0
                except Exception:
                    pass
                persisted_state = {"persisted": False, "capsule_path": "", "embedding_state_id": ""}
                try:
                    if idx_count > 0:
                        persisted_state = _persist_embedder_state(idx, "intelligence_status")
                except Exception:
                    pass
                return {
                    "ok": True,
                    "embedder": est,
                    "anchors": {
                        "count": total,
                        "loaded": loaded,
                        "anchor_set_hash": hashlib.sha256(
                            json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        ).hexdigest(),
                    },
                    "indexes": {
                        "active_binaries": active_indexes,
                        "functions_indexed": idx_count,
                    },
                    "capsule_embedding_state": persisted_state,
                }

            if action == "anchor_status":
                loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
                total = len(getattr(classifier, "ANCHORS", {}) or {})
                return {
                    "ok": True,
                    "count": total,
                    "loaded": loaded,
                    "anchor_set_hash": hashlib.sha256(
                        json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest(),
                }

            if action == "refresh_anchors":
                behaviors = []
                if query:
                    behaviors = [x.strip() for x in str(query).split(",") if x.strip()]
                classifier.refresh_anchors(behaviors or None)
                loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
                return {"ok": True, "refreshed": behaviors or "all", "loaded": loaded}

            if action == "classify_text":
                if not query:
                    return make_error(MCPError.INVALID_ARGS, "query required for classify_text")
                threshold = float(kwargs.get("threshold", 0.25))
                top_k = int(kwargs.get("top_k", 4))
                block = bool(kwargs.get("block", False))
                rows = classifier.classify(str(query), threshold=threshold, top_k=top_k, block=block)
                return {
                    "ok": True,
                    "backend": embedder.backend,
                    "behaviors": rows,
                }

            if action == "classify_function":
                if not addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required for classify_function")
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    pseudo = str(cfunc) if cfunc else ""
                except Exception:
                    pseudo = ""
                if not pseudo:
                    return make_error(MCPError.IDA_ERROR, "failed to decompile function")
                threshold = float(kwargs.get("threshold", 0.25))
                top_k = int(kwargs.get("top_k", 4))
                block = bool(kwargs.get("block", False))
                rows = classifier.classify(pseudo, threshold=threshold, top_k=top_k, block=block)
                return {
                    "ok": True,
                    "addr": hex(ea),
                    "name": ida_funcs.get_func_name(ea),
                    "backend": embedder.backend,
                    "behaviors": rows,
                }

            if action == "index_function":
                if not addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required for index_function")
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    pseudo = str(cfunc) if cfunc else ""
                except Exception:
                    pseudo = ""
                if not pseudo:
                    return make_error(MCPError.IDA_ERROR, "failed to decompile function")
                idx, db_path = _index_for_current_idb()
                name = ida_funcs.get_func_name(ea) or hex(ea)
                idx.index(hex(ea), name, pseudo)
                persisted_state = _persist_embedder_state(idx, "index_function")
                return {
                    "ok": True,
                    "addr": hex(ea),
                    "name": name,
                    "index": {"path": db_path, "size": idx.size},
                    "capsule_embedding_state": persisted_state,
                }

            if action == "index_batch":
                limit = max(1, int(kwargs.get("limit", max_items)))
                idx, db_path = _index_for_current_idb()
                count = 0
                failures = 0
                for fea in idautils.Functions():
                    if count >= limit:
                        break
                    try:
                        cfunc = ida_hexrays.decompile(fea)
                        pseudo = str(cfunc) if cfunc else ""
                        if not pseudo:
                            failures += 1
                            continue
                        name = ida_funcs.get_func_name(fea) or hex(fea)
                        idx.index(hex(fea), name, pseudo)
                        count += 1
                    except Exception:
                        failures += 1
                persisted_state = _persist_embedder_state(idx, "index_batch")
                return {
                    "ok": True,
                    "indexed": count,
                    "failed": failures,
                    "index": {"path": db_path, "size": idx.size},
                    "capsule_embedding_state": persisted_state,
                }

            if action == "similar_functions":
                if not addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required for similar_functions")
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                threshold = float(kwargs.get("threshold", 0.55))
                top_k = max(1, int(kwargs.get("top_k", max_items)))
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    pseudo = str(cfunc) if cfunc else ""
                except Exception:
                    pseudo = ""
                if not pseudo:
                    return make_error(MCPError.IDA_ERROR, "failed to decompile function")
                idx, db_path = _index_for_current_idb()
                qname = ida_funcs.get_func_name(ea) or hex(ea)
                idx.index_async(hex(ea), qname, pseudo)
                similar = idx.similar(pseudo, top_k=top_k, exclude_ea=hex(ea), threshold=threshold)
                persisted_state = _persist_embedder_state(
                    idx,
                    "similar_functions",
                    thresholds={"similarity_threshold": float(threshold)},
                )
                return {
                    "ok": True,
                    "query_addr": hex(ea),
                    "query_name": qname,
                    "similar": similar,
                    "index": {"path": db_path, "size": idx.size},
                    "capsule_embedding_state": persisted_state,
                }

            if action == "export_index_summary":
                idx, db_path = _index_for_current_idb()
                meta = {}
                try:
                    meta = idx.metadata()
                except Exception:
                    meta = {}
                persisted_state = _persist_embedder_state(idx, "export_index_summary")
                return {
                    "ok": True,
                    "index": {
                        "path": db_path,
                        "size": idx.size,
                        "metadata": meta,
                    },
                    "capsule_embedding_state": persisted_state,
                }

            if action == "evidence_card":
                if not addr:
                    return make_error(MCPError.INVALID_ARGS, "addr required for evidence_card")
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    pseudo = str(cfunc) if cfunc else ""
                except Exception:
                    pseudo = ""
                if not pseudo:
                    return make_error(MCPError.IDA_ERROR, "failed to decompile function")

                threshold = float(kwargs.get("threshold", 0.25))
                top_k = int(kwargs.get("top_k", 4))
                behavior_rows = classifier.classify(pseudo, threshold=threshold, top_k=top_k, block=False)
                idx, db_path = _index_for_current_idb()
                qname = ida_funcs.get_func_name(ea) or hex(ea)
                idx.index_async(hex(ea), qname, pseudo)
                similar = idx.similar(pseudo, top_k=max(1, int(kwargs.get("similar_top_k", 3))), exclude_ea=hex(ea), threshold=0.0)

                top_behavior = behavior_rows[0] if behavior_rows else {}
                top_conf = float(top_behavior.get("confidence", 0.0) or 0.0)
                claim_behavior = str(top_behavior.get("behavior") or "unknown_behavior")
                claim = f"Function may implement {claim_behavior.replace('_', ' ')} behavior."
                evidence = []
                if behavior_rows:
                    evidence.append(
                        {
                            "type": "behavior_anchor",
                            "value": claim_behavior,
                            "confidence": round(top_conf, 4),
                            "source": "BehaviorClassifier",
                            "explain": top_behavior.get("explain", []),
                        }
                    )
                if similar:
                    evidence.append(
                        {
                            "type": "similar_function",
                            "addr": similar[0].get("ea"),
                            "name": similar[0].get("name"),
                            "similarity": similar[0].get("similarity"),
                            "source": "FunctionEmbeddingIndex",
                        }
                    )
                card = {
                    "claim": claim,
                    "claim_type": "behavior_triage",
                    "confidence": round(top_conf, 4),
                    "evidence": evidence,
                    "source_refs": [{"kind": "function", "addr": hex(ea), "name": qname}],
                    "required_followup": {
                        "tool": "code",
                        "action": "callers",
                        "addr": hex(ea),
                    },
                }

                persisted = False
                persisted_id = ""
                capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
                if capsule_path:
                    try:
                        from ida_pro_mcp.capsule import CapsuleStore

                        with CapsuleStore.open(capsule_path) as cap:
                            if not cap.is_initialized():
                                cap.init(project_name="ida-session", created_by="ida-pro-mcp-agent")
                            persisted_id = cap.add_evidence_card(
                                claim=card["claim"],
                                claim_type=card["claim_type"],
                                confidence=card["confidence"],
                                evidence=card["evidence"],
                                source_refs=card["source_refs"],
                                metadata={
                                    "addr": hex(ea),
                                    "name": qname,
                                    "index_path": db_path,
                                },
                            )
                            persisted = True
                    except Exception:
                        persisted = False
                        persisted_id = ""

                return {
                    "ok": True,
                    "addr": hex(ea),
                    "name": qname,
                    "card": card,
                    "persisted": persisted,
                    "persisted_id": persisted_id,
                }
        
        elif action == "similar":
            # Find functions with similar characteristics using embedding-based search
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")

            ea, err = validate_addr(addr)
            if err:
                return err

            func = idaapi.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            target_name = ida_funcs.get_func_name(func.start_ea)

            # Try embedding-based similarity first (fast, O(n) cosine scan)
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex
            except ImportError:
                try:
                    from host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex  # type: ignore
                except ImportError:
                    FunctionEmbeddingIndex = None

            if FunctionEmbeddingIndex is not None:
                try:
                    pseudo = None
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            pseudo = str(cfunc)
                    except Exception:
                        pass
                    if pseudo:
                        embedder = BgeCodeEmbedder()
                        idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
                        db_path = idb_path + ".embeddings.db"
                        idx = FunctionEmbeddingIndex(db_path, embedder)
                        # Index the query function if not already indexed
                        idx.index_async(hex(func.start_ea), target_name or hex(func.start_ea), pseudo)
                        results = idx.similar(pseudo, top_k=max(6, max_items * 3), exclude_ea=hex(func.start_ea), threshold=0.0)
                        if results:
                            sims = sorted(float(r.get("similarity") or 0.0) for r in results)
                            q50 = sims[len(sims) // 2]
                            q75 = sims[min(len(sims) - 1, int(round((len(sims) - 1) * 0.75)))]
                            gate = q50 + max(0.0, q75 - q50)
                            filtered = [r for r in results if float(r.get("similarity") or 0.0) >= gate]
                            results = (filtered or results)[:max_items]
                        return {
                            "ok": True,
                            "target": target_name,
                            "target_addr": hex(func.start_ea),
                            "similar_functions": results,
                            "count": len(results),
                            "method": embedder.backend,
                        }
                except Exception:
                    pass  # fall through to deterministic fallback

            # Deterministic fallback: API + string overlap (bounded scan)
            target_apis: set = set()
            target_strings: set = set()
            for item in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN, idaapi.fl_F):
                        name = idc.get_name(xref.to)
                        if name and not name.startswith("sub_"):
                            target_apis.add(name)
                    elif not xref.iscode:
                        s = idc.get_strlit_contents(xref.to)
                        if s:
                            target_strings.add((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:50])

            target_size = func.end_ea - func.start_ea
            similar_funcs = []
            _cap = max_items * 20  # scan at most this many functions

            for i, other_ea in enumerate(idautils.Functions()):
                if i >= _cap or len(similar_funcs) >= max_items * 3:
                    break
                if other_ea == func.start_ea:
                    continue
                other_func = idaapi.get_func(other_ea)
                if not other_func:
                    continue
                other_size = other_func.end_ea - other_func.start_ea
                size_ratio = min(target_size, other_size) / max(target_size, other_size, 1)
                if size_ratio < 0.4:
                    continue

                other_apis: set = set()
                other_strings: set = set()
                for item in idautils.FuncItems(other_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN, idaapi.fl_F):
                            n = idc.get_name(xref.to)
                            if n and not n.startswith("sub_"):
                                other_apis.add(n)
                        elif not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                other_strings.add((s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))[:50])

                score = int(size_ratio * 30)
                reasons = []
                if target_apis and other_apis:
                    api_j = len(target_apis & other_apis) / len(target_apis | other_apis)
                    if api_j > 0.3:
                        score += int(api_j * 50)
                        reasons.append(f"api_overlap:{int(api_j*100)}%")
                if target_strings and other_strings:
                    str_j = len(target_strings & other_strings) / len(target_strings | other_strings)
                    if str_j > 0.2:
                        score += int(str_j * 20)
                        reasons.append(f"string_overlap:{int(str_j*100)}%")

                if score >= 20 and reasons:
                    similar_funcs.append({
                        "addr": hex(other_ea),
                        "name": ida_funcs.get_func_name(other_ea),
                        "score": score,
                        "reasons": reasons,
                        "shared_apis": list(target_apis & other_apis)[:5],
                    })

            similar_funcs.sort(key=lambda x: x["score"], reverse=True)
            return {
                "ok": True,
                "target": target_name,
                "target_addr": hex(func.start_ea),
                "similar_functions": similar_funcs[:max_items],
                "count": len(similar_funcs[:max_items]),
                "method": "deterministic_fallback",
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

        elif action == "cluster":
            # Batch embed all functions and cluster by behavioral similarity.
            # Uses bge-code-v1 embeddings (or TF-IDF fallback) + pure-numpy k-means.
            # Returns labeled clusters with representative functions and behavior tags.
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex, _extract_signature
            except ImportError:
                from host.intelligence import BgeCodeEmbedder, BehaviorClassifier, FunctionEmbeddingIndex, _extract_signature  # type: ignore

            k = int(kwargs.get("k") or max_items or 12)
            func_limit = int(kwargs.get("func_limit") or 2000)
            embedder = BgeCodeEmbedder()
            classifier = BehaviorClassifier.instance(embedder)

            # Collect functions: prefer decompiled pseudocode, fall back to API names
            funcs_data = []  # [(ea, name, text_to_embed)]
            for func_ea in idautils.Functions():
                if len(funcs_data) >= func_limit:
                    break
                fname = idc.get_func_name(func_ea) or hex(func_ea)
                text = None
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        text = _extract_signature(str(cfunc), max_idents=40)
                except Exception:
                    pass
                if not text:
                    # Fallback: collect API calls as text
                    apis = []
                    for item in idautils.FuncItems(func_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                                n = idc.get_name(xref.to)
                                if n and not n.startswith("sub_"):
                                    apis.append(n)
                    text = " ".join(apis[:30]) or fname
                funcs_data.append((func_ea, fname, text))

            if len(funcs_data) < 2:
                return make_error(MCPError.INVALID_ARGS, "Not enough functions to cluster")

            # Batch embed
            texts = [t for _, _, t in funcs_data]
            vecs = embedder.embed_batch(texts)

            # K-means cluster
            k = min(k, len(funcs_data))
            labels, centroids = _kmeans_numpy(vecs, k)

            # Build clusters
            clusters: dict = {}
            for i, (func_ea, fname, _) in enumerate(funcs_data):
                lbl = labels[i]
                clusters.setdefault(lbl, []).append({"addr": hex(func_ea), "name": fname})

            # Label each cluster using BehaviorClassifier on the centroid
            result_clusters = []
            for lbl, members in sorted(clusters.items(), key=lambda x: -len(x[1])):
                centroid = centroids[lbl].tolist()
                behavior = classifier.classify_vec(centroid, threshold=0.0, top_k=4, block=False)
                if behavior:
                    bs = sorted(float(b.get("confidence") or b.get("score") or 0.0) for b in behavior)
                    bq50 = bs[len(bs) // 2]
                    bq75 = bs[min(len(bs) - 1, int(round((len(bs) - 1) * 0.75)))]
                    bgate = bq50 + max(0.0, bq75 - bq50)
                    behavior = [b for b in behavior if float(b.get("confidence") or b.get("score") or 0.0) >= bgate]
                label = behavior[0]["behavior"] if behavior else f"cluster_{lbl}"
                confidence = behavior[0]["confidence"] if behavior else 0.0
                result_clusters.append({
                    "cluster_id": lbl,
                    "label": label,
                    "confidence": round(confidence, 3),
                    "size": len(members),
                    "behavior_tags": [b["behavior"] for b in behavior],
                    "representative_functions": members[:8],
                })

            # Auto-write cluster summary to blackboard
            try:
                from .blackboard import BlackboardStore
                store = BlackboardStore()
                for c in result_clusters:
                    store.write(
                        title=f"Cluster: {c['label']} ({c['size']} functions)",
                        content=str([m["name"] for m in c["representative_functions"]]),
                        category="cluster",
                        tags=["auto", "cluster"] + c["behavior_tags"],
                        confidence=c["confidence"],
                        source="agent.cluster",
                    )
            except Exception:
                pass

            return {
                "ok": True,
                "total_functions": len(funcs_data),
                "k": k,
                "clusters": result_clusters,
                "backend": embedder.backend,
                "note": "Clusters are behavioral groups. Use classify(action='function') on representative_functions for deeper analysis.",
            }

        elif action == "fingerprint":
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex, _extract_signature
            except ImportError:
                from host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex, _extract_signature  # type: ignore

            idb_path = ""
            try:
                idb_path = idc.get_idb_path() or ""
            except Exception:
                pass
            if not idb_path:
                return make_error(MCPError.INVALID_ARGS, "No IDB path")

            embedder = BgeCodeEmbedder()
            current_idx = FunctionEmbeddingIndex(idb_path + ".embeddings.db", embedder)

            if current_idx.size == 0:
                return {"ok": True, "note": "No functions indexed. Run code(action='decompile') first.", "matches": []}

            import os
            fingerprint_eas = list(current_idx._cache.keys())[:20]
            fingerprint_vecs = [current_idx._cache[ea] for ea in fingerprint_eas]

            db_dir = os.path.dirname(idb_path)
            matches = []
            for fname in os.listdir(db_dir):
                if not fname.endswith(".embeddings.db"):
                    continue
                other_path = os.path.join(db_dir, fname)
                if other_path == idb_path + ".embeddings.db":
                    continue
                try:
                    other_idx = FunctionEmbeddingIndex(other_path, embedder)
                    if other_idx.size == 0:
                        continue
                    sims = []
                    for vec in fingerprint_vecs:
                        best = other_idx.similar_vec(vec, top_k=1, threshold=0.0)
                        if best:
                            sims.append(best[0]["similarity"])
                    if sims:
                        avg_sim = sum(sims) / len(sims)
                        matches.append({"binary": fname.replace(".embeddings.db", ""), "similarity": round(avg_sim, 3), "matched_functions": len(sims)})
                except Exception:
                    continue

            matches.sort(key=lambda x: -x["similarity"])
            return {
                "ok": True,
                "current_binary": os.path.basename(idb_path),
                "fingerprint_size": len(fingerprint_eas),
                "matches": matches[:10],
                "backend": embedder.backend,
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _kmeans_numpy(vecs, k: int, max_iter: int = 30):
    """
    Pure-numpy k-means. Returns (labels, centroids).
    vecs: list of float lists, all same length.
    """
    import numpy as np
    X = np.array(vecs, dtype=np.float32)
    n = len(X)
    if n <= k:
        return list(range(n)), X
    # Kmeans++ init
    rng = np.random.default_rng(42)
    centers = [X[rng.integers(n)]]
    for _ in range(k - 1):
        dists = np.array([min(np.dot(x - c, x - c) for c in centers) for x in X])
        probs = dists / dists.sum()
        centers.append(X[rng.choice(n, p=probs)])
    centers = np.array(centers)
    labels = np.zeros(n, dtype=int)
    for _ in range(max_iter):
        # Assign
        dists = np.array([[np.dot(x - c, x - c) for c in centers] for x in X])
        new_labels = np.argmin(dists, axis=1)
        if np.all(new_labels == labels):
            break
        labels = new_labels
        # Update centroids
        for j in range(k):
            members = X[labels == j]
            if len(members):
                centers[j] = members.mean(axis=0)
    return labels.tolist(), centers


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================
