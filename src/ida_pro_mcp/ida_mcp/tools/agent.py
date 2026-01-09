from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import time
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
    from ..rpc import tool, unsafe
    from ..sync import idaread, idawrite, IDAError
    from ..utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ..error_handling import (
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
    action: Annotated[Literal["analyze_function", "explore_address", "find_references", "search_all", "search_structs", "context_pack"],
                      "Action: analyze_function|explore_address|find_references|search_all|search_structs|context_pack"],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Search query"] = None,
    depth: Annotated[int, "Exploration depth"] = 1,
    include_pseudocode: Annotated[bool, "Include decompiler pseudocode in context pack"] = False,
    max_items: Annotated[int, "Max items for context pack lists"] = 25,
    use_cache: Annotated[bool, "Use cached decompiler summaries when possible"] = True,
) -> dict:
    """
    High-level agent helpers: triage, exploration, and universal search.
    
    Actions:
    - analyze_function: Full analysis (pseudocode, xrefs, strings, stack).
    - explore_address: Get context around an unknown address.
    - find_references: Trace code and data references to an address.
    - search_all: Universal search across names, strings, and functions.
    - search_structs: Find structs by field name or type name.
    - context_pack: One-shot function context (pseudocode, xrefs, callers, callees, strings, types).
    """
    try:
        if action == "analyze_function":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            def debug_log_agent(msg):
                try:
                    with open(os.path.join(os.environ.get("TEMP", "C:\\temp"), "ida_mcp_emergency.log"), "a") as f:
                        f.write(f"[{time.ctime()}] AGENT: {msg}\n")
                except: pass

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
            return {"ok": True, "addr": hex(ea), "code_refs": code_refs.get("matches", []), "data_refs": data_refs.get("matches", [])}
        
        elif action == "search_all":
            if not query: return make_error(MCPError.INVALID_ARGS, "query required")
            from .data import data as data_tool
            funcs = data_tool(action="functions", query=query, count=10)
            strings = data_tool(action="strings", query=query, count=10)
            names = data_tool(action="globals", query=query, count=10)
            return {"ok": True, "query": query, "functions": funcs.get("functions", []), "strings": strings.get("strings", []), "names": names.get("globals", [])}

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
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != func.start_ea:
                                    calls.add((hex(tf.start_ea), ida_funcs.get_func_name(tf.start_ea)))
                            else:
                                s = idc.get_strlit_contents(xref.to)
                                if s:
                                    strings.append({"addr": hex(xref.to), "string": s.decode("utf-8", errors="replace")})
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
                for xref in idautils.XrefsTo(func.start_ea, 0):
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================
