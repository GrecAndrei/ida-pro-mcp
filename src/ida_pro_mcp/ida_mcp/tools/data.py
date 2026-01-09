
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
    from ida_mcp.utils import resolve_symbol
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
    from utils import resolve_symbol
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================

@tool
@idaread
def data(
    action: Annotated[Literal["functions", "globals", "strings", "imports", "exports", "lookup", "bulk_query"],
                      "Action: functions|globals|strings|imports|exports|lookup"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    **kwargs
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
            found_count = 0
            
            # First pass: Count total matches
            total = 0
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                if not query or query.lower() in name.lower():
                    total += 1
                    
                    # Second pass: Collect paginated results
                    if total > offset and (count == 0 or len(funcs) < count):
                        fn = idaapi.get_func(ea)
                        funcs.append({
                            "addr": hex_ea(ea), 
                            "name": name, 
                            "size": hex_size(fn.end_ea - fn.start_ea)
                        })
            
            result = {"ok": True, "functions": funcs, "total": total, "offset": offset, "count": len(funcs)}
            if total == 0:
                result["warning"] = "No functions found matching query."
            return result
        
        elif action == "globals":
            globs = []
            total = 0
            for ea, name in idautils.Names():
                if idaapi.get_func(ea):
                    continue
                if not query or query.lower() in name.lower():
                    total += 1
                    if total > offset and (count == 0 or len(globs) < count):
                        globs.append({"addr": hex_ea(ea), "name": name})
            
            return {"ok": True, "globals": globs, "total": total, "offset": offset, "count": len(globs)}
        
        elif action == "strings":
            strings = []
            total = 0
            for i in range(idaapi.get_strlist_qty()):
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if not content: continue
                        
                        s = content.decode("utf-8", errors="replace")
                        if len(s) < 8: continue
                        
                        # Section check
                        seg = idaapi.getseg(sc.ea)
                        if seg and (seg.perm & idaapi.SEGPERM_EXEC): continue
                        
                        # Meaningful check
                        alnum_count = sum(1 for c in s if c.isalnum() or c in ' ._-/:=()[]{}\\n\\t')
                        if alnum_count / len(s) < 0.7: continue
                        
                        if not query or query.lower() in s.lower():
                            total += 1
                            if total > offset and (count == 0 or len(strings) < count):
                                strings.append({"addr": hex_ea(sc.ea), "string": s[:200], "length": sc.length})
                    except:
                        pass
            
            return {"ok": True, "strings": strings, "total": total, "offset": offset, "count": len(strings)}
        
        elif action == "imports":
            imports = []
            total = 0
            for i in range(ida_nalt.get_import_module_qty()):
                module = ida_nalt.get_import_module_name(i)
                
                # Internal list to handle module-level pagination accurately
                mod_imports = []
                def cb(ea, name, ordinal):
                    mod_imports.append({"addr": hex_ea(ea), "name": name or f"ord_{ordinal}", "module": module})
                    return True
                ida_nalt.enum_import_names(i, cb)
                
                for imp in mod_imports:
                    total += 1
                    if total > offset and (count == 0 or len(imports) < count):
                        imports.append(imp)
                        
            return {"ok": True, "imports": imports, "total": total, "offset": offset, "count": len(imports)}
        
        elif action == "exports":
            exports = []
            total = 0
            
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
                        return make_error(MCPError.IDA_ERROR, "Entry API not available in this IDA version")

            for i in range(_qty()):
                ordinal = _ordinal(i)
                ea = _entry(ordinal)
                name = _name(ordinal)
                total += 1
                if total > offset and (count == 0 or len(exports) < count):
                    exports.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
            return {"ok": True, "exports": exports, "total": total, "offset": offset, "count": len(exports)}
        
        elif action == "lookup":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for lookup")
            try:
                return {"ok": True, **resolve_symbol(query)}
            except Exception as e:
                return make_error(MCPError.FILE_NOT_FOUND, str(e))

        elif action == "bulk_query":
            items = kwargs.get("items") or kwargs.get("queries") or []
            if not isinstance(items, list):
                return make_error(MCPError.INVALID_ARGS, "items must be a list")
            results = []
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    results.append({"index": i, "error": "invalid item"})
                    continue
                kind = item.get("kind") or item.get("action")
                if not kind:
                    results.append({"index": i, "error": "missing kind"})
                    continue
                sub_query = item.get("query")
                sub_offset = item.get("offset", 0)
                sub_count = item.get("count", 100)
                res = data(action=kind, query=sub_query, offset=sub_offset, count=sub_count)
                results.append({"index": i, "kind": kind, "result": res})
            return {"ok": True, "results": results, "count": len(results)}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================
