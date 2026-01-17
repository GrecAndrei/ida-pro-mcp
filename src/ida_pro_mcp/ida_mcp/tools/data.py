
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
                      "Action: functions|globals|strings|imports|exports|lookup|bulk_query"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    include_prototype: Annotated[bool, "Include function prototypes (functions action)"] = False,
    include_xrefs: Annotated[bool, "Include cross-reference counts"] = False,
    min_size: Annotated[Optional[int], "Minimum function size filter"] = None,
    named_only: Annotated[bool, "Only return named (non-sub_) items"] = False,
    **kwargs
) -> dict:
    """
    Query, filter, and list data items: functions, globals, strings, imports.
    
    ACTIONS:
    
    functions - List all defined functions with optional filtering
        Params: query (name filter), offset, count, include_prototype, include_xrefs, 
                min_size, named_only
        Returns: {functions: [{addr, name, size, end, flags, prototype?, xrefs_to?, xrefs_from?}]}
        
    globals - List global names/variables (non-functions)
        Params: query (name filter), offset, count, include_xrefs
        Returns: {globals: [{addr, name, size, type, xrefs?}]}
        
    strings - List string literals with filtering
        Params: query (content filter), offset, count
        Returns: {strings: [{addr, string, length, encoding, xrefs}]}
        
    imports - List imported modules and functions
        Params: query (filter by module or function name), offset, count
        Returns: {imports: [{addr, name, module, ordinal}]}
        
    exports - List exported entry points
        Params: offset, count
        Returns: {exports: [{addr, name, ordinal}]}
        
    lookup - Resolve a name to address or address to name
        Params: query (name or address)
        Returns: {addr, name, type, size}
        
    bulk_query - Execute multiple queries in one call
        Params: items (list of {kind, query, offset, count})
        Returns: {results: [{index, kind, result}]}
    """
    try:
        if action == "functions":
            funcs = []
            found_count = 0
            
            # First pass: Count total matches
            total = 0
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                
                # Filter by named_only
                if named_only and name.startswith("sub_"):
                    continue
                    
                fn = idaapi.get_func(ea)
                if not fn:
                    continue
                    
                # Filter by min_size
                func_size = fn.end_ea - fn.start_ea
                if min_size and func_size < min_size:
                    continue
                    
                if not query or query.lower() in name.lower():
                    total += 1
                    
                    # Collect paginated results
                    if total > offset and (count == 0 or len(funcs) < count):
                        entry = {
                            "addr": hex_ea(ea), 
                            "name": name, 
                            "size": hex_size(func_size),
                            "end": hex_ea(fn.end_ea),
                            "flags": hex(fn.flags),
                        }
                        
                        if include_prototype:
                            entry["prototype"] = get_prototype(fn)
                            
                        if include_xrefs:
                            entry["xrefs_to"] = len(list(idautils.XrefsTo(ea)))
                            entry["xrefs_from"] = len(list(idautils.XrefsFrom(ea)))
                            
                        funcs.append(entry)
            
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
                    
                if named_only and (name.startswith("unk_") or name.startswith("off_") or 
                                   name.startswith("loc_") or name.startswith("byte_") or
                                   name.startswith("word_") or name.startswith("dword_") or
                                   name.startswith("qword_")):
                    continue
                    
                if not query or query.lower() in name.lower():
                    total += 1
                    if total > offset and (count == 0 or len(globs) < count):
                        entry = {"addr": hex_ea(ea), "name": name}
                        
                        # Get size and type info
                        entry["size"] = idc.get_item_size(ea)
                        
                        # Try to get type
                        tif = ida_typeinf.tinfo_t()
                        if ida_nalt.get_tinfo(tif, ea):
                            entry["type"] = str(tif)
                            
                        if include_xrefs:
                            entry["xrefs"] = len(list(idautils.XrefsTo(ea)))
                            
                        globs.append(entry)
            
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
                        if len(s) < 4: continue
                        
                        # Section check - skip strings in executable sections (likely false positives)
                        seg = idaapi.getseg(sc.ea)
                        if seg and (seg.perm & idaapi.SEGPERM_EXEC) and len(s) < 12:
                            continue
                        
                        # Meaningful check - relax for longer strings
                        if len(s) < 20:
                            alnum_count = sum(1 for c in s if c.isalnum() or c in ' ._-/:=()[]{}\\n\\t')
                            if alnum_count / len(s) < 0.6: continue
                        
                        if not query or query.lower() in s.lower():
                            total += 1
                            if total > offset and (count == 0 or len(strings) < count):
                                # Determine encoding
                                str_type = idc.get_str_type(sc.ea)
                                encoding = "ascii"
                                if str_type == idc.STRTYPE_C_16:
                                    encoding = "utf-16"
                                elif str_type == idc.STRTYPE_C_32:
                                    encoding = "utf-32"
                                
                                entry = {
                                    "addr": hex_ea(sc.ea), 
                                    "string": s[:500], 
                                    "length": sc.length,
                                    "encoding": encoding,
                                }
                                
                                # Count xrefs
                                entry["xrefs"] = len(list(idautils.XrefsTo(sc.ea)))
                                
                                strings.append(entry)
                    except:
                        pass
            
            return {"ok": True, "strings": strings, "total": total, "offset": offset, "count": len(strings)}
        
        elif action == "imports":
            imports = []
            total = 0
            query_lower = query.lower() if query else None
            
            for i in range(ida_nalt.get_import_module_qty()):
                module = ida_nalt.get_import_module_name(i)
                
                # Check module filter
                if query_lower and query_lower not in module.lower():
                    # Still check individual function names
                    pass
                
                # Collect imports
                mod_imports = []
                def cb(ea, name, ordinal):
                    imp_name = name or f"ord_{ordinal}"
                    if not query_lower or query_lower in module.lower() or query_lower in imp_name.lower():
                        mod_imports.append({
                            "addr": hex_ea(ea), 
                            "name": imp_name, 
                            "module": module,
                            "ordinal": ordinal if ordinal else None
                        })
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
                
                if query and query.lower() not in (name or "").lower():
                    continue
                    
                total += 1
                if total > offset and (count == 0 or len(exports) < count):
                    entry = {"addr": hex(ea), "name": name, "ordinal": ordinal}
                    
                    # Add function size if it's a function
                    func = idaapi.get_func(ea)
                    if func:
                        entry["size"] = hex(func.end_ea - func.start_ea)
                        
                    exports.append(entry)
                    
            return {"ok": True, "exports": exports, "total": total, "offset": offset, "count": len(exports)}
        
        elif action == "lookup":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for lookup")
            try:
                result = resolve_symbol(query)
                # Enhance with additional info
                ea = parse_address(result.get("addr", query)) if result.get("addr") else None
                if ea:
                    result["size"] = idc.get_item_size(ea)
                    func = idaapi.get_func(ea)
                    if func:
                        result["is_function"] = True
                        result["func_size"] = hex(func.end_ea - func.start_ea)
                    else:
                        result["is_function"] = False
                return {"ok": True, **result}
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
