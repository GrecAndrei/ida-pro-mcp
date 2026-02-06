
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import ida_ida
import idaapi
import idautils
import idc

# Infrastructure discovery
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
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


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
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results"] = 100,
    **kwargs
) -> dict:
    """
    Deep import analysis with thunk resolution and delay import detection.
    
    ACTIONS:
    
    thunks - Resolve import thunks to actual API addresses
        Params: query (optional string pattern filter for DLL or function name)
        Returns: {thunks: [{thunk_addr, target, name, dll}]}
        
    delay - List delay-loaded imports
        Returns: {delay_imports: [{dll, functions: [...]}]}
        
    forwarded - Detect forwarded exports in imported DLLs
        Returns: {forwarded: [{from_dll, to_dll, name}]}
        
    ordinal - Resolve ordinal imports to named symbols
        Params: query (optional DLL name filter)
        Returns: {ordinal_imports: [{dll, ordinal, resolved_name}]}
        
    api_sets - Resolve Windows API Set redirections (api-ms-*)
        Returns: {api_sets: [{virtual_dll, actual_dll}]}
        
    resolve - Resolve import at specific address or list all imports
        Params: addr (optional - if omitted, lists first 100 imports)
        Returns: {addr, dll, name, type} OR {resolved: [...]}
    """
    try:
        if action == "thunks":
            thunk_lines = []
            
            # Find IAT/thunk sections
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if '.idata' in seg_name.lower() or 'iat' in seg_name.lower():
                    seg = ida_segment.getseg(seg_ea)
                    if not seg:
                        continue
                    
                    ea = seg.start_ea
                    while ea < seg.end_ea:
                        is_64 = ida_ida.inf_is_64bit()
                        target = idc.get_qword(ea) if is_64 else idc.get_wide_dword(ea)
                        name = idc.get_name(ea)
                        
                        if name and target:
                            if query and query.lower() not in name.lower():
                                ea += 8 if is_64 else 4
                                continue

                            thunk_lines.append(f"{hex(ea)}  -> {hex(target)}  {name}")
                        
                        ea += 8 if is_64 else 4
                        
                        if count != 0 and len(thunk_lines) >= offset + count:
                            break

            total = len(thunk_lines)
            page = thunk_lines[offset:offset + count] if count != 0 else thunk_lines[offset:]
            return {"ok": True, "thunks": "\n".join(page), "total": total, "offset": offset, "count": len(page)}
        
        elif action == "delay":
            delay_imports = {}
            
            # Look for delay import directory
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if 'delay' in seg_name.lower() or '.didat' in seg_name.lower():
                    seg = ida_segment.getseg(seg_ea)
                    if seg:
                        ea = seg.start_ea
                        while ea < seg.end_ea:
                            name = idc.get_name(ea)
                            if name:
                                parts = name.split('_')
                                if len(parts) >= 2:
                                    dll = parts[0]
                                    if dll not in delay_imports:
                                        delay_imports[dll] = []
                                    delay_imports[dll].append(f"{hex(ea)}  {name}")
                            ea = idc.next_head(ea, seg.end_ea)
                            if ea == idaapi.BADADDR:
                                break
            
            result_lines = []
            for dll, funcs in delay_imports.items():
                result_lines.append(f"[{dll}]")
                for f in funcs[:20]:
                    result_lines.append(f"  {f}")
            page = result_lines[offset:offset + count] if count != 0 else result_lines[offset:]
            return {"ok": True, "delay_imports": "\n".join(page), "total": len(result_lines), "offset": offset, "count": len(page)}
        
        elif action == "forwarded":
            fwd_lines = []
            
            def imp_cb(ea, name, ordinal):
                if name and '.' in name:
                    parts = name.split('.')
                    if len(parts) == 2:
                        fwd_lines.append(f"{hex(ea)}  {name}  -> {parts[1]}")
                return True
            
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name:
                    ida_nalt.enum_import_names(i, imp_cb)
            
            page = fwd_lines[offset:offset + count] if count != 0 else fwd_lines[offset:]
            return {"ok": True, "forwarded": "\n".join(page), "total": len(fwd_lines), "offset": offset, "count": len(page), "note": "Limited detection - full analysis requires DLL parsing"}
        
        elif action == "ordinal":
            ord_lines = []
            
            def imp_cb(ea, name, ordinal):
                if ordinal and ordinal > 0:
                    ord_lines.append(f"{hex(ea)}  ord={ordinal}  {name or f'Ordinal_{ordinal}'}")
                return True
            
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if query and query.lower() not in mod_name.lower():
                    continue
                ida_nalt.enum_import_names(i, imp_cb)
            
            page = ord_lines[offset:offset + count] if count != 0 else ord_lines[offset:]
            return {"ok": True, "ordinal_imports": "\n".join(page), "total": len(ord_lines), "offset": offset, "count": len(page)}
        
        elif action == "api_sets":
            set_lines = []
            
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name and mod_name.lower().startswith('api-ms-'):
                    actual = "kernel32.dll"
                    if 'win-core' in mod_name.lower():
                        actual = "kernelbase.dll"
                    elif 'crt' in mod_name.lower():
                        actual = "ucrtbase.dll"
                    
                    set_lines.append(f"{mod_name}  -> {actual}")
            
            page = set_lines[offset:offset + count] if count != 0 else set_lines[offset:]
            return {"ok": True, "api_sets": "\n".join(page), "total": len(set_lines), "offset": offset, "count": len(page)}
        
        elif action == "resolve":
            if not addr:
                # Perform batch resolution of all imports
                resolve_lines = []
                nimps = ida_nalt.get_import_module_qty()
                for i in range(nimps):
                    mod_name = ida_nalt.get_import_module_name(i)
                    
                    def collect_cb(ea, name, ordinal):
                        resolve_lines.append(f"{hex(ea)}  {mod_name}  {name or f'ordinal_{ordinal}'}")
                        return len(resolve_lines) < (offset + count if count != 0 else 1000000)
                        
                    ida_nalt.enum_import_names(i, collect_cb)
                    if len(resolve_lines) >= 100:
                        break
                page = resolve_lines[offset:offset + count] if count != 0 else resolve_lines[offset:]
                return {"ok": True, "resolved": "\n".join(page), "total": len(resolve_lines), "offset": offset, "count": len(page)}

            ea, err = validate_addr(addr)
            if err: return err
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
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "dll": module,
                "type": "import" if module else "unknown"
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 33. COMMENTS_AI - AI-Optimized Comment Management
# ============================================================================
