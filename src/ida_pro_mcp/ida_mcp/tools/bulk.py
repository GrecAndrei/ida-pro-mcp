
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
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================

@tool
@unsafe
@idawrite
def bulk(
    action: Annotated[Literal["rename", "comment", "apply_type", "rename_stack", "import_annotations", "export_annotations"],
                      "Action: rename|comment|apply_type|rename_stack|import_annotations|export_annotations"],
    items: Annotated[Optional[list[dict]], "List of {addr, value} dicts for bulk operations"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
    **kwargs
) -> dict:
    """
    Bulk operations for efficient multi-target modifications.
    
    Actions:
    - rename: Bulk rename [{addr, value}, ...]
    - comment: Bulk add comments [{addr, value, type?}, ...]
    - apply_type: Bulk apply types [{addr, value}, ...]
    - rename_stack: Bulk rename stack variables in a function [{addr, old, new}, ...]
    - import_annotations: Load names/comments from JSON file.
    - export_annotations: Save all names/comments to JSON file.
    """
    try:
        if action == "rename":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"))
                    if err: 
                        failed.append({"addr": item.get("addr"), "error": "Invalid address"})
                        continue
                    if idc.set_name(ea, item.get("value"), ida_name.SN_FORCE | ida_name.SN_NOWARN): success += 1
                    else: failed.append({"addr": hex(ea), "error": "set_name failed"})
                except Exception as e: failed.append({"addr": item.get("addr"), "error": str(e)})
            return {"ok": True, "success": success, "failed": len(failed), "errors": failed[:10]}
        
        elif action == "comment":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"))
                    if err: continue
                    idc.set_cmt(ea, item.get("value"), 1 if item.get("type") == "repeatable" else 0)
                    success += 1
                except: pass
            return {"ok": True, "success": success}
        
        elif action == "rename_stack":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"), require_func=True)
                    if err: continue
                    # item: {addr, old, new}
                    if idc.define_local_var(ea, ea, item["old"], item["new"]): success += 1
                    else: failed.append({"addr": hex(ea), "var": item["old"], "error": "Failed"})
                except Exception as e: failed.append({"error": str(e)})
            return {"ok": True, "success": success, "failed": failed}

        elif action == "export_annotations":
            annotations = {"names": [], "comments": []}
            # Fast name export
            for ea, name in idautils.Names():
                if not name.startswith(("sub_", "loc_", "unk_", "off_")):
                    annotations["names"].append({"addr": hex(ea), "name": name})
            
            # Fast comment export via heads
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    cmt = idc.get_cmt(head, 0) or idc.get_cmt(head, 1)
                    if cmt:
                        annotations["comments"].append({"addr": hex(head), "comment": cmt})
            
            if path:
                path, err = validate_path_safe(path)
                if err: return err
                import json
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(annotations, f, indent=2)
                return {"ok": True, "path": path, "counts": {k: len(v) for k, v in annotations.items()}}
            return {"ok": True, "annotations": annotations}
        
        elif action == "import_annotations":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            if not os.path.exists(path): return make_error(MCPError.FILE_NOT_FOUND, path)
            import json
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            n_applied, c_applied = 0, 0
            for item in data.get("names", []):
                try:
                    ea = parse_address(item["addr"])
                    if idc.set_name(ea, item["name"], ida_name.SN_FORCE): n_applied += 1
                except: pass
            for item in data.get("comments", []):
                try:
                    ea = parse_address(item["addr"])
                    if idc.set_cmt(ea, item["comment"], 0): c_applied += 1
                except: pass
            return {"ok": True, "names": n_applied, "comments": c_applied}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 21. CTREE - Hex-Rays AST/CTree Access for Deep Decompiler Analysis
# ============================================================================
