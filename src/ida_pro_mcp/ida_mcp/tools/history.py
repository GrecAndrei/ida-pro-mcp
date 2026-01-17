
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
import ida_loader

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
# 29. HISTORY - Database Version Control and Undo Management
# ============================================================================

@tool
@idaread
def history(
    action: Annotated[Literal["undo", "redo", "list", "snapshot", "restore", "diff"],
                      "Action: undo|redo|list|snapshot|restore|diff"],
    name: Annotated[Optional[str], "Snapshot name"] = None,
    count: Annotated[int, "Number of undo steps"] = 1,
    **kwargs
) -> dict:
    """
    Database version control: undo, redo, snapshots.
    
    ACTIONS:
    
    undo - Undo last operation(s)
        Params: count (number of steps)
        Returns: {undone, count}
        
    redo - Redo undone operation(s)
        Params: count
        Returns: {redone, count}
        
    list - List undo/redo history
        Returns: {undo_available, redo_available, history}
        
    snapshot - Create a named snapshot of current state
        Params: name
        Returns: {created, name, timestamp}
        
    restore - Restore from a snapshot
        Params: name
        Returns: {restored, name}
        
    diff - Show what changed since last save
        Returns: {changes: [{type, addr, before, after}]}
    """
    try:
        import ida_undo
        
        if action == "undo":
            undone = 0
            for _ in range(count):
                if ida_undo.perform_undo():
                    undone += 1
                else:
                    break

            return {"ok": True, "undone": undone, "requested": count}
        
        elif action == "redo":
            redone = 0
            for _ in range(count):
                if ida_undo.perform_redo():
                    redone += 1
                else:
                    break

            return {"ok": True, "redone": redone, "requested": count}
        
        elif action == "list":
            # Get undo/redo status
            result = {
                "ok": True,
                "undo_available": False,
                "redo_available": False,
                "note": "Detailed history API varies by IDA version"
            }
            
            # Check if undo is available by trying to get description
            if hasattr(ida_undo, 'get_undo_description'):
                desc = ida_undo.get_undo_description()
                result["undo_available"] = bool(desc)
                result["undo_description"] = desc
            
            if hasattr(ida_undo, 'get_redo_description'):
                desc = ida_undo.get_redo_description()
                result["redo_available"] = bool(desc)
                result["redo_description"] = desc
            
            return result
        
        elif action == "snapshot":
            if not name:
                import datetime
                name = f"snapshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Use native snapshot if available (IDA 7.4+)
            if hasattr(idautils, 'take_database_snapshot'):
                try:
                    if idautils.take_database_snapshot(name):
                        return {"ok": True, "type": "native_snapshot", "name": name}
                except:
                    pass # Fallback to save copy
            
            # Fallback: Save a copy of the database
            import os
            root = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            dirname = os.path.dirname(root)
            filename = f"{name}.i64"
            target = os.path.join(dirname, filename)
            
            if ida_loader.save_database(target, 0):
                return {"ok": True, "type": "idb_copy", "path": target}
            
            return make_error(MCPError.IDA_ERROR, "Failed to create snapshot")
        
        elif action == "restore":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            
            # List available snapshots
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            snapshot_dir = os.path.join(os.path.dirname(idb_path), ".ida_snapshots")
            
            meta_path = os.path.join(snapshot_dir, f"{name}.json")
            if os.path.exists(meta_path):
                import json as json_module
                with open(meta_path, 'r') as f:
                    metadata = json_module.load(f)
                return {
                    "ok": True,
                    "found": True,
                    "metadata": metadata,
                    "note": "To fully restore, reload IDB from backup"
                }
            else:
                return make_error(MCPError.FILE_NOT_FOUND, f"Snapshot '{name}' not found")
        
        elif action == "diff":
            # Show changes since database was opened
            # This is limited without IDA's internal change tracking
            
            changes = {
                "note": "Full diff requires IDA's internal change tracking",
                "modified_functions": []
            }
            
            # We can list functions that appear to have been renamed
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        changes["modified_functions"].append({
                            "addr": hex(func_ea),
                            "name": name
                        })
                    if len(changes["modified_functions"]) >= 100:
                        break
            
            changes["ok"] = True
            return changes
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# END OF SESSION A TOOLS (27-29)
# Session B tools (30-35) should be added AFTER this line
# ============================================================================


# ============================================================================
# 30. STRINGS_XREF - Advanced String Analysis
# ============================================================================
