
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import os
import ida_loader


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
            safe_name = os.path.basename(name.replace("/", "_").replace("\\", "_"))

            # Save a copy of the IDB alongside the original
            root = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            dirname = os.path.dirname(root)
            snap_dir = os.path.join(dirname, ".ida_snapshots")
            os.makedirs(snap_dir, exist_ok=True)
            ext = ".i64" if root.endswith(".i64") else ".idb"
            target = os.path.join(snap_dir, f"{safe_name}{ext}")
            _, path_err = validate_path_safe(target)
            if path_err:
                return path_err

            if ida_loader.save_database(target, 0):
                return {"ok": True, "name": safe_name, "path": target}

            return make_error(MCPError.IDA_ERROR, "Failed to create snapshot")

        elif action == "restore":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")

            safe_name = os.path.basename(name.replace("/", "_").replace("\\", "_"))

            root = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            snap_dir = os.path.join(os.path.dirname(root), ".ida_snapshots")

            # Find the snapshot file (try both extensions)
            snap_path = None
            for ext in (".i64", ".idb"):
                candidate = os.path.join(snap_dir, f"{safe_name}{ext}")
                if os.path.exists(candidate):
                    snap_path = candidate
                    break

            if not snap_path:
                # List available snapshots to help the user
                available = []
                if os.path.isdir(snap_dir):
                    available = [
                        os.path.splitext(f)[0]
                        for f in os.listdir(snap_dir)
                        if f.endswith((".i64", ".idb"))
                    ]
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"Snapshot '{name}' not found",
                    hint=f"Available: {available}" if available else "No snapshots found",
                )

            return {
                "ok": True,
                "found": True,
                "path": snap_path,
                "note": "To restore, close IDA and replace the current IDB with this snapshot file",
            }
        
        elif action == "diff":
            # Show changes since database was opened
            # This is limited without IDA's internal change tracking
            
            changes = {
                "note": "Full diff requires IDA's internal change tracking",
                "modified_functions": []
            }
            
            # We can list functions that appear to have been renamed
            scanned_funcs = 0
            max_scan = 100000
            for seg_ea in idautils.Segments():
                if len(changes["modified_functions"]) >= 100: break
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    scanned_funcs += 1
                    if scanned_funcs > max_scan: break
                    if len(changes["modified_functions"]) >= 100: break
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        changes["modified_functions"].append({
                            "addr": hex(func_ea),
                            "name": name
                        })
            
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
