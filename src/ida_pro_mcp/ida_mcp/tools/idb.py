from typing import Annotated, Optional, Literal, Union, Any
import os
import idaapi
import idautils
import idc
import ida_nalt
import ida_segment
import ida_funcs
import ida_entry

try:
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from error_handling import MCPError, make_error, handle_error
except ImportError:
    from ..rpc import tool, unsafe
    from ..sync import idaread, idawrite, IDAError
    from ..error_handling import MCPError, make_error, handle_error

def _get_path(module, names):
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)()
    return None

@tool
def idb(
    action: Literal["meta", "summary", "stats", "bookmarks", "segments", "entrypoints"] = "summary",
    args: Optional[dict] = None
) -> Any:
    """Forensic analysis of the IDA database."""
    try:
        if action == "meta": return {"ok": True, **idb_meta()}
        if action == "summary": return {"ok": True, **idb_summary()}
        if action == "segments": return {"ok": True, "segments": idb_segments()}
        if action == "entrypoints": return {"ok": True, "entrypoints": idb_entrypoints()}
        if action == "bookmarks":
            # Inline bookmarks implementation (bookmarks.py doesn't exist)
            import ida_moves
            bookmarks = []
            try:
                # IDA 9.x uses ida_moves for bookmarks
                for i in range(1000):  # Max 1000 bookmarks
                    desc, ea = idc.get_bookmark_desc(i), idc.get_bookmark(i)
                    if ea == idaapi.BADADDR:
                        break
                    bookmarks.append({"index": i, "addr": hex(ea), "desc": desc or ""})
            except AttributeError:
                # Fallback - try different API
                pass
            return {"ok": True, "bookmarks": bookmarks, "count": len(bookmarks)}
        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e, "idb")

@idaread
def idb_meta():
    return {
        "binary_path": _get_path(ida_nalt, ["get_input_file_path"]) or _get_path(idaapi, ["get_input_file_path"]) or "unknown",
        "idb_path": _get_path(idaapi, ["get_idb_path"]) or _get_path(idc, ["get_idb_path"]) or "unknown",
        "processor": idc.get_inf_attr(idc.INF_PROCNAME),
        "file_type": idc.get_inf_attr(idc.INF_FILETYPE),
        "bitness": 64 if (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100) else 32,
        "image_base": hex(idc.get_inf_attr(idc.INF_BASEADDR))
    }

@idaread
def idb_segments():
    segments = []
    # Force a refresh of segments in case analysis just finished
    for ea in idautils.Segments():
        segments.append({
            "name": idc.get_segm_name(ea),
            "start": hex(ea),
            "end": hex(idc.get_segm_end(ea)),
            "size": hex(idc.get_segm_end(ea) - ea)
        })
    return segments

@idaread
def idb_entrypoints():
    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ord_val = ida_entry.get_entry_ordinal(i)
        # IDA 9.2 uses get_entry() not get_entry_ea()
        ea = ida_entry.get_entry(ord_val)
        name = ida_entry.get_entry_name(ord_val)
        entries.append({"name": name, "address": hex(ea), "ordinal": ord_val})
    return entries

@idaread
def idb_summary():
    return {
        "functions": len(list(idautils.Functions())),
        "segments": len(list(idautils.Segments())),
        "analysis_ok": idaapi.auto_is_ok()
    }
