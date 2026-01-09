from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idc
import ida_loader

# Infrastructure discovery
try:
    # Package mode
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
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
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# ANALYSIS - Loader/processor options and reanalysis
# ============================================================================

@tool
@idawrite
def analysis(
    action: Annotated[Literal["get_options", "set_options", "set_processor", "set_loader_options", "reanalyze"],
                      "Action: get_options|set_options|set_processor|set_loader_options|reanalyze"],
    options: Annotated[Optional[dict], "Options dict for set_options"] = None,
    processor: Annotated[Optional[str], "Processor name for set_processor"] = None,
    flags: Annotated[Optional[int], "Processor flags (idaapi.SETPROC_*)"] = None,
    loader: Annotated[Optional[str], "Loader name (for set_loader_options)"] = None,
    value: Annotated[Optional[str], "Loader options string (for set_loader_options)"] = None,
    start: Annotated[Optional[str], "Start address for reanalysis"] = None,
    end: Annotated[Optional[str], "End address for reanalysis"] = None,
    **kwargs
) -> dict:
    """
    Control analysis options and reanalysis behavior.

    Actions:
    - get_options: Return key analysis/processor settings.
    - set_options: Set select info options (baseaddr, start_ea, min_ea, max_ea).
    - set_processor: Switch processor type.
    - set_loader_options: Apply loader-specific options string.
    - reanalyze: Re-run auto-analysis over a range.
    """
    try:
        if action == "get_options":
            inf = None
            if hasattr(idaapi, "get_inf_structure"):
                try:
                    inf = idaapi.get_inf_structure()
                except Exception:
                    inf = None
            def safe_inf_attr(attr, default=None):
                if inf is not None and hasattr(inf, attr):
                    return getattr(inf, attr)
                return default
            def safe_idc_attr(name, default=None):
                key = getattr(idc, name, None)
                if key is None:
                    return default
                try:
                    return idc.get_inf_attr(key)
                except Exception:
                    return default

            procname = safe_inf_attr("procname", None) or safe_idc_attr("INF_PROCNAME", "")
            filetype = safe_inf_attr("filetype", None) or safe_idc_attr("INF_FILETYPE", None)
            is_64bit = inf.is_64bit() if inf and hasattr(inf, "is_64bit") else bool(safe_idc_attr("INF_LFLAGS", 0) & 0x100)
            is_be = inf.is_be() if inf and hasattr(inf, "is_be") else False

            return {
                "ok": True,
                "procname": procname,
                "filetype": filetype,
                "is_64bit": is_64bit,
                "is_be": is_be,
                "start_ea": hex(idaapi.inf_get_start_ea()) if hasattr(idaapi, "inf_get_start_ea") else None,
                "min_ea": hex(idaapi.inf_get_min_ea()) if hasattr(idaapi, "inf_get_min_ea") else None,
                "max_ea": hex(idaapi.inf_get_max_ea()) if hasattr(idaapi, "inf_get_max_ea") else None,
            }

        if action == "set_options":
            if not options or not isinstance(options, dict):
                return make_error(MCPError.INVALID_ARGS, "options dict required")
            mapping = {
                "baseaddr": getattr(idc, "INF_BASEADDR", None),
                "start_ea": getattr(idc, "INF_START_EA", None),
                "min_ea": getattr(idc, "INF_MIN_EA", None),
                "max_ea": getattr(idc, "INF_MAX_EA", None),
            }
            applied = {}
            for key, val in options.items():
                if key not in mapping or mapping[key] is None:
                    continue
                idc.set_inf_attr(mapping[key], int(val))
                applied[key] = int(val)
            return {"ok": True, "applied": applied}

        if action == "set_processor":
            if not processor:
                return make_error(MCPError.INVALID_ARGS, "processor required")
            proc_flags = flags if flags is not None else idaapi.SETPROC_LOADER
            ok = idaapi.set_processor_type(processor, proc_flags)
            return {"ok": True, "processor": processor, "result": ok}

        if action == "set_loader_options":
            if not loader or value is None:
                return make_error(MCPError.INVALID_ARGS, "loader and value required")
            if not hasattr(ida_loader, "set_loader_options"):
                return make_error(MCPError.NOT_IMPLEMENTED, "set_loader_options not supported in this IDA version")
            ok = ida_loader.set_loader_options(loader, value)
            return {"ok": True, "loader": loader, "result": ok}

        if action == "reanalyze":
            if start and end:
                s_ea, err = validate_addr(start)
                if err: return err
                e_ea, err = validate_addr(end)
                if err: return err
            else:
                s_ea = idaapi.inf_get_min_ea()
                e_ea = idaapi.inf_get_max_ea()
            if hasattr(idaapi, "auto_mark_range"):
                idaapi.auto_mark_range(s_ea, e_ea, idaapi.AU_FINAL)
                idaapi.auto_wait()
                return {"ok": True, "start": hex(s_ea), "end": hex(e_ea)}
            return make_error(MCPError.NOT_IMPLEMENTED, "auto_mark_range not available")

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
