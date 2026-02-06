
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 14. TRACE - Trace operations
# ============================================================================

@tool
@unsafe
@idawrite
def trace(
    action: Annotated[Literal["get", "clear", "set_options"], "Action: get|clear|set_options"],
    addr: Annotated[Optional[str], "Address filter"] = None,
    count: Annotated[int, "Max trace entries to return"] = 1000,
    enable_insn: Annotated[Optional[bool], "Enable instruction tracing"] = None,
    enable_func: Annotated[Optional[bool], "Enable function tracing"] = None,
    enable_bblk: Annotated[Optional[bool], "Enable basic block tracing"] = None,
    **kwargs
) -> dict:
    """Trace operations: get trace data, clear, set options"""
    try:
        import ida_dbg
        
        if action == "get":
            err = check_debugger(require_active=True)
            if err: return err

            traces = []
            # tev_t removed in IDA 9, check for availability
            if not hasattr(ida_dbg, 'tev_t'):
                return make_error(MCPError.NOT_IMPLEMENTED, "Trace API not available in this IDA version")
            tev = ida_dbg.tev_t()
            for i in range(min(ida_dbg.get_tev_qty(), count)):
                if ida_dbg.get_tev_info(i, tev):
                    entry = {"idx": i, "addr": hex(tev.ea), "type": tev.type}
                    if addr and hex(tev.ea) != addr:
                        continue
                    traces.append(entry)
            return {"ok": True, "traces": traces, "count": len(traces)}
        
        elif action == "clear":
            err = check_debugger(require_active=True)
            if err: return err
            ida_dbg.clear_trace()
            return {"ok": True}
        
        elif action == "set_options":
            err = check_debugger(require_active=True)
            if err: return err
            # Set trace options
            opts = ida_dbg.get_step_trace_options()
            if enable_insn is not None:
                if enable_insn:
                    opts |= ida_dbg.ST_OVER_LIB_FUNC
                else:
                    opts &= ~ida_dbg.ST_OVER_LIB_FUNC
            ida_dbg.set_step_trace_options(opts)
            return {"ok": True, "options": opts}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 15. FIXUPS - Relocation/fixup operations
# ============================================================================
