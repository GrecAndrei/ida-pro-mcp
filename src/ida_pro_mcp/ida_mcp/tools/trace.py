
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
            changed = {}
            unsupported = []

            def _try_set_via_func(fn_names: list[str], value: bool) -> bool:
                for fn_name in fn_names:
                    fn = getattr(ida_dbg, fn_name, None)
                    if callable(fn):
                        fn(value)
                        return True
                return False

            def _try_set_via_flags(flag_names: list[str], value: bool) -> bool:
                get_opts = getattr(ida_dbg, "get_step_trace_options", None)
                set_opts = getattr(ida_dbg, "set_step_trace_options", None)
                if not callable(get_opts) or not callable(set_opts):
                    return False
                opts = get_opts()
                for flag_name in flag_names:
                    flag = getattr(ida_dbg, flag_name, None)
                    if isinstance(flag, int):
                        if value:
                            opts |= flag
                        else:
                            opts &= ~flag
                        set_opts(opts)
                        return True
                return False

            if enable_insn is not None:
                applied = _try_set_via_func(["enable_insn_trace", "enable_step_trace"], bool(enable_insn))
                if not applied:
                    applied = _try_set_via_flags(
                        ["ST_TRACE_INSN", "ST_TRACE_INSTRUCTIONS", "ST_INSN_TRACE", "ST_OVER_LIB_FUNC"],
                        bool(enable_insn),
                    )
                if applied:
                    changed["enable_insn"] = bool(enable_insn)
                else:
                    unsupported.append("enable_insn")

            if enable_func is not None:
                applied = _try_set_via_func(["enable_func_trace", "enable_function_trace"], bool(enable_func))
                if not applied:
                    applied = _try_set_via_flags(
                        ["ST_TRACE_FUNC", "ST_TRACE_FUNCTIONS", "ST_FUNC_TRACE"],
                        bool(enable_func),
                    )
                if applied:
                    changed["enable_func"] = bool(enable_func)
                else:
                    unsupported.append("enable_func")

            if enable_bblk is not None:
                applied = _try_set_via_func(["enable_bblk_trace", "enable_basic_block_trace"], bool(enable_bblk))
                if not applied:
                    applied = _try_set_via_flags(
                        ["ST_TRACE_BBLK", "ST_TRACE_BASIC_BLOCKS", "ST_BBLK_TRACE"],
                        bool(enable_bblk),
                    )
                if applied:
                    changed["enable_bblk"] = bool(enable_bblk)
                else:
                    unsupported.append("enable_bblk")

            if not changed and unsupported:
                return make_error(
                    MCPError.NOT_IMPLEMENTED,
                    "Trace option control is not supported by this IDA build",
                    details={"unsupported": unsupported},
                )

            result = {"ok": True, "changed": changed}
            if unsupported:
                result["warning"] = f"Unsupported options: {', '.join(unsupported)}"
            get_opts = getattr(ida_dbg, "get_step_trace_options", None)
            if callable(get_opts):
                result["options"] = get_opts()
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 15. FIXUPS - Relocation/fixup operations
# ============================================================================
