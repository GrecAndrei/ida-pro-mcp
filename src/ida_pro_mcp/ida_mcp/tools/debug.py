
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 9. DEBUG - Debugger operations
# ============================================================================

@tool
@unsafe
@idawrite
def debug(
    action: Annotated[Literal[
        "start", "stop", "continue", "step_into", "step_over", "run_to", "run_until",
        "breakpoints", "add_bp", "del_bp", "enable_bp",
        "regs", "set_reg", "threads", "modules", "callstack", "read_mem", "write_mem"
    ], "Action"],
    addr: Annotated[Optional[str], "Address (for run_to/run_until)"] = None,
    condition: Annotated[Optional[str], "Python expression for run_until (e.g. 'cpu.rax == 5')"] = None,
    reg: Annotated[Optional[str], "Register name (for set_reg)"] = None,
    value: Annotated[Optional[Union[str, int]], "Register value (for set_reg)"] = None,
    size: Annotated[int, "Size for read_mem"] = 16,
    data: Annotated[Optional[str], "Hex data for write_mem"] = None,
    enabled: Annotated[bool, "Enable/disable for enable_bp"] = True,
    tid: Annotated[Optional[int], "Thread ID for regs/threads"] = None,
    **kwargs
) -> dict:
    """
    Debugger control: process state, breakpoints, registers, memory.
    
    Actions:
    - start: Launch the debugger/process.
    - stop: Terminate the process.
    - continue: Resume execution.
    - step_into/step_over: Single step execution.
    - run_to: Execute until `addr` is reached (hardware BP).
    - run_until: Step automatically until `addr` is hit OR `condition` is true.
    - breakpoints: List current breakpoints.
    - add_bp/del_bp: Add or remove software breakpoints.
    - enable_bp: Enable/disable an existing breakpoint.
    - regs: Get current register values.
    - set_reg: Set a register value (requires active debugger).
    - threads: List all process threads.
    - modules: List all loaded modules.
    - callstack: Get the current thread's call stack.
    - read_mem/write_mem: Read/write memory in the debugged process.
    """
    try:
        import ida_dbg
        import ida_idd
        
        if action == "start":
            if ida_dbg.start_process(): return {"ok": True}
            return make_error(MCPError.IDA_ERROR, "Failed to start debugger")
        
        elif action == "stop":
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            ida_dbg.exit_process()
            return {"ok": True}
        
        elif action == "continue":
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            ida_dbg.continue_process()
            return {"ok": True}
        
        elif action == "step_into":
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            ida_dbg.step_into()
            return {"ok": True}
        
        elif action == "step_over":
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            ida_dbg.step_over()
            return {"ok": True}
        
        elif action == "run_to":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            ea, err = validate_addr(addr)
            if err: return err
            ida_dbg.run_to(ea)
            return {"ok": True, "addr": hex(ea)}

        elif action == "run_until":
            # Autopilot debugging loop
            if not ida_dbg.is_debugger_on(): return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger not running")
            
            target_ea = None
            if addr:
                target_ea, err = validate_addr(addr)
                if err: return err

            # We limit steps to prevent infinite loops (e.g. 500 steps max per call)
            max_steps = 500
            steps = 0
            
            # Simple wrapper to eval python expression with access to ida_dbg
            def check_condition(expr):
                # Expose a simple 'cpu' object for registers
                class CPU:
                    def __getattr__(self, name):
                        return ida_dbg.get_reg_val(name)
                return eval(expr, {"cpu": CPU(), "ida_dbg": ida_dbg, "idc": idc})

            while steps < max_steps:
                ida_dbg.step_over()
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1) # Wait until step finishes
                steps += 1
                
                # Check Address
                curr_ea = ida_dbg.get_ip_val()
                if target_ea and curr_ea == target_ea:
                    return {"ok": True, "reason": "address_reached", "addr": hex(curr_ea), "steps": steps}
                
                # Check Condition
                if condition:
                    try:
                        if check_condition(condition):
                            return {"ok": True, "reason": "condition_met", "addr": hex(curr_ea), "steps": steps}
                    except Exception as e:
                        return make_error(MCPError.IDA_ERROR, f"Condition error: {e}")
            
            return {"ok": True, "reason": "step_limit_reached", "addr": hex(ida_dbg.get_ip_val()), "steps": steps}
        
        elif action == "breakpoints":
            bps = []
            for i in range(ida_dbg.get_bpt_qty()):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.getn_bpt(i, bpt):
                    bps.append({"addr": hex(bpt.ea), "enabled": bpt.is_enabled(), "type": bpt.type})
            return {"ok": True, "breakpoints": bps}
        
        elif action == "add_bp":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_code=True)
            if err: return err
            if ida_dbg.add_bpt(ea, 0, 0): return {"ok": True, "addr": hex(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to add breakpoint")
        
        elif action == "del_bp":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            if ida_dbg.del_bpt(ea): return {"ok": True, "addr": hex(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to delete breakpoint")
        
        elif action == "enable_bp":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            if ida_dbg.enable_bpt(ea, enabled): return {"ok": True, "addr": hex(ea), "enabled": enabled}
            return make_error(MCPError.IDA_ERROR, "Failed to enable/disable breakpoint")
        
        elif action == "regs":
            err = check_debugger(require_active=True)
            if err: return err
            target_tid = tid if tid is not None else ida_dbg.get_current_thread()
            dbg = ida_idd.get_dbg()
            if not dbg: return make_error(MCPError.IDA_ERROR, "No debugger info")
            regvals = ida_dbg.get_reg_vals(target_tid)
            if not regvals: return make_error(MCPError.IDA_ERROR, f"Failed to get registers for thread {target_tid}")
            regs = {}
            for i, rv in enumerate(regvals):
                 if i < dbg.nregs:
                     reg_info = dbg.regs(i)
                     if not reg_info: continue
                     name = reg_info.name
                     try:
                         val = rv.pyval(reg_info.dtype)
                         regs[name] = hex(val) if isinstance(val, int) else str(val)
                     except Exception: regs[name] = "?"
            return {"ok": True, "registers": regs, "tid": target_tid}

        elif action == "set_reg":
            if not reg or value is None: return make_error(MCPError.INVALID_ARGS, "reg and value required")
            err = check_debugger(require_active=True)
            if err: return err
            
            val = int(str(value), 0) if isinstance(value, str) else value
            if ida_dbg.set_reg_val(reg, val):
                return {"ok": True, "reg": reg, "value": hex(val)}
            return make_error(MCPError.IDA_ERROR, f"Failed to set register {reg}")

        elif action == "threads":
            err = check_debugger(require_active=True)
            if err: return err
            threads = []
            for i in range(ida_dbg.get_thread_qty()):
                tid_val = ida_dbg.getn_thread(i)
                name = ida_dbg.get_thread_name(tid_val)
                threads.append({"tid": tid_val, "name": name or ""})
            return {"ok": True, "threads": threads}

        elif action == "modules":
            err = check_debugger(require_active=True)
            if err: return err
            modules = []
            mod = ida_idd.modinfo_t()
            if ida_dbg.get_first_module(mod):
                while True:
                    modules.append({"name": mod.name, "base": hex(mod.base), "size": hex(mod.size)})
                    if not ida_dbg.get_next_module(mod): break
            return {"ok": True, "modules": modules}
        
        elif action == "callstack":
            err = check_debugger(require_active=True)
            if err: return err
            if hasattr(ida_dbg, 'collect_stack_trace'):
                stack = []
                frames = ida_dbg.collect_stack_trace(ida_dbg.get_current_thread())
                if frames:
                    for frame in frames:
                        stack.append({"addr": hex(frame.ea), "func": idc.get_name(frame.ea) or ""})
                return {"ok": True, "callstack": stack}
            return make_error(MCPError.NOT_IMPLEMENTED, "Callstack API not available")
        
        elif action == "read_mem":
            err = check_debugger(require_active=True)
            if err: return err
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            data = ida_dbg.read_dbg_memory(ea, size)
            if data: return {"ok": True, "addr": hex(ea), "data": " ".join(f"{b:02x}" for b in data)}
            return make_error(MCPError.IDA_ERROR, "Failed to read memory")
        
        elif action == "write_mem":
            err = check_debugger(require_active=True)
            if err: return err
            if not addr or not data: return make_error(MCPError.INVALID_ARGS, "addr and data required")
            ea, err = validate_addr(addr)
            if err: return err
            try: bytes_data = bytes.fromhex(data.replace(" ", ""))
            except Exception: return make_error(MCPError.INVALID_ARGS, "Invalid hex data")
            if ida_dbg.write_dbg_memory(ea, bytes_data): return {"ok": True, "addr": hex(ea), "size": len(bytes_data)}
            return make_error(MCPError.IDA_ERROR, "Failed to write memory")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 10. FUNCS - Function management
# ============================================================================
