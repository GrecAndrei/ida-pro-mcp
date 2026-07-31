
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import contextlib
import json
import os
import time
from collections import OrderedDict

# ============================================================================
# DEBUG - Debugger operations
# ============================================================================

# Cache for register snapshots (used by reg_diff)
_REG_SNAPSHOTS: OrderedDict[str, dict] = OrderedDict()
_MAX_REG_SNAPSHOTS = 50
_TRACE_HOOK = None
_TRACE_STATE = {"file": None, "count": 0, "max_insns": 50000}
_MEM_DIFF_SNAPSHOTS: Dict[Tuple[int, int], bytes] = {}
_MAX_MEM_DIFF_SNAPSHOTS = 128
_MAX_MEM_DIFF_SPAN = 0x10000
_BP_CONDITIONS: Dict[int, str] = {}
_BP_HOOK = None

_BPT_COND_ALLOWED = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_()[]=<>!&|+-*/%^~.,: \t")


class _TraceHooks(idaapi.DBG_Hooks):
    def dbg_trace(self, tid, ea):
        try:
            if not _TRACE_STATE.get("file"):
                return 0
            if int(_TRACE_STATE.get("count", 0)) >= int(_TRACE_STATE.get("max_insns", 50000)):
                return 0
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "").strip()
            rec = {"ea": hex(int(ea)), "insn": line, "regs": {}}
            try:
                import ida_dbg
                for rname in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP", "EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "EIP"):
                    try:
                        rv = ida_dbg.get_reg_val(rname)
                        if rv is not None:
                            rec["regs"][rname.lower()] = int(rv)
                    except Exception:
                        pass
            except Exception:
                pass
            fh = _TRACE_STATE.get("file")
            fh.write(json.dumps(rec) + "\n")
            _TRACE_STATE["count"] = int(_TRACE_STATE.get("count", 0)) + 1
        except Exception:
            pass
        return 0


class _BreakpointHooks(idaapi.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        try:
            cond = _BP_CONDITIONS.get(int(ea))
            if not cond:
                # No custom condition — pause normally.
                return 1
            # Restricted eval via IDC expression evaluator as requested.
            try:
                ok = bool(idc.eval_idc(cond))
            except Exception:
                ok = False
            if not ok:
                import ida_dbg
                ida_dbg.continue_process()
                return 0
            return 1
        except Exception:
            return 1

def _is_safe_bp_condition(expr: str) -> bool:
    if not isinstance(expr, str):
        return False
    txt = expr.strip()
    if not txt or len(txt) > 256:
        return False
    return all(ch in _BPT_COND_ALLOWED for ch in txt)


def _wait_for_suspend(timeout_ms: int = 3000):
    try:
        import ida_dbg
    except Exception:
        return None
    wait_fn = getattr(ida_dbg, "wait_for_next_event", None)
    if not callable(wait_fn):
        return None
    mask = getattr(ida_dbg, "WFNE_SUSP", None)
    if mask is None:
        mask = getattr(ida_dbg, "WFNE_ANY", 0)
    try:
        return wait_fn(mask, timeout_ms)
    except Exception:
        return None


def _debug_state():
    try:
        import ida_dbg
    except Exception:
        return False, False, None, None
    is_on = bool(getattr(ida_dbg, "is_debugger_on", lambda: False)())
    state = None
    state_name = None
    get_state = getattr(ida_dbg, "get_process_state", None)
    if callable(get_state):
        try:
            state = get_state()
        except Exception:
            state = None
    if state is not None:
        for name in dir(ida_dbg):
            if not name.startswith("DSTATE_"):
                continue
            val = getattr(ida_dbg, name, None)
            if isinstance(val, int) and val == state:
                state_name = name
                break
    inactive = {
        getattr(ida_dbg, "DSTATE_NOTASK", None),
        getattr(ida_dbg, "DSTATE_END", None),
        getattr(ida_dbg, "DSTATE_PROC_EXIT", None),
    }
    inactive.discard(None)
    active = is_on or (state is not None and state not in inactive)
    return active, is_on, state, state_name


def _debug_active():
    return _debug_state()[0]


def _debug_not_running():
    return {"ok": True, "note": "Debugger is not running in headless mode", "hint": "Debugger control is not a public operation; use ida_python (ida_dbg) if code execution is authorized"}


def _get_reg_dict(tid=None):
    """Get registers as a plain dict."""
    import ida_dbg
    import ida_idd
    target_tid = tid if tid is not None else ida_dbg.get_current_thread()
    dbg = ida_idd.get_dbg()
    if not dbg:
        return make_error(
            MCPError.DEBUGGER_NOT_RUNNING,
            "No debugger backend attached",
        )
    regvals = ida_dbg.get_reg_vals(target_tid)
    if not regvals:
        return make_error(
            MCPError.DEBUGGER_REGISTER_ERROR,
            "Could not read register values (debugger not running?)",
        )
    regs = {}
    for i, rv in enumerate(regvals):
        if i < dbg.nregs:
            reg_info = dbg.regs(i)
            if not reg_info:
                continue
            name = reg_info.name
            try:
                val = rv.pyval(reg_info.dtype)
                regs[name] = val if isinstance(val, int) else str(val)
            except Exception:
                regs[name] = None
    return regs


def _read_dbg_ptr(ea: int, size: int):
    """Read a pointer from debugged memory."""
    import ida_dbg
    raw = ida_dbg.read_dbg_memory(ea, size)
    if not raw or len(raw) < size:
        return None
    return int.from_bytes(raw[:size], "little")


def _get_ptr_size():
    """Get pointer size for current architecture."""
    try:
        return 8 if _inf_is_64bit() else 4
    except Exception:
        return 4


def _inject_blackboard_context(result, pc_str):
    """Inject blackboard entries for a given PC address into result dict."""
    try:
        try: from .blackboard import BlackboardStore
        except ImportError: from blackboard import BlackboardStore  # type: ignore[import-not-found]
        store = BlackboardStore()
        entries = store.list(addr=pc_str, limit=3)
        if entries:
            result["blackboard_context"] = [
                {"title": e["title"], "category": e["category"], "confidence": e["confidence"]}
                for e in entries
            ]
    except Exception:
        pass


@tool
@unsafe
@idawrite
def debug(
    action: Annotated[Literal[
        "status", "start", "stop", "continue", "step_into", "step_over", "run_to", "run_until",
        "breakpoints", "add_bp", "del_bp", "enable_bp", "add_hw_bp", "add_watch",
        "regs", "set_reg", "reg_diff", "snapshot_regs", "threads", "modules", "callstack",
        "read_mem", "write_mem", "search_mem", "stack_dump", "mem_map", "bp_context",
        "trace_start", "trace_stop", "trace_read", "mem_diff"
    ], "Action"],
    addr: Annotated[Optional[str], "Address (for run_to/run_until/bp/watch)"] = None,
    condition: Annotated[Optional[str], "Python expression for run_until (e.g. 'cpu.rax == 5')"] = None,
    reg: Annotated[Optional[str], "Register name (for set_reg/reg_diff)"] = None,
    value: Annotated[Optional[Union[str, int]], "Register value (for set_reg)"] = None,
    size: Annotated[int, "Size for read_mem/stack_dump"] = 16,
    data: Annotated[Optional[str], "Hex data for write_mem or pattern for search_mem"] = None,
    enabled: Annotated[bool, "Enable/disable for enable_bp"] = True,
    tid: Annotated[Optional[int], "Thread ID for regs/threads"] = None,
    snapshot_name: Annotated[Optional[str], "Name for register snapshot (for snapshot_regs/reg_diff)"] = None,
    access_type: Annotated[Literal["read", "write", "rw", "execute"], "Watchpoint access type (for add_watch)"] = "write",
    **kwargs
) -> dict:
    """
    Debugger control: process state, breakpoints, watchpoints, registers, memory.

    Actions:
    - start: Launch the debugger/process.
    - stop: Terminate the process.
    - continue: Resume execution.
    - step_into/step_over: Single step execution.
    - run_to: Execute until `addr` is reached (hardware BP).
    - run_until: Step automatically until `addr` is hit OR Python `condition` is true.
    - breakpoints: List current breakpoints.
    - add_bp/del_bp: Add/remove software breakpoints; use `idc_condition` kwarg
      (or legacy `condition`) for IDC expressions.
    - enable_bp: Enable/disable an existing breakpoint.
    - add_hw_bp: Add a hardware breakpoint at `addr`.
    - add_watch: Add a memory watchpoint at `addr` with `access_type`.
    - regs: Get current register values.
    - set_reg: Set a register value (requires active debugger).
    - snapshot_regs: Save current register state with a name.
    - reg_diff: Compare current registers to a named snapshot.
    - threads: List all process threads.
    - modules: List all loaded modules.
    - callstack: Get the current thread's call stack.
    - read_mem/write_mem: Read/write memory in the debugged process.
    - search_mem: Search for a byte pattern in debugged memory.
    - stack_dump: Dump the current stack (RSP/ESP-based).
    - mem_map: Show memory map of the debugged process.
    - bp_context: Query blackboard for entries related to the current PC/function.
    """
    global _TRACE_HOOK, _BP_HOOK
    try:
        import ida_dbg
        import ida_idd
        idc_condition = kwargs.get("idc_condition")

        if action == "status":
            active, is_on, state, state_name = _debug_state()
            result = {
                "ok": True,
                "active": bool(active),
                "is_debugger_on": bool(is_on),
                "state": state,
                "state_name": state_name,
            }
            if state_name and "SUSP" in state_name:
                try:
                    pc = ida_dbg.get_ip_val()
                    if pc:
                        result["pc"] = hex(pc)
                        _inject_blackboard_context(result, hex(pc))
                except Exception:
                    pass
            return result

        if action == "start":
            started = bool(ida_dbg.start_process())
            if not started and _debug_active():
                active, is_on, state, state_name = _debug_state()
                return {
                    "ok": True,
                    "already_running": True,
                    "debugger_on": is_on,
                    "process_active": active,
                    "state": state,
                    "state_name": state_name,
                }
            if not started:
                return make_error(MCPError.IDA_ERROR, "Failed to start debugger")

            evt = None
            deadline = time.time() + 6.0
            while time.time() < deadline:
                maybe_evt = _wait_for_suspend(500)
                if maybe_evt is not None:
                    evt = maybe_evt
                if _debug_active():
                    break

            active, is_on, state, state_name = _debug_state()
            if not active:
                return {
                    "ok": True,
                    "started": started,
                    "debugger_on": is_on,
                    "process_active": False,
                    "event": evt,
                    "state": state,
                    "state_name": state_name,
                    "warning": "Debugger start request succeeded, but process is not yet in an active/suspended state.",
                    "hint": "Try debug(action='continue') or set a breakpoint, then call debug(action='regs').",
                }
            return {
                "ok": True,
                "debugger_on": is_on,
                "process_active": active,
                "event": evt,
                "state": state,
                "state_name": state_name,
            }

        elif action == "stop":
            if not _debug_active():
                return _debug_not_running()
            ida_dbg.exit_process()
            return {"ok": True}

        elif action == "continue":
            if not _debug_active():
                return _debug_not_running()
            ida_dbg.continue_process()
            return {"ok": True}

        elif action == "step_into":
            if not _debug_active():
                return _debug_not_running()
            ida_dbg.step_into()
            result = {"ok": True}
            try:
                pc = ida_dbg.get_ip_val()
                if pc:
                    result["pc"] = hex(pc)
                    _inject_blackboard_context(result, hex(pc))
            except Exception:
                pass
            return result

        elif action == "step_over":
            if not _debug_active():
                return _debug_not_running()
            ida_dbg.step_over()
            result = {"ok": True}
            try:
                pc = ida_dbg.get_ip_val()
                if pc:
                    result["pc"] = hex(pc)
                    _inject_blackboard_context(result, hex(pc))
            except Exception:
                pass
            return result

        elif action == "run_to":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not _debug_active():
                return _debug_not_running()
            ea, err = validate_addr(addr)
            if err:
                return err
            ida_dbg.run_to(ea)
            return {"ok": True, "addr": hex(ea)}

        elif action == "run_until":
            if not _debug_active():
                return _debug_not_running()

            target_ea = None
            if addr:
                target_ea, err = validate_addr(addr)
                if err:
                    return err

            max_steps = 500
            steps = 0

            class CPU:
                _SAFE_REG_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")
                def __getattr__(self, name):
                    if not self._SAFE_REG_RE.match(name):
                        raise AttributeError(f"Invalid register name: {name}")
                    return ida_dbg.get_reg_val(name)

            def check_condition(expr):
                # Security: only allow a very restricted set of operations.
                # Whitelist: alphanumeric, operators, parentheses, dots for cpu.xxx,
                # decimal/hex numbers, and whitespace.
                if not isinstance(expr, str) or len(expr) > 512:
                    raise ValueError("Condition too long or not a string")
                allowed = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.=<>!+-%*/&|~^ ")
                if not all(c in allowed for c in expr):
                    raise ValueError("Condition contains forbidden characters")
                # Only expose cpu (register reads) and basic math constants.
                safe_ns = {"cpu": CPU(), "True": True, "False": False, "None": None}
                return eval(expr, {"__builtins__": {}}, safe_ns)  # noqa: S307

            while steps < max_steps:
                ida_dbg.step_over()
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                steps += 1

                curr_ea = ida_dbg.get_ip_val()
                if target_ea and curr_ea == target_ea:
                    return {"ok": True, "reason": "address_reached", "addr": hex(curr_ea), "steps": steps}

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
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_code=True)
            if err:
                return err
            bp_cond = idc_condition if idc_condition is not None else condition
            if bp_cond is not None and not _is_safe_bp_condition(str(bp_cond)):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "idc_condition contains unsupported characters",
                    hint="Use a simple IDC expression (alnum/operators/whitespace only).",
                )
            if ida_dbg.add_bpt(ea, 0, 0):
                if bp_cond:
                    _BP_CONDITIONS[int(ea)] = str(bp_cond)
                    if _BP_HOOK is None:
                        try:
                            _BP_HOOK = _BreakpointHooks()
                            _BP_HOOK.hook()
                        except Exception:
                            _BP_HOOK = None
                return {
                    "ok": True,
                    "addr": hex(ea),
                    "condition": _BP_CONDITIONS.get(int(ea)),
                    "condition_language": "idc" if bp_cond else None,
                }
            return make_error(MCPError.IDA_ERROR, "Failed to add breakpoint")

        elif action == "del_bp":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            if ida_dbg.del_bpt(ea):
                _BP_CONDITIONS.pop(int(ea), None)
                if not _BP_CONDITIONS and _BP_HOOK is not None:
                    with contextlib.suppress(Exception):
                        _BP_HOOK.unhook()
                    _BP_HOOK = None
                return {"ok": True, "addr": hex(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to delete breakpoint")

        elif action == "enable_bp":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            if ida_dbg.enable_bpt(ea, enabled):
                return {"ok": True, "addr": hex(ea), "enabled": enabled}
            return make_error(MCPError.IDA_ERROR, "Failed to enable/disable breakpoint")

        elif action == "add_hw_bp":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_code=True)
            if err:
                return err
            # Hardware breakpoint type 1 = execute
            hw_type = kwargs.get("hw_type", 1)
            hw_size = kwargs.get("hw_size", 0)
            if ida_dbg.add_bpt(ea, hw_size, hw_type):
                return {"ok": True, "addr": hex(ea), "type": "hardware", "hw_type": hw_type}
            return make_error(MCPError.IDA_ERROR, "Failed to add hardware breakpoint")

        elif action == "add_watch":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            watch_size = kwargs.get("watch_size", 4)
            # Map access_type to IDA hw breakpoint type
            type_map = {"read": 2, "write": 3, "rw": 4, "execute": 1}
            hw_type = type_map.get(access_type, 3)
            if ida_dbg.add_bpt(ea, watch_size, hw_type):
                return {"ok": True, "addr": hex(ea), "type": "watchpoint", "access": access_type, "size": watch_size}
            return make_error(MCPError.IDA_ERROR, "Failed to add watchpoint")

        elif action == "regs":
            if not _debug_active():
                _wait_for_suspend(1200)
            if not _debug_active():
                return {"ok": True, "note": "Debugger is not running in headless mode", "_debug_status": "inactive"}
            target_tid = tid if tid is not None else ida_dbg.get_current_thread()
            dbg = ida_idd.get_dbg()
            if not dbg:
                return make_error(MCPError.IDA_ERROR, "No debugger info")
            regvals = ida_dbg.get_reg_vals(target_tid)
            if not regvals:
                _wait_for_suspend(1200)
                regvals = ida_dbg.get_reg_vals(target_tid)
            if not regvals:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Failed to get registers for thread {target_tid}",
                    hint="Pause the debugger or break on an address before reading registers.",
                )
            regs = {}
            for i, rv in enumerate(regvals):
                if i < dbg.nregs:
                    reg_info = dbg.regs(i)
                    if not reg_info:
                        continue
                    name = reg_info.name
                    try:
                        val = rv.pyval(reg_info.dtype)
                        regs[name] = hex(val) if isinstance(val, int) else str(val)
                    except Exception:
                        regs[name] = "?"
            return {"ok": True, "registers": regs, "tid": target_tid}

        elif action == "set_reg":
            if not reg or value is None:
                return make_error(MCPError.INVALID_ARGS, "reg and value required")
            err = check_debugger(require_active=True)
            if err:
                return err
            val = int(str(value), 0) if isinstance(value, str) else value
            if ida_dbg.set_reg_val(reg, val):
                return {"ok": True, "reg": reg, "value": hex(val)}
            return make_error(MCPError.IDA_ERROR, f"Failed to set register {reg}")

        elif action == "snapshot_regs":
            err = check_debugger(require_active=True)
            if err:
                return err
            name = snapshot_name or f"snap_{int(time.time())}"
            regs = _get_reg_dict(tid)
            _REG_SNAPSHOTS[name] = {
                "regs": regs,
                "timestamp": time.time(),
                "tid": tid or ida_dbg.get_current_thread(),
            }
            while len(_REG_SNAPSHOTS) > _MAX_REG_SNAPSHOTS:
                _REG_SNAPSHOTS.popitem(last=False)
            return {"ok": True, "snapshot_name": name, "reg_count": len(regs)}

        elif action == "reg_diff":
            err = check_debugger(require_active=True)
            if err:
                return err
            if not snapshot_name:
                return make_error(MCPError.INVALID_ARGS, "snapshot_name required for reg_diff")
            old = _REG_SNAPSHOTS.get(snapshot_name)
            if not old:
                available = list(_REG_SNAPSHOTS.keys())
                return make_error(
                    MCPError.NOT_FOUND,
                    f"Snapshot '{snapshot_name}' not found",
                    hint=f"Available snapshots: {available}",
                )
            current = _get_reg_dict(tid)
            diffs = {}
            for reg_name in set(current.keys()) | set(old["regs"].keys()):
                old_val = old["regs"].get(reg_name)
                new_val = current.get(reg_name)
                if old_val != new_val:
                    diffs[reg_name] = {"old": hex(old_val) if isinstance(old_val, int) else old_val,
                                       "new": hex(new_val) if isinstance(new_val, int) else new_val}
            return {"ok": True, "snapshot": snapshot_name, "diffs": diffs, "changed_count": len(diffs)}

        elif action == "threads":
            err = check_debugger(require_active=True)
            if err:
                return err
            threads = []
            for i in range(ida_dbg.get_thread_qty()):
                tid_val = ida_dbg.getn_thread(i)
                name = ida_dbg.get_thread_name(tid_val)
                threads.append({"tid": tid_val, "name": name or ""})
            return {"ok": True, "threads": threads}

        elif action == "modules":
            err = check_debugger(require_active=True)
            if err:
                return err
            modules = []
            mod = ida_idd.modinfo_t()
            if ida_dbg.get_first_module(mod):
                while True:
                    modules.append({"name": mod.name, "base": hex(mod.base), "size": hex(mod.size)})
                    if not ida_dbg.get_next_module(mod):
                        break
            return {"ok": True, "modules": modules}

        elif action == "callstack":
            err = check_debugger(require_active=True)
            if err:
                return err
            if hasattr(ida_dbg, "collect_stack_trace"):
                stack = []
                frames = ida_dbg.collect_stack_trace(ida_dbg.get_current_thread())
                if frames:
                    for frame in frames:
                        stack.append({"addr": hex(frame.ea), "func": idc.get_name(frame.ea) or ""})
                return {"ok": True, "callstack": stack}
            # Fallback frame-walk
            ptr_size = _get_ptr_size()
            fp_names = ["RBP", "EBP", "X29", "FP"]
            fp_val = None
            fp_name = None
            for candidate in fp_names:
                try:
                    reg_v = ida_dbg.get_reg_val(candidate)
                except Exception:
                    reg_v = None
                if isinstance(reg_v, int) and reg_v != 0:
                    fp_val = reg_v
                    fp_name = candidate
                    break

            stack = []
            try:
                ip = ida_dbg.get_ip_val()
                if isinstance(ip, int) and ip != 0:
                    stack.append({"addr": hex(ip), "func": idc.get_name(ip) or idc.get_func_name(ip) or ""})
            except Exception:
                pass

            if fp_val is None:
                return {"ok": True, "callstack": stack, "note": "Frame-pointer fallback unavailable (no frame register)."}

            visited_fp = set()
            cur_fp = int(fp_val)
            max_frames = 64
            for _ in range(max_frames):
                if cur_fp in visited_fp or cur_fp == 0:
                    break
                visited_fp.add(cur_fp)
                next_fp = _read_dbg_ptr(cur_fp, ptr_size)
                ret_ea = _read_dbg_ptr(cur_fp + ptr_size, ptr_size)
                if not isinstance(ret_ea, int) or ret_ea in (0, idaapi.BADADDR):
                    break
                stack.append(
                    {
                        "addr": hex(ret_ea),
                        "func": idc.get_name(ret_ea) or idc.get_func_name(ret_ea) or "",
                        "fp": hex(cur_fp),
                    }
                )
                if not isinstance(next_fp, int) or next_fp <= cur_fp:
                    break
                cur_fp = next_fp

            return {
                "ok": True,
                "callstack": stack,
                "mode": "frame_pointer_fallback",
                "frame_register": fp_name,
            }

        elif action == "read_mem":
            err = check_debugger(require_active=True)
            if err:
                return err
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            mem_data = ida_dbg.read_dbg_memory(ea, size)
            if mem_data:
                return {"ok": True, "addr": hex(ea), "data": " ".join(f"{b:02x}" for b in mem_data)}
            return make_error(MCPError.IDA_ERROR, "Failed to read memory")

        elif action == "write_mem":
            err = check_debugger(require_active=True)
            if err:
                return err
            if not addr or not data:
                return make_error(MCPError.INVALID_ARGS, "addr and data required")
            ea, err = validate_addr(addr)
            if err:
                return err
            try:
                bytes_data = bytes.fromhex(data.replace(" ", ""))
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "Invalid hex data")
            if ida_dbg.write_dbg_memory(ea, bytes_data):
                return {"ok": True, "addr": hex(ea), "size": len(bytes_data)}
            return make_error(MCPError.IDA_ERROR, "Failed to write memory")

        elif action == "search_mem":
            err = check_debugger(require_active=True)
            if err:
                return err
            if not addr or not data:
                return make_error(MCPError.INVALID_ARGS, "addr and data (pattern) required")
            ea, err = validate_addr(addr)
            if err:
                return err
            search_size = kwargs.get("search_size", 0x10000)
            try:
                pattern = bytes.fromhex(data.replace(" ", ""))
            except ValueError:
                pattern = data.encode("utf-8", errors="replace")
            mem_data = ida_dbg.read_dbg_memory(ea, search_size)
            if not mem_data:
                return make_error(MCPError.IDA_ERROR, "Failed to read memory for search")
            hits = []
            idx = mem_data.find(pattern)
            while idx != -1:
                hits.append(hex(ea + idx))
                if len(hits) >= 100:
                    break
                idx = mem_data.find(pattern, idx + 1)
            return {"ok": True, "pattern": data, "hits": hits, "count": len(hits), "region": f"{hex(ea)}-{hex(ea + search_size)}"}

        elif action == "stack_dump":
            err = check_debugger(require_active=True)
            if err:
                return err
            ptr_size = _get_ptr_size()
            sp_names = ["RSP", "ESP", "XSP", "SP"]
            sp_val = None
            sp_name = None
            for candidate in sp_names:
                try:
                    reg_v = ida_dbg.get_reg_val(candidate)
                except Exception:
                    reg_v = None
                if isinstance(reg_v, int) and reg_v != 0:
                    sp_val = reg_v
                    sp_name = candidate
                    break
            if sp_val is None:
                return make_error(MCPError.IDA_ERROR, "Could not find stack pointer register")
            dump = []
            for offset in range(0, size * ptr_size, ptr_size):
                ptr = _read_dbg_ptr(sp_val + offset, ptr_size)
                if ptr is not None:
                    name = idc.get_name(ptr) or ""
                    dump.append(f"{hex(sp_val + offset)}  {hex(ptr)}  {name}")
                else:
                    dump.append(f"{hex(sp_val + offset)}  ???")
            return {"ok": True, "sp_register": sp_name, "sp": hex(sp_val), "dump": dump}

        elif action == "mem_map":
            err = check_debugger(require_active=True)
            if err:
                return err
            regions = []
            try:
                # Try to use ida_dbg.get_memory_info if available
                get_mem_info = getattr(ida_dbg, "get_memory_info", None)
                if callable(get_mem_info):
                    info = get_mem_info()
                    for r in info:
                        regions.append({
                            "start": hex(r.start_ea) if hasattr(r, "start_ea") else hex(r[0]),
                            "end": hex(r.end_ea) if hasattr(r, "end_ea") else hex(r[1]),
                            "name": r.name if hasattr(r, "name") else "",
                            "perms": f"{'r' if r.perm & 1 else '-'}{'w' if r.perm & 2 else '-'}{'x' if r.perm & 4 else '-'}" if hasattr(r, "perm") else "???",
                        })
            except Exception:
                pass
            if not regions:
                # Fallback: use segments
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if seg:
                        perms = f"{'r' if seg.perm & idaapi.SEGPERM_READ else '-'}{'w' if seg.perm & idaapi.SEGPERM_WRITE else '-'}{'x' if seg.perm & idaapi.SEGPERM_EXEC else '-'}"
                        regions.append({
                            "start": hex(seg.start_ea),
                            "end": hex(seg.end_ea),
                            "name": ida_segment.get_segm_name(seg),
                            "perms": perms,
                        })
            return {"ok": True, "regions": regions, "count": len(regions)}

        elif action == "bp_context":
            try:
                pc = idaapi.get_reg_val("PC") or idaapi.get_reg_val("RIP") or idaapi.get_reg_val("EIP") or 0
            except Exception:
                pc = 0
            if not pc:
                return make_error(MCPError.INVALID_ARGS, "No active debugger or PC unavailable")
            pc_hex = hex(pc)
            try:
                try: from .blackboard import BlackboardStore
                except ImportError: from blackboard import BlackboardStore  # type: ignore[import-not-found]
                store = BlackboardStore()
                addr_entries = store.list(addr=pc_hex, limit=10)
                func = idaapi.get_func(pc)
                func_entries = []
                if func:
                    func_hex = hex(func.start_ea)
                    func_entries = store.list(addr=func_hex, limit=5)
                    fname = idc.get_func_name(func.start_ea) or ""
                    if fname and not fname.startswith("sub_"):
                        semantic = store.semantic_search(query=fname, top_k=3, threshold=0.5)
                        func_entries.extend(semantic)
                return {
                    "ok": True,
                    "pc": pc_hex,
                    "func": hex(func.start_ea) if func else None,
                    "func_name": idc.get_func_name(func.start_ea) if func else None,
                    "blackboard_at_pc": addr_entries,
                    "blackboard_at_func": func_entries[:8],
                    "note": "Prior analysis findings for current execution context.",
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, str(e))

        elif action == "trace_start":
            output_file = str(kwargs.get("output_file") or "").strip()
            if not output_file:
                return make_error(MCPError.INVALID_ARGS, "output_file required")
            max_insns = int(kwargs.get("max_insns") or 50000)
            if max_insns <= 0:
                return make_error(MCPError.INVALID_ARGS, "max_insns must be > 0")
            if _TRACE_HOOK is not None:
                active_fh = _TRACE_STATE.get("file")
                active_path = str(getattr(active_fh, "name", "") or "")
                return {
                    "ok": True,
                    "already_running": True,
                    "trace_file": active_path,
                    "insn_count": int(_TRACE_STATE.get("count", 0)),
                    "max_insns": int(_TRACE_STATE.get("max_insns", 50000)),
                }
            out_dir = os.path.dirname(output_file)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            fh = open(output_file, "w", encoding="utf-8")
            _TRACE_STATE["file"] = fh
            _TRACE_STATE["count"] = 0
            _TRACE_STATE["max_insns"] = min(1_000_000, max_insns)
            _TRACE_HOOK = _TraceHooks()
            _TRACE_HOOK.hook()
            return {"ok": True, "trace_file": output_file, "max_insns": _TRACE_STATE["max_insns"]}

        elif action == "trace_stop":
            if _TRACE_HOOK is not None:
                with contextlib.suppress(Exception):
                    _TRACE_HOOK.unhook()
                _TRACE_HOOK = None
            fh = _TRACE_STATE.get("file")
            path = ""
            if fh:
                try:
                    fh.flush()
                    path = str(getattr(fh, "name", "") or "")
                    fh.close()
                except Exception:
                    path = ""
            count = int(_TRACE_STATE.get("count", 0))
            _TRACE_STATE["file"] = None
            _TRACE_STATE["count"] = 0
            return {"ok": True, "trace_file": path, "insn_count": count}

        elif action == "trace_read":
            output_file = str(kwargs.get("output_file") or "").strip()
            if not output_file:
                return make_error(MCPError.INVALID_ARGS, "output_file required")
            lim = int(kwargs.get("limit") or 500)
            if lim <= 0:
                return make_error(MCPError.INVALID_ARGS, "limit must be > 0")
            lim = min(lim, 5000)
            try:
                with open(output_file, encoding="utf-8") as f:
                    lines = f.readlines()
                rows = []
                for ln in lines[-max(1, lim):]:
                    try:
                        rows.append(json.loads(ln))
                    except Exception:
                        continue
                return {"ok": True, "trace_file": output_file, "entries": rows, "count": len(rows)}
            except Exception as e:
                return make_error(MCPError.FILE_NOT_FOUND, str(e))

        elif action == "mem_diff":
            err = check_debugger(require_active=True)
            if err:
                return err
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            span = int(size or 16)
            if span <= 0:
                return make_error(MCPError.INVALID_ARGS, "size must be > 0")
            if span > _MAX_MEM_DIFF_SPAN:
                return make_error(MCPError.INVALID_ARGS, f"size too large (max {_MAX_MEM_DIFF_SPAN})")
            cur = ida_dbg.read_dbg_memory(ea, span)
            if not cur:
                return make_error(MCPError.IDA_ERROR, "Failed to read memory")
            key = (int(ea), int(span))
            prev = _MEM_DIFF_SNAPSHOTS.get(key)
            changes = []
            if prev:
                n = min(len(prev), len(cur))
                for i in range(n):
                    if prev[i] != cur[i]:
                        changes.append({"offset": i, "before": f"{prev[i]:02x}", "after": f"{cur[i]:02x}"})
                if len(prev) != len(cur):
                    changes.append({"offset": n, "before": f"len={len(prev)}", "after": f"len={len(cur)}"})
            _MEM_DIFF_SNAPSHOTS[key] = bytes(cur)
            if len(_MEM_DIFF_SNAPSHOTS) > _MAX_MEM_DIFF_SNAPSHOTS:
                try:
                    oldest_key = next(iter(_MEM_DIFF_SNAPSHOTS.keys()))
                    _MEM_DIFF_SNAPSHOTS.pop(oldest_key, None)
                except Exception:
                    pass
            out = {"ok": True, "addr": hex(ea), "size": span, "changed_offsets": changes[:1024], "change_count": len(changes)}
            if prev is None:
                out["baseline_created"] = True
            return out

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
