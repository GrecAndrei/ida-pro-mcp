
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
# 34. NAV - Navigation Helpers
# ============================================================================

@tool
@idaread
def nav(
    action: Annotated[Literal["goto", "cursor", "interesting"],
                      "Action: goto|cursor|interesting"],
    addr: Annotated[Optional[str], "Address to navigate to"] = None,
    **kwargs
) -> dict:
    """
    Navigation helpers for triage and analysis context.
    
    Actions:
    - goto: Get detailed analysis context for an address.
    - cursor: Get current pseudo-cursor position (screen ea).
    - interesting: Find high-value triage points (crypto, syscalls, anti-debug).
    """
    try:
        if action == "goto":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea),
                "function": idc.get_func_name(func.start_ea) if func else None,
                "disasm": ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            }

        elif action == "cursor":
            ea = ida_kernwin.get_screen_ea()
            if ea == idaapi.BADADDR:
                return {"ok": True, "addr": None, "name": None, "warning": "Cursor unavailable in headless mode"}
            return {"ok": True, "addr": hex(ea), "name": idc.get_name(ea)}

        elif action == "interesting":
            findings = []
            # Instruction-based triage
            targets = {"syscall": "system_call", "int 3": "breakpoint", "rdtsc": "timing_check", "cpuid": "environment_check"}
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg or not (seg.perm & idaapi.SEGPERM_EXEC): continue
                curr = seg.start_ea
                while curr < seg.end_ea and len(findings) < 100:
                    insn = idc.print_insn_mnem(curr).lower()
                    if insn in targets:
                        findings.append({"addr": hex(curr), "type": targets[insn], "disasm": idc.generate_disasm_line(curr, 0)})
                    curr = idc.next_head(curr, seg.end_ea)
            return {"ok": True, "findings": findings}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 35. COLORIZE - Code Region Coloring
# ============================================================================
