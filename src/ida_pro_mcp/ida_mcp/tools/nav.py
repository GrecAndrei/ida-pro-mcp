
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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
            targets = INTERESTING_INSTRUCTIONS
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg or not (seg.perm & idaapi.SEGPERM_EXEC): continue
                curr = seg.start_ea
                while curr < seg.end_ea and len(findings) < 100:
                    insn = idc.print_insn_mnem(curr).lower()
                    if insn in targets:
                        findings.append({"addr": hex(curr), "type": targets[insn], "disasm": ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))})
                    curr = idc.next_head(curr, seg.end_ea)
                    if curr == idaapi.BADADDR: break
            return {"ok": True, "findings": findings}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 35. COLORIZE - Code Region Coloring
# ============================================================================
