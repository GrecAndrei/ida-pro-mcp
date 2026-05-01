"""
Unified Edit Hub - Routes edit operations to appropriate tools.
This provides a single entry point for all write operations.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# VOERA: Neuro-Symbolic Governance for Edit Operations
# ============================================================================

def _validate_edit(action: str, addr: str, value: str, args: dict) -> dict:
    """Deterministic pre-flight validation before edit commit.
    Returns {"approved": bool, "violations": list[str]}
    """
    violations = []
    
    # Rule 1: Prevent renaming to misleading names
    if action == "rename":
        lower_val = (value or "").lower()
        if lower_val in ("main", "start", "entry", "init"):
            # Heuristic: these names should only be applied to functions with appropriate characteristics
            ea, err = validate_addr(addr)
            if not err and ea != idaapi.BADADDR:
                func = idaapi.get_func(ea)
                if func:
                    # Check if function is large enough to be main/entry
                    if func.end_ea - func.start_ea < 20:
                        violations.append(f"Renaming small function ({func.end_ea - func.start_ea} bytes) to '{value}' may be misleading")
    
    # Rule 2: Prevent patching prologue/epilogue sequences
    if action == "patch" or (action == "bulk" and args.get("subaction") == "patch"):
        ea, err = validate_addr(addr)
        if not err and ea != idaapi.BADADDR:
            func = idaapi.get_func(ea)
            if func:
                offset = ea - func.start_ea
                if offset < 5:
                    violations.append("Patching function prologue - verify this won't break stack frame setup")
                if func.end_ea - ea < 5:
                    violations.append("Patching near function end - verify this won't break epilogue/return")
    
    # Rule 3: Prevent dangerous comment claims
    if action == "comment":
        lower_val = (value or "").lower()
        if any(kw in lower_val for kw in ("safe", "secure", "harmless", "no vulnerability")):
            violations.append("Comment claims safety without verification - consider adding uncertainty marker")
    
    # Rule 4: Type safety - warn on extreme type changes
    if action == "type":
        ea, err = validate_addr(addr)
        if not err and ea != idaapi.BADADDR:
            existing_name = idc.get_name(ea) or ""
            if existing_name and not existing_name.startswith("sub_"):
                # Already has a meaningful name - type change might be significant
                pass  # Allow but we could add more checks
    
    return {"approved": len(violations) == 0, "violations": violations}


@tool
@unsafe
@idawrite
def edit(
    action: Annotated[Literal["rename", "comment", "type", "patch", "create_func", "bulk", "validate"],
                      "Action: rename|comment|type|patch|create_func|bulk|validate"],
    addr: Annotated[Optional[str], "Address to edit"] = None,
    value: Annotated[Optional[str], "New value (name, comment text, or type)"] = None,
    items: Annotated[Optional[list], "List of items for bulk operations"] = None,
    subaction: Annotated[Optional[str], "Sub-action for complex operations"] = None,
    args: Annotated[Optional[dict], "Additional arguments"] = None,
    governed: Annotated[bool, "Run neuro-symbolic governance validation before applying (default: true)"] = True,
    **kwargs
) -> dict:
    """
    Unified edit hub - single entry point for all write operations.
    
    This tool routes edits to the appropriate underlying tool, making
    modifications simpler and more consistent.
    
    QUICK ACTIONS:
    
    rename - Rename a symbol at address
        Params: addr, value (new name)
        Example: edit(action="rename", addr="0x401000", value="parse_config")
        
    comment - Add/update a comment at address
        Params: addr, value (comment text)
        Example: edit(action="comment", addr="0x401000", value="Initialize configuration")
        
    type - Set type at address
        Params: addr, value (type declaration)
        Example: edit(action="type", addr="0x401000", value="int __cdecl(int argc, char **argv)")
        
    patch - Patch bytes/instruction at address
        Params: addr, value (bytes as hex string or assembly)
        args: {asm: true} to assemble instruction
        Example: edit(action="patch", addr="0x401000", value="90 90")  # NOP NOP
        
    create_func - Create a function at address
        Params: addr
        Example: edit(action="create_func", addr="0x401000")
        
    bulk - Bulk operations
        Params: items (list of {addr, value, action?})
        subaction: rename|comment|type
        Example: edit(action="bulk", subaction="rename", items=[{"addr": "0x401000", "value": "func1"}])

    validate - Neuro-symbolic governance check for a proposed edit.
        Params: action, addr, value
        Returns: {approved, violations}
        Use before committing edits to catch dangerous operations.
    """
    try:
        args = args or {}
        
        # Governance pre-flight for all mutating actions
        if governed and action in ("rename", "comment", "type", "patch", "bulk"):
            sub = subaction or action
            gov_result = _validate_edit(sub, addr, value or "", args)
            if not gov_result["approved"]:
                return {
                    "ok": False,
                    "governed": True,
                    "approved": False,
                    "violations": gov_result["violations"],
                    "hint": "Set governed=false to bypass (not recommended). Review violations first.",
                }
        
        if action == "validate":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for validate")
            sub = subaction or kwargs.get("edit_action", "rename")
            gov_result = _validate_edit(sub, addr, value or "", args)
            return {
                "ok": True,
                "action": sub,
                "addr": addr,
                "approved": gov_result["approved"],
                "violations": gov_result["violations"],
            }
        
        if action == "rename":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (new name) required")
            from .modify import modify as modify_tool
            return modify_tool(action="rename", addr=addr, value=value)
            
        elif action == "comment":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (comment text) required")
            from .modify import modify as modify_tool
            return modify_tool(action="comment", addr=addr, value=value, **args)
            
        elif action == "type":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (type declaration) required")
            from .modify import modify as modify_tool
            return modify_tool(action="set_type", addr=addr, value=value)
            
        elif action == "patch":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (bytes or asm) required")
            from .modify import modify as modify_tool
            if args.get("asm"):
                return modify_tool(action="patch_asm", addr=addr, value=value)
            else:
                # Direct byte patching
                from .data_ops import data_ops as data_ops_tool
                return data_ops_tool(action="patch", addr=addr, bytes=value)
            
        elif action == "create_func":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            from .funcs import funcs as funcs_tool
            return funcs_tool(action="create", addr=addr)
            
        elif action == "bulk":
            if not items:
                return make_error(MCPError.INVALID_ARGS, "items required for bulk operations")
            sub = subaction or "rename"
            from .bulk import bulk as bulk_tool
            return bulk_tool(action=sub, items=items, **args)
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
