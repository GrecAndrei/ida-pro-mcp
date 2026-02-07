
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 7. MODIFY - Rename, comments, set type
# ============================================================================

@tool
@idawrite
def modify(
    action: Annotated[Literal["rename", "comment", "set_type", "patch_asm"], 
                      "Action: rename|comment|set_type|patch_asm"],
    addr: Annotated[str, "Address"],
    value: Annotated[Optional[str], "New name, comment text, type declaration, or assembly instruction(s)"] = None,
    # Aliases for compatibility
    name: Annotated[Optional[str], "Alias for value (when action=rename)"] = None,
    text: Annotated[Optional[str], "Alias for value (when action=comment)"] = None,
    type_str: Annotated[Optional[str], "Alias for value (when action=set_type)"] = None,
    asm: Annotated[Optional[str], "Alias for value (when action=patch_asm)"] = None,
    comment_type: Annotated[Literal["regular", "repeatable", "anterior", "posterior"], 
                            "Comment type (for action=comment)"] = "regular",
    **kwargs
) -> dict:
    """
    Modify the database: renaming, commenting, types, and assembly patching.
    
    Actions:
    - rename: Change the name of a function, label, or data item at `addr`.
    - comment: Add a comment. Supports regular, repeatable, anterior (above), posterior (below).
    - set_type: Apply a type declaration to `addr` (similar to types.apply).
    - patch_asm: Assemble and patch instructions at `addr`.
      Supports single instructions (e.g. "mov eax, 1") or multiple instructions
      separated by semicolons (e.g. "nop; nop; nop" or "push ebp; mov ebp, esp").
      Each instruction is assembled and patched sequentially at consecutive addresses.
    
    Arguments:
    - value (or name/text/type_str/asm): The content to apply.
    - comment_type: One of 'regular', 'repeatable', 'anterior', 'posterior'.
    """
    try:
        # Support multiple parameter names for compatibility
        if not value:
            if action == "rename" and name:
                value = name
            elif action == "comment" and text:
                value = text
            elif action == "set_type" and type_str:
                value = type_str
            elif action == "patch_asm" and asm:
                value = asm
        
        if not value:
            return make_error(MCPError.INVALID_ARGS, f"value parameter required (or use {action}-specific alias: name/text/type_str/asm)")
        
        ea, error = validate_addr(addr)
        if error: return error
        
        if action == "rename":
            if idc.set_name(ea, value, ida_name.SN_FORCE):
                return {"ok": True, "addr": addr, "name": value}
            return make_error(MCPError.IDA_ERROR, "Failed to rename", "Check if name is valid C identifier and not duplicate")
        
        elif action == "comment":
            if comment_type == "regular":
                idc.set_cmt(ea, value, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, value, 1)
            else:
                # Anterior/Posterior
                import ida_lines
                is_anterior = (comment_type == "anterior")
                if hasattr(ida_lines, "add_extra_cmt"):
                    ida_lines.add_extra_cmt(ea, is_anterior, value)
                else:
                    return make_error(MCPError.NOT_IMPLEMENTED, "Extra comments not supported in this IDA version")
            return {"ok": True, "addr": addr, "comment_type": comment_type, "comment": value}
        
        elif action == "set_type":
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, value, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse type: {value}", "Check C declaration syntax")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": addr, "type": str(tif)}
            return make_error(MCPError.IDA_ERROR, "Failed to apply type", "Check if type is compatible with address")
        
        elif action == "patch_asm":
            # Assemble and patch - supports multiple instructions separated by semicolons
            import ida_idp
            import ida_ua
            
            # Split multiple instructions by semicolons
            instructions = [inst.strip() for inst in value.split(";") if inst.strip()]
            if not instructions:
                return make_error(MCPError.INVALID_ARGS, "No valid instructions provided")
            
            current_ea = ea
            total_size = 0
            patched = []
            
            for inst in instructions:
                # IDA assemble API
                res = ida_idp.assemble(current_ea, 0, current_ea, True, inst)
                if isinstance(res, tuple):
                    success, code = res
                else:
                    # Fallback for older IDA versions
                    success = res is not None and res != b'' and res != 0
                    code = res

                if not success or not code:
                    hint = f"Check instruction syntax for your target architecture. Failed at instruction: '{inst}'"
                    if patched:
                        hint += f". Note: {len(patched)} instruction(s) were already patched before this failure."
                    return make_error(
                        MCPError.IDA_ERROR,
                        f"Failed to assemble: '{inst}' at {hex(current_ea)}",
                        hint,
                    )
                
                code_bytes = bytes(code)
                ida_bytes.patch_bytes(current_ea, code_bytes)
                patched.append({"addr": hex(current_ea), "size": len(code_bytes), "asm": inst})
                current_ea += len(code_bytes)
                total_size += len(code_bytes)
            
            if len(patched) == 1:
                return {"ok": True, "addr": addr, "size": total_size, "asm": instructions[0]}
            return {"ok": True, "addr": addr, "total_size": total_size, "instructions": patched, "count": len(patched)}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 8. MISC - Python exec, signatures, bookmarks, undo, stack
# ============================================================================
