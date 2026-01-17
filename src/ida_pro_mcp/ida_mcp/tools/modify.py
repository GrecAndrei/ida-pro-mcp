
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
# 7. MODIFY - Rename, comments, set type
# ============================================================================

@tool
@idawrite
def modify(
    action: Annotated[Literal["rename", "comment", "set_type", "patch_asm"], 
                      "Action: rename|comment|set_type|patch_asm"],
    addr: Annotated[str, "Address"],
    value: Annotated[Optional[str], "New name, comment text, type declaration, or assembly instruction"] = None,
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
    - patch_asm: Assemble and patch instructions at `addr` (e.g. "mov eax, 1").
    
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
            # Assemble and patch
            import ida_idp
            import ida_ua
            
            # IDA 9.2 assemble returns (bool success, bytes code)
            res = ida_idp.assemble(ea, 0, ea, True, value)
            if isinstance(res, tuple):
                success, code = res
            else:
                # Fallback for older IDA versions where it might return bytes or None
                success = res is not None
                code = res

            if success and code:
                # Ensure it's a standard bytes object for IDA 9.2
                code_bytes = bytes(code)
                ida_bytes.patch_bytes(ea, code_bytes)
                return {"ok": True, "addr": addr, "size": len(code_bytes), "asm": value}
            return make_error(MCPError.IDA_ERROR, f"Failed to assemble: {value}", "Check instruction syntax and operands")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 8. MISC - Python exec, signatures, bookmarks, undo, stack
# ============================================================================
