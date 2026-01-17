
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
# 16. DATA_OPS - Data creation operations
# ============================================================================

@tool
@idawrite
def data_ops(
    action: Annotated[Literal["make_data", "make_array", "make_string", "undefine", "make_code"],
                      "Action: make_data|make_array|make_string|undefine|make_code"],
    addr: Annotated[str, "Address"],
    size: Annotated[Optional[int], "Size in bytes"] = None,
    count: Annotated[Optional[int], "Array element count"] = None,
    str_type: Annotated[int, "String type (0=C, 1=Pascal, 2=UTF16)"] = 0,
    **kwargs
) -> dict:
    """Data creation: make_data, make_array, make_string, undefine, make_code"""
    try:
        ea, err = validate_addr(addr)
        if err: return err

        if action == "make_data":
            if size is None:
                size = 1
            flags = {1: ida_bytes.byte_flag(), 2: ida_bytes.word_flag(),
                     4: ida_bytes.dword_flag(), 8: ida_bytes.qword_flag()}.get(size, ida_bytes.byte_flag())
            if ida_bytes.create_data(ea, flags, size, idaapi.BADADDR):
                return {"ok": True, "addr": addr, "size": size}
            return make_error(MCPError.IDA_ERROR, "Failed to create data")
        
        elif action == "make_array":
            if count is None:
                return make_error(MCPError.INVALID_ARGS, "count required")
            elem_size = size or 1
            flags = {1: ida_bytes.byte_flag(), 2: ida_bytes.word_flag(),
                     4: ida_bytes.dword_flag(), 8: ida_bytes.qword_flag()}.get(elem_size, ida_bytes.byte_flag())
            if ida_bytes.create_data(ea, flags, elem_size, idaapi.BADADDR):
                # Set array info
                import ida_nalt as nalt
                arr = nalt.array_parameters()
                arr.flags = 0
                arr.lineitems = 0
                arr.alignment = 0
                nalt.set_array_parameters(ea, arr)
                idc.make_array(ea, count)
                return {"ok": True, "addr": addr, "count": count, "elem_size": elem_size}
            return make_error(MCPError.IDA_ERROR, "Failed to create array")

        elif action == "make_string":
            str_types = {0: idc.STRTYPE_C, 1: idc.STRTYPE_PASCAL, 2: idc.STRTYPE_C_16}
            stype = str_types.get(str_type, idc.STRTYPE_C)
            length = size or idaapi.BADADDR
            try:
                created = idc.create_strlit(ea, length if length != idaapi.BADADDR else idc.BADADDR, stype)
            except TypeError:
                created = idc.create_strlit(ea, length if length != idaapi.BADADDR else idc.BADADDR)
            if created:
                return {"ok": True, "addr": addr, "type": str_type}
            return make_error(MCPError.IDA_ERROR, "Failed to create string")

        elif action == "undefine":
            length = size or ida_bytes.get_item_size(ea)
            if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, length):
                return {"ok": True, "addr": addr, "size": length}
            return make_error(MCPError.IDA_ERROR, "Failed to undefine")

        elif action == "make_code":
            length = idc.create_insn(ea)
            if length > 0:
                return {"ok": True, "addr": addr, "size": length}
            return make_error(MCPError.IDA_ERROR, "Failed to create instruction")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 17. AGENT - High-level analysis helpers
# ============================================================================
