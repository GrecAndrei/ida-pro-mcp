"""Memory operations for IDA Pro MCP.

CONSOLIDATED: Merged read operations into single tool with type parameter.
"""

from typing import Annotated, Literal, Optional
import ida_bytes
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import normalize_list_input, parse_address, MemoryRead, MemoryPatch


# ============================================================================
# Helpers
# ============================================================================

def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


# ============================================================================
# CONSOLIDATED MEMORY TOOL (replaces 8 tools with 2)
# ============================================================================


@tool
@idaread
def mem_read(
    addrs: Annotated[list[str] | str, "Address(es) to read from"],
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "string", "global"], 
                    "Data type: bytes|u8|u16|u32|u64|string|global"] = "u32",
    size: Annotated[int, "Byte count (for type=bytes)"] = 16,
) -> list[dict]:
    """Read memory: supports bytes, u8, u16, u32, u64, string, or global variable"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            
            if type == "bytes":
                data = " ".join(f"{x:02x}" for x in ida_bytes.get_bytes(ea, size))
                results.append({"addr": addr, "data": data})
            elif type == "u8":
                value = ida_bytes.get_wide_byte(ea)
                results.append({"addr": addr, "value": value})
            elif type == "u16":
                value = ida_bytes.get_wide_word(ea)
                results.append({"addr": addr, "value": value})
            elif type == "u32":
                value = ida_bytes.get_wide_dword(ea)
                results.append({"addr": addr, "value": value})
            elif type == "u64":
                value = ida_bytes.get_qword(ea)
                results.append({"addr": addr, "value": value})
            elif type == "string":
                value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
                results.append({"addr": addr, "value": value})
            elif type == "global":
                value = get_global_variable_value_internal(ea)
                results.append({"addr": addr, "value": value})
            else:
                results.append({"addr": addr, "error": f"Unknown type: {type}"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@tool
@idawrite
def mem_write(
    patches: Annotated[list[dict] | dict, "Patch(es) with addr and data (hex string)"],
) -> list[dict]:
    """Patch bytes at memory addresses. Each patch: {addr: '0x...', data: 'deadbeef'}"""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])
            ida_bytes.patch_bytes(ea, data)
            results.append({"addr": patch["addr"], "size": len(data), "ok": True})
        except Exception as e:
            results.append({"addr": patch.get("addr"), "error": str(e)})

    return results
