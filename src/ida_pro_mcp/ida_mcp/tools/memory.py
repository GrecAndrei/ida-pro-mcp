
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 6. MEMORY - Read/Write operations
# ============================================================================

@tool 
@idawrite
def memory(
    action: Annotated[Literal["read", "write"], "Action: read|write"],
    addr: Annotated[str, "Address"],
    type: Annotated[Literal["bytes", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"],
                    "Data type (for read)"] = "u32",
    size: Annotated[int, "Size in bytes (for type=bytes)"] = 16,
    data: Annotated[Optional[str], "Hex data to write (for write)"] = None,
    **kwargs
) -> dict:
    """
    Read or write raw memory in the database (or debugger memory if running).
    
    Actions:
    - read: Read values from `addr`. Returns hex or native value.
    - write: Patch bytes at `addr`.
    
    Arguments:
    - addr: Address to read/write.
    - type: Data type for read (u8/u16/u32/u64, s8/s16/s32/s64, f32/f64, ptr, bytes, string). Default 'u32'.
    - size: Number of bytes to read (only for type='bytes').
    - data: Hex string to write (e.g. "90 90 90"). REQUIRED for write.
    """
    try:
        ea, error = validate_addr(addr)
        if error: return error
        
        if action == "read":
            # Safety check for size
            if size > 1024 * 1024:  # 1MB limit
                return make_error(MCPError.SIZE_LIMIT_EXCEEDED, f"Read size too large ({size} bytes)", "Limit reads to 1MB or use paging")

            if type == "bytes":
                data = ida_bytes.get_bytes(ea, size)
                if data:
                    value = " ".join(f"{x:02x}" for x in data)
                else:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read {size} bytes from {hex(ea)}")
            elif type == "u8":
                value = ida_bytes.get_wide_byte(ea)
            elif type == "u16":
                value = ida_bytes.get_wide_word(ea)
            elif type == "u32":
                value = ida_bytes.get_wide_dword(ea)
            elif type == "u64":
                value = ida_bytes.get_qword(ea)
            elif type == "s8":
                value = ida_bytes.get_wide_byte(ea)
                value = value - 0x100 if value & 0x80 else value
            elif type == "s16":
                value = ida_bytes.get_wide_word(ea)
                value = value - 0x10000 if value & 0x8000 else value
            elif type == "s32":
                value = ida_bytes.get_wide_dword(ea)
                value = value - 0x100000000 if value & 0x80000000 else value
            elif type == "s64":
                value = ida_bytes.get_qword(ea)
                value = value - 0x10000000000000000 if value & 0x8000000000000000 else value
            elif type == "f32":
                raw = ida_bytes.get_bytes(ea, 4)
                if not raw:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read 4 bytes from {hex(ea)}")
                import struct
                value = struct.unpack("<f", raw)[0]
            elif type == "f64":
                raw = ida_bytes.get_bytes(ea, 8)
                if not raw:
                    return make_error(MCPError.ADDRESS_INVALID, f"Could not read 8 bytes from {hex(ea)}")
                import struct
                value = struct.unpack("<d", raw)[0]
            elif type == "ptr":
                is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100)
                value = ida_bytes.get_qword(ea) if is_64 else ida_bytes.get_wide_dword(ea)
            elif type == "string":
                # Check string length limit
                s = idaapi.get_strlit_contents(ea, -1, 0)
                if s:
                    if len(s) > 65536:
                        s = s[:65536]
                    value = s.decode("utf-8", errors="replace")
                else:
                    value = None
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown type: {type}")
            resp = {"ok": True, "addr": addr, "type": type, "value": value}
            if type == "bytes":
                resp["size"] = size
            elif type in ("u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "ptr"):
                resp["value_hex"] = hex(value)
            elif type == "string":
                resp["length"] = len(value) if value is not None else 0
            return resp
        
        elif action == "write":
            if not data:
                return make_error(MCPError.INVALID_ARGS, "data required for write")
            try:
                bytes_data = bytes.fromhex(data.replace(" ", ""))
            except ValueError:
                return make_error(MCPError.INVALID_ARGS, "Invalid hex data")

            # Check if writable
            seg = ida_segment.getseg(ea)
            if seg and (seg.perm & ida_segment.SEGPERM_WRITE) == 0:
                 # Warn but allow if user insists (maybe add force param?)
                 pass

            ida_bytes.patch_bytes(ea, bytes_data)
            return {"ok": True, "addr": addr, "size": len(bytes_data), "data": data}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 7. MODIFY - Rename, comments, set type
# ============================================================================
