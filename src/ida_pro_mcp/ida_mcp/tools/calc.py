
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


@tool
@idaread
def calc(
    action: Annotated[Literal["eval", "offset", "convert", "resolve", "deref", "chain", "align"],
                      "Action: eval|offset|convert|resolve|deref|chain|align"],
    expr: Annotated[Optional[str], "Expression to evaluate (e.g. '0x401000 + 0x100')"] = None,
    addr: Annotated[Optional[str], "Address for conversion/resolution"] = None,
    target: Annotated[Optional[str], "Target address for offset calculation"] = None,
    value: Annotated[Optional[Union[str, int]], "Value for conversion/alignment"] = None,
    type: Annotated[Optional[str], "Value type (u8/u16/u32/u64/s8/s16/s32/s64/f32/f64/ptr/bytes/string)"] = None,
    size: Annotated[Optional[int], "Size in bytes for bytes/ptr/alignment"] = None,
    offsets: Annotated[Optional[Union[str, list]], "Offset chain for pointer chasing"] = None,
    **kwargs
) -> dict:
    """
    Address calculation and number conversion utilities (r2-style).

    ACTIONS:

    eval - Evaluate a mathematical expression involving addresses
        Returns: {expr, result_hex, result_int}
        Example: calc(action="eval", expr="0x401000 + 0x50")

    offset - Calculate the distance between two addresses
        Returns: {from, to, delta_hex, delta_int}
        Example: calc(action="offset", addr="0x401000", target="0x401050")

    convert - Convert a value to Hex, Dec, Bin, and ASCII
        Returns: {hex, dec, bin, ascii, bitmask}
        Example: calc(action="convert", value="1234")

    resolve - Convert between Virtual Address (VA) and File Offset
        Returns: {va, file_offset, segment}
        Example: calc(action="resolve", addr="0x401000")

    deref - Read a typed value from memory
        Returns: {addr, type, value, value_hex?}
        Example: calc(action="deref", addr="0x401000", type="u32")

    chain - Follow a pointer chain with offsets
        Returns: {base, offsets, steps, final}
        Example: calc(action="chain", addr="0x401000", offsets="0x10,0x20")

    align - Align a value/address to a boundary
        Returns: {value, alignment, aligned_down, aligned_up}
        Example: calc(action="align", value="0x401003", size=0x10)
    """
    try:
        def resolve_int(val):
            if val is None:
                raise ValueError("value required")
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                try:
                    return int(val, 0)
                except ValueError:
                    ea = idc.get_name_ea_simple(val)
                    if ea != idaapi.BADADDR:
                        return ea
            raise ValueError(f"Invalid value: {val}")

        def resolve_addr(val):
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                try:
                    return int(val, 0)
                except ValueError:
                    ea = idc.get_name_ea_simple(val)
                    if ea != idaapi.BADADDR:
                        return ea
            raise ValueError(f"Invalid address: {val}")

        def ptr_size():
            if hasattr(idaapi, "inf_is_64bit"):
                return 8 if idaapi.inf_is_64bit() else 4
            try:
                inf = idaapi.get_inf_structure()
                return 8 if inf.is_64bit() else 4
            except Exception:
                return 8 if (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100) else 4

        def read_int(ea, width, signed=False):
            data = ida_bytes.get_bytes(ea, width)
            if not data or len(data) != width:
                raise ValueError(f"Could not read {width} bytes from {hex(ea)}")
            import struct
            fmts = {
                (1, False): "<B", (1, True): "<b",
                (2, False): "<H", (2, True): "<h",
                (4, False): "<I", (4, True): "<i",
                (8, False): "<Q", (8, True): "<q",
            }
            return struct.unpack(fmts[(width, signed)], data)[0]

        def read_float(ea, width):
            data = ida_bytes.get_bytes(ea, width)
            if not data or len(data) != width:
                raise ValueError(f"Could not read {width} bytes from {hex(ea)}")
            import struct
            return struct.unpack("<f" if width == 4 else "<d", data)[0]

        def read_ptr(ea, width=None):
            width = width or ptr_size()
            return read_int(ea, width, signed=False)

        def read_typed(ea, val_type, val_size):
            if val_type == "bytes":
                if not val_size:
                    raise ValueError("size required for bytes")
                data = ida_bytes.get_bytes(ea, val_size)
                if not data:
                    raise ValueError(f"Could not read {val_size} bytes from {hex(ea)}")
                return " ".join(f"{x:02x}" for x in data)
            if val_type == "u8":
                return read_int(ea, 1, False)
            if val_type == "u16":
                return read_int(ea, 2, False)
            if val_type == "u32":
                return read_int(ea, 4, False)
            if val_type == "u64":
                return read_int(ea, 8, False)
            if val_type == "s8":
                return read_int(ea, 1, True)
            if val_type == "s16":
                return read_int(ea, 2, True)
            if val_type == "s32":
                return read_int(ea, 4, True)
            if val_type == "s64":
                return read_int(ea, 8, True)
            if val_type == "f32":
                return read_float(ea, 4)
            if val_type == "f64":
                return read_float(ea, 8)
            if val_type == "ptr":
                return read_ptr(ea, val_size)
            if val_type == "string":
                s = idaapi.get_strlit_contents(ea, -1, 0)
                if not s:
                    return None
                if len(s) > 65536:
                    s = s[:65536]
                return s.decode("utf-8", errors="replace")
            raise ValueError(f"Unknown type: {val_type}")

        def eval_expr(expression):
            import re
            names = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', expression)
            namespace = {
                "hex": hex, "int": int, "abs": abs,
                "BADADDR": idaapi.BADADDR
            }
            namespace.update({
                "u8": lambda a: read_int(resolve_addr(a), 1, False),
                "u16": lambda a: read_int(resolve_addr(a), 2, False),
                "u32": lambda a: read_int(resolve_addr(a), 4, False),
                "u64": lambda a: read_int(resolve_addr(a), 8, False),
                "s8": lambda a: read_int(resolve_addr(a), 1, True),
                "s16": lambda a: read_int(resolve_addr(a), 2, True),
                "s32": lambda a: read_int(resolve_addr(a), 4, True),
                "s64": lambda a: read_int(resolve_addr(a), 8, True),
                "f32": lambda a: read_float(resolve_addr(a), 4),
                "f64": lambda a: read_float(resolve_addr(a), 8),
                "ptr": lambda a, w=None: read_ptr(resolve_addr(a), w),
            })
            for name in names:
                if name not in namespace:
                    ea = idc.get_name_ea_simple(name)
                    if ea != idaapi.BADADDR:
                        namespace[name] = ea
            return eval(expression, {"__builtins__": {}}, namespace)

        if action == "eval":
            if not expr:
                return make_error(MCPError.INVALID_ARGS, "expr required")
            # Evaluates expressions like "0x401000 + 0x100" or "main + 0x20"
            try:
                res = eval_expr(expr)
                return {
                    "ok": True,
                    "expr": expr,
                    "value": res,
                    "value_hex": hex(res) if isinstance(res, int) else str(res)
                }
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"Evaluation error: {expr} ({e})")

        elif action == "offset":
            if not addr or not target:
                return make_error(MCPError.INVALID_ARGS, "addr and target required")
            
            ea1, err1 = validate_addr(addr)
            if err1: return err1
            ea2, err2 = validate_addr(target)
            if err2: return err2
            
            delta = ea2 - ea1
            return {
                "from": hex(ea1),
                "to": hex(ea2),
                "delta_hex": hex(delta) if delta >= 0 else f"-{hex(abs(delta))}",
                "delta_int": delta
            }

        elif action == "convert":
            if value is None:
                return make_error(MCPError.INVALID_ARGS, "value required")

            # Parse value
            try:
                v = resolve_int(value)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
                
            # ASCII representation (4/8 bytes)
            import struct
            try:
                ascii_val = ""
                for b in struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF):
                    if 32 <= b <= 126:
                        ascii_val += chr(b)
                    else:
                        ascii_val += "."
            except:
                ascii_val = "n/a"
                
            return {
                "hex": hex(v),
                "dec": v,
                "bin": bin(v),
                "ascii": ascii_val,
                "bitmask": f"{v:064b}" if v >= 0 else "n/a"
            }

        elif action == "resolve":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")

            ea, err = validate_addr(addr)
            if err: return err
            
            # Get file offset
            file_off = ida_nalt.get_fileregion_offset(ea)
            seg = idaapi.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else "none"
            
            return {
                "va": hex(ea),
                "file_offset": hex(file_off) if file_off != -1 else "not in file",
                "segment": seg_name
            }

        elif action == "deref":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            val_type = type or "ptr"
            try:
                value_out = read_typed(ea, val_type, size)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            resp = {"ok": True, "addr": hex(ea), "type": val_type, "value": value_out}
            if val_type in ("u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "ptr"):
                resp["value_hex"] = hex(value_out)
            if val_type == "bytes":
                resp["size"] = size
            if val_type == "string":
                resp["length"] = len(value_out) if value_out else 0
            return resp

        elif action == "chain":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if offsets is None:
                return make_error(MCPError.INVALID_ARGS, "offsets required")
            ea, err = validate_addr(addr)
            if err:
                return err
            try:
                offs = normalize_list_input(offsets)
                if not offs:
                    return make_error(MCPError.INVALID_ARGS, "offsets required")
                offs_int = [resolve_int(o) for o in offs]
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            steps = []
            current = ea
            try:
                for off in offs_int:
                    pval = read_ptr(current, size)
                    next_addr = pval + off
                    steps.append({"ptr": hex(pval), "offset": off, "addr": hex(next_addr)})
                    current = next_addr
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            return {"ok": True, "base": hex(ea), "offsets": offs_int, "steps": steps, "final": hex(current)}

        elif action == "align":
            if size is None:
                return make_error(MCPError.INVALID_ARGS, "size (alignment) required")
            try:
                alignment = int(size)
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "Invalid alignment size")
            if alignment <= 0:
                return make_error(MCPError.INVALID_ARGS, "Alignment must be > 0")
            try:
                if addr is not None:
                    align_val = resolve_addr(addr)
                elif expr is not None:
                    align_val = eval_expr(expr)
                    if not isinstance(align_val, int):
                        return make_error(MCPError.INVALID_ARGS, "Expression must evaluate to int")
                else:
                    align_val = resolve_int(value)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"Evaluation error: {expr} ({e})")
            if alignment & (alignment - 1) == 0:
                aligned_down = align_val & ~(alignment - 1)
            else:
                aligned_down = (align_val // alignment) * alignment
            aligned_up = aligned_down if align_val == aligned_down else aligned_down + alignment
            return {
                "ok": True,
                "value": align_val,
                "alignment": alignment,
                "aligned_down": aligned_down,
                "aligned_up": aligned_up,
                "aligned_down_hex": hex(aligned_down),
                "aligned_up_hex": hex(aligned_up),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
