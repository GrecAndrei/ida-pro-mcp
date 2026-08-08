"""Shared IDA SDK helpers.

Portions of this module (several of the ``get_*`` accessors and the
xref/string/constant extraction helpers) derive from ida-pro-mcp by
mrexodia, MIT licensed:

    Copyright (c) 2025 mrexodia
    https://github.com/mrexodia/ida-pro-mcp

The vendored ``ida_mcp/zeromcp`` package is from the same author and keeps
its own LICENSE file alongside the sources.
"""

import json
import struct
from collections.abc import Callable
from typing import (
    Any,
    Literal,
    Optional,
    TypedDict,
    overload,
)

import ida_funcs
import ida_hexrays
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from ida_pro_mcp.services import parse_str_list

# Support both package mode and standalone mode
try:
    from sync import IDAError
except ImportError:
    try:
        from .sync import IDAError
    except ImportError:
        class IDAError(Exception):
            pass

# Smart pattern matching — shared with host (no IDA deps)
try:
    from ida_pro_mcp.services import compile_smart_pattern, smart_match
except ImportError:
    try:
        from ...host.patterns import compile_smart_pattern, smart_match
    except ImportError:
        def compile_smart_pattern(pattern, case_sensitive=False, **kwargs):
            if not pattern:
                return lambda _t: True
            pl = pattern.lower()
            return lambda _t, _p=pl: _p in _t.lower()

        def smart_match(pattern, text, case_sensitive=False):
            return compile_smart_pattern(pattern, case_sensitive)(text)

# ============================================================================
# Helper Functions
# ============================================================================


def get_image_size() -> int:
    try:
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida

        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    image_size = omax_ea - omin_ea
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def is_64bit() -> bool:
    """Check if the current IDB is 64-bit in a way compatible with IDA 7.x-9.x"""
    try:
        from .tools._common import _inf_is_64bit
        return _inf_is_64bit()
    except (ImportError, AttributeError):
        try:
            return idaapi.get_inf_structure().is_64bit()
        except AttributeError:
            return False


def parse_address(addr: str | int) -> int:
    if isinstance(addr, int):
        return addr

    # Try direct integer conversion (hex or decimal)
    try:
        return int(addr, 0)
    except ValueError:
        pass

    # Try resolving as a symbol/name
    import idc
    ea = idc.get_name_ea_simple(addr)
    if ea != idaapi.BADADDR:
        return ea

    # Final attempt: check if it's a hex string without 0x prefix
    try:
        if all(c in "0123456789abcdefABCDEF" for c in addr):
            return int(addr, 16)
    except ValueError:
        pass

    raise IDAError(f"Failed to resolve address or symbol: {addr}")


def normalize_list_input(value: list | str) -> list:
    """Normalize input to list - accepts list or comma-separated string"""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return parse_str_list(value)
    return [value]

def resolve_symbol(query: str) -> dict:
    """Resolve an address or name to a canonical {addr,name,is_func} dict.

    Resolution order:
    1. Address literal (hex/decimal)
    2. Exact symbol name (idc.get_name_ea_simple)
    3. Demangled C++ name (scan idautils.Names() with ida_name.demangle_name)
    4. Gives up — caller falls back to pattern matching
    """
    if query is None:
        raise IDAError("query required")
    # Try address forms first
    try:
        if looks_like_address(str(query)):
            ea = parse_address(str(query))
            name = idc.get_name(ea) or ""
            func = idaapi.get_func(ea)
            return {"addr": hex(ea), "name": name, "is_func": func is not None}
    except Exception:
        pass
    # Try as exact name
    ea = idc.get_name_ea_simple(str(query))
    if ea != idaapi.BADADDR:
        func = idaapi.get_func(ea)
        return {"addr": hex(ea), "name": str(query), "is_func": func is not None}
    # Try demangled C++ name (e.g. "vtable for android::SystemKloProxy").
    # NOTE: ida_name.get_ea's flags param is for SN_* name-search flags, not
    # demangle-format flags — passing MNG_LONG_FORM there silently degrades to
    # a plain (already-failed) name lookup. Scan the name table and compare
    # the demangled form instead.
    try:
        import ida_name
        clean = str(query).strip()
        for ea, name in idautils.Names():
            dname = ida_name.demangle_name(name, ida_name.MNG_LONG_FORM)
            if dname and dname == clean:
                func = idaapi.get_func(ea)
                return {"addr": hex(ea), "name": name, "is_func": func is not None}
    except Exception:
        pass
    # Try scanning all names for an exact match (including renamed symbols)
    clean = str(query).strip()
    for ea, name in idautils.Names():
        if name == clean:
            func = idaapi.get_func(ea)
            return {"addr": hex(ea), "name": name, "is_func": func is not None}
    raise IDAError(f"Not found: {query}")


def normalize_dict_list(
    value: list[dict] | dict | str | list[str] | Any,
    string_parser: Optional[Callable[[str], dict]] = None,
) -> list[dict]:
    """Normalize input to list[dict] with optional string parsing

    Args:
        value: Input value (dict, list[dict], str, list[str], or any)
        string_parser: Optional function to convert string → dict
                      If None, strings → empty dict

    Flow:
        dict → [dict]
        str → split by ',' → list[str] → map(string_parser) → list[dict]
        list[str] → map(string_parser) → list[dict]
        list[dict] → list[dict]
        Any → [{}]
    """
    if isinstance(value, dict):
        return [value]
    elif isinstance(value, list):
        if not value:
            return [{}]
        # Check if list[str] or list[dict]
        if all(isinstance(item, dict) for item in value):
            return value
        elif all(isinstance(item, str) for item in value):
            # list[str] → map with parser
            if string_parser:
                return [string_parser(s.strip()) for s in value if s.strip()]
            return [{}]
        else:
            # Mixed types - filter dicts only
            return [item for item in value if isinstance(item, dict)] or [{}]
    elif isinstance(value, str):
        # Try JSON parse first
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

        # Not JSON - split by comma and parse
        parts = parse_str_list(value)
        if not parts:
            return [{}]

        if string_parser:
            return [string_parser(part) for part in parts]
        return [{}]
    else:
        # Any other type → empty dict
        return [{}]


def looks_like_address(s: str) -> bool:
    """Check if string looks like an address (0x prefix or all hex chars)"""
    if s.startswith(("0x", "0X")):
        return True
    # All hex chars and at least 4 chars → likely address
    return bool(len(s) >= 4 and all(c in "0123456789abcdefABCDEF" for c in s))


class Function(TypedDict):
    """Shape returned by :func:`get_function`."""

    addr: str
    name: str
    size: str


@overload
def get_function(addr: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(addr: int) -> Function: ...


@overload
def get_function(addr: int, *, raise_error: Literal[False]) -> Optional[Function]: ...


def get_function(addr, *, raise_error=True):
    fn = idaapi.get_func(addr)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(addr)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    return Function(addr=hex(addr), name=name, size=hex(fn.end_ea - fn.start_ea))


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except Exception:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)
    # 16-bit integers
    elif type_name in (
        "int16",
        "__int16",
        "int16_t",
        "short",
        "short int",
        "signed short",
        "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
        "uint16",
        "__uint16",
        "uint16_t",
        "unsigned short",
        "unsigned short int",
        "word",
        "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)
    # 32-bit integers
    elif type_name in (
        "int32",
        "__int32",
        "int32_t",
        "int",
        "signed int",
        "long",
        "long int",
        "signed long",
        "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
        "uint32",
        "__uint32",
        "uint32_t",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "dword",
        "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
    # 64-bit integers
    elif type_name in (
        "int64",
        "__int64",
        "int64_t",
        "long long",
        "long long int",
        "signed long long",
        "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
        "uint64",
        "__uint64",
        "uint64_t",
        "unsigned int64",
        "unsigned long long",
        "unsigned long long int",
        "qword",
        "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
        "uint128",
        "__uint128",
        "uint128_t",
        "__uint128_t",
        "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)
    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)
    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)
    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    # Named types
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif
    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")




def refresh_decompiler_ctext(fn_addr: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        fn_addr, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


class StackFrameVariable(TypedDict):
    """One stack frame member returned by get_stack_frame_variables_internal."""

    name: str
    offset: str
    size: str
    type: str


def get_stack_frame_variables_internal(
    fn_addr: int, raise_error: bool
) -> list[StackFrameVariable]:
    try:
        from .sync import ida_major
    except ImportError:
        ida_major = 9  # Assume IDA 9+ in standalone mode

    if ida_major < 9:
        return []

    func = idaapi.get_func(fn_addr)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {fn_addr}")
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members



# Formatting helpers
def hex_ea(ea: int) -> str:
    return hex(ea)

def hex_size(size: int) -> str:
    return hex(size)
