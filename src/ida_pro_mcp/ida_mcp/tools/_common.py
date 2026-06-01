"""
Shared imports for all IDA MCP tool modules.

Usage in tool files:
    from ._common import *
    # or in standalone mode:
    from _common import *

This eliminates ~30 lines of boilerplate per tool file.
"""

import io
import sys
import os
from typing import Annotated, Optional, Literal, Union, Any

# IDA SDK imports
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

# Infrastructure discovery - supports both package and standalone modes
try:
    # Package mode
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size,
        smart_match, compile_smart_pattern, resolve_symbol,
    )
    from ida_mcp.error_handling import (
        MCPError, make_error, handle_error, ERROR_HINTS,
        validate_addr, validate_range, check_debugger, validate_path_safe,
        require_arg, require_one_of, validate_action, validate_count
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)

    from rpc import tool, unsafe  # type: ignore[import-not-found]
    from sync import idaread, idawrite, IDAError  # type: ignore[import-not-found]
    from utils import (  # type: ignore[import-not-found]
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size,
        smart_match, compile_smart_pattern, resolve_symbol,
    )
    from error_handling import (  # type: ignore[import-not-found]
        MCPError, make_error, handle_error, ERROR_HINTS,
        validate_addr, validate_range, check_debugger, validate_path_safe,
        require_arg, require_one_of, validate_action, validate_count
    )

# Centralized API categories (deduplication)
try:
    from ..support._api_categories import (
        API_CATEGORIES, API_TO_CATEGORY, DANGEROUS_APIS,
        TAG_CATEGORIES, API_TO_TAG, MAGIC_CONSTANTS,
    )
except ImportError:
    from support._api_categories import (  # type: ignore[import-not-found]
        API_CATEGORIES, API_TO_CATEGORY, DANGEROUS_APIS,
        TAG_CATEGORIES, API_TO_TAG, MAGIC_CONSTANTS,
    )

# Multi-architecture helpers
try:
    from ..support.arch_utils import (  # type: ignore[import-not-found]
        get_arch, is_x86_family, is_arm_family, is_mips_family,
        is_ppc_family, is_riscv_family, is_sparc_family,
        is_return_mnemonic, is_call_mnemonic, is_syscall_mnemonic,
        get_return_register, get_stack_pointer_names, get_callee_saved_registers,
        get_prologue_pattern, get_epilogue_pattern, get_tail_call_mnemonics,
        RETURN_MNEMONICS, UNCONDITIONAL_JUMP_MNEMONICS, CALL_MNEMONICS,
        CONDITIONAL_BRANCH_MNEMONICS, TERMINATOR_MNEMONICS, SYSCALL_MNEMONICS,
        MOV_MNEMONICS, COMPARISON_MNEMONICS, XOR_MNEMONICS,
        ARITHMETIC_MNEMONICS, INTERESTING_INSTRUCTIONS,
    )
except ImportError:
    from support.arch_utils import (  # type: ignore[import-not-found]
        get_arch, is_x86_family, is_arm_family, is_mips_family,
        is_ppc_family, is_riscv_family, is_sparc_family,
        is_return_mnemonic, is_call_mnemonic, is_syscall_mnemonic,
        get_return_register, get_stack_pointer_names, get_callee_saved_registers,
        get_prologue_pattern, get_epilogue_pattern, get_tail_call_mnemonics,
        RETURN_MNEMONICS, UNCONDITIONAL_JUMP_MNEMONICS, CALL_MNEMONICS,
        CONDITIONAL_BRANCH_MNEMONICS, TERMINATOR_MNEMONICS, SYSCALL_MNEMONICS,
        MOV_MNEMONICS, COMPARISON_MNEMONICS, XOR_MNEMONICS,
        ARITHMETIC_MNEMONICS, INTERESTING_INSTRUCTIONS,
    )


# ============================================================================
# Safe IDA info API wrappers — compatible IDA 7.x through 9.x
# IDA 9 removed get_inf_structure() and cvar.inf in favour of ida_ida.inf_*
# Always use these helpers instead of calling idaapi.get_inf_structure() directly.
# ============================================================================

def _inf_is_64bit() -> bool:
    """Return True if the current IDB is 64-bit."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_64bit"):
            return bool(ida_ida.inf_is_64bit())
    except Exception:
        pass
    try:
        if hasattr(idaapi, "inf_is_64bit"):
            return bool(idaapi.inf_is_64bit())
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None and hasattr(inf, "is_64bit"):
            return bool(inf.is_64bit())
    except Exception:
        pass
    return False


def _inf_is_be() -> bool:
    """Return True if the current IDB is big-endian."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_be"):
            return bool(ida_ida.inf_is_be())
    except Exception:
        pass
    try:
        if hasattr(idaapi, "inf_is_be"):
            return bool(idaapi.inf_is_be())
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None and hasattr(inf, "is_be"):
            return bool(inf.is_be())
    except Exception:
        pass
    return False


def _inf_min_ea() -> int:
    """Return the lowest address in the IDB."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_min_ea"):
            return int(ida_ida.inf_get_min_ea())
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "min_ea", None)
            if v is not None:
                return int(v)
    except Exception:
        pass
    try:
        return int(idaapi.cvar.inf.min_ea)
    except Exception:
        pass
    return 0


def _inf_max_ea() -> int:
    """Return the highest address in the IDB."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_max_ea"):
            return int(ida_ida.inf_get_max_ea())
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "max_ea", None)
            if v is not None:
                return int(v)
    except Exception:
        pass
    try:
        return int(idaapi.cvar.inf.max_ea)
    except Exception:
        pass
    return idaapi.BADADDR


def _inf_start_ea() -> int:
    """Return the program entry point address."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_start_ea"):
            return int(ida_ida.inf_get_start_ea())
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "start_ea", None)
            if v is not None and v != idaapi.BADADDR:
                return int(v)
    except Exception:
        pass
    return idaapi.BADADDR


def _inf_ptr_size() -> int:
    """Return pointer size in bytes (4 or 8)."""
    return 8 if _inf_is_64bit() else 4


def _inf_procname() -> str:
    """Return processor name from IDB info."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_procname"):
            return str(ida_ida.inf_get_procname() or "")
    except Exception:
        pass
    try:
        v = idc.get_inf_attr(getattr(idc, "INF_PROCNAME", -1))
        if v is not None:
            return str(v or "")
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            return str(getattr(inf, "procname", "") or "")
    except Exception:
        pass
    return ""


def _inf_filetype_id() -> int:
    """Return numeric IDA filetype id."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_filetype"):
            return int(ida_ida.inf_get_filetype())
    except Exception:
        pass
    try:
        v = idc.get_inf_attr(getattr(idc, "INF_FILETYPE", -1))
        if v is not None:
            return int(v)
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "filetype", None)
            if v is not None:
                return int(v)
    except Exception:
        pass
    return 0


def _filetype_name(filetype_id: int | None = None) -> str:
    """Map filetype id to a stable lowercase name."""
    ft = _inf_filetype_id() if filetype_id is None else int(filetype_id)
    names = {
        0: "unknown",
        1: "exe",
        2: "obj",
        3: "lib",
        4: "script",
        7: "elf",
        8: "pe",
        9: "coff",
        10: "macho",
        17: "raw",
    }
    return names.get(ft, f"type_{ft}")


def _inf_bitness() -> int:
    """Return effective IDB bitness as 16/32/64."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_16bit") and ida_ida.inf_is_16bit():
            return 16
    except Exception:
        pass
    if _inf_is_64bit():
        return 64
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_32bit_exactly") and ida_ida.inf_is_32bit_exactly():
            return 32
    except Exception:
        pass
    return 32


__all__ = [
    # typing
    "Annotated", "Optional", "Literal", "Union", "Any",
    # stdlib
    "io", "sys", "os",
    # IDA SDK
    "idaapi", "idautils", "idc",
    "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf",
    "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin",
    "ida_frame", "ida_lines",
    # MCP infrastructure
    "tool", "unsafe", "idaread", "idawrite", "IDAError",
    # Utilities
    "parse_address", "normalize_list_input", "normalize_dict_list",
    "get_function", "get_prototype", "get_image_size", "looks_like_address",
    "get_stack_frame_variables_internal", "get_type_by_name", "hex_ea", "hex_size",
    "smart_match", "compile_smart_pattern", "resolve_symbol",
    # Error handling
    "MCPError", "make_error", "handle_error", "ERROR_HINTS",
    "validate_addr", "validate_range", "check_debugger", "validate_path_safe",
    "require_arg", "require_one_of", "validate_action", "validate_count",
    # Centralized API categories
    "API_CATEGORIES", "API_TO_CATEGORY", "DANGEROUS_APIS",
    "TAG_CATEGORIES", "API_TO_TAG", "MAGIC_CONSTANTS",
    # Multi-architecture helpers
    "get_arch", "is_x86_family", "is_arm_family", "is_mips_family",
    "is_ppc_family", "is_riscv_family", "is_sparc_family",
    "is_return_mnemonic", "is_call_mnemonic", "is_syscall_mnemonic",
    "get_return_register", "get_stack_pointer_names", "get_callee_saved_registers",
    "get_prologue_pattern", "get_epilogue_pattern", "get_tail_call_mnemonics",
    "RETURN_MNEMONICS", "UNCONDITIONAL_JUMP_MNEMONICS", "CALL_MNEMONICS",
    "CONDITIONAL_BRANCH_MNEMONICS", "TERMINATOR_MNEMONICS", "SYSCALL_MNEMONICS",
    "MOV_MNEMONICS", "COMPARISON_MNEMONICS", "XOR_MNEMONICS",
    "ARITHMETIC_MNEMONICS", "INTERESTING_INSTRUCTIONS",
    # Safe IDA info API helpers
    "_inf_is_64bit", "_inf_is_be", "_inf_min_ea", "_inf_max_ea",
    "_inf_start_ea", "_inf_ptr_size",
    "_inf_procname", "_inf_filetype_id", "_filetype_name", "_inf_bitness",
]
