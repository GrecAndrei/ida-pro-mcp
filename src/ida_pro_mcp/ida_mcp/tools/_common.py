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
        _is_regex, smart_match, compile_smart_pattern, resolve_symbol,
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
        _is_regex, smart_match, compile_smart_pattern, resolve_symbol,
    )
    from error_handling import (  # type: ignore[import-not-found]
        MCPError, make_error, handle_error, ERROR_HINTS,
        validate_addr, validate_range, check_debugger, validate_path_safe,
        require_arg, require_one_of, validate_action, validate_count
    )

# Multi-architecture helpers
try:
    from .arch_utils import (  # type: ignore[import-not-found]
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
    from arch_utils import (  # type: ignore[import-not-found]
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
    "_is_regex", "smart_match", "compile_smart_pattern", "resolve_symbol",
    # Error handling
    "MCPError", "make_error", "handle_error", "ERROR_HINTS",
    "validate_addr", "validate_range", "check_debugger", "validate_path_safe",
    "require_arg", "require_one_of", "validate_action", "validate_count",
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
]
