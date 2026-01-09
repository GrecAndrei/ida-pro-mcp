"""
Unified error handling for IDA Pro MCP tools.
Provides standardized error codes, validation helpers, and safe execution wrappers.
"""

import sys
import traceback
from typing import Any, Dict, Optional, Tuple, Union

# Try to import IDA modules (will fail in standalone tests, but that's handled by mocks)
try:
    import idaapi
    import idc
    import ida_funcs
    import ida_segment
    import ida_bytes
    import ida_dbg
except ImportError:
    pass

class MCPError:
    """Structured error codes compatible with ida_mcp_stdio.py"""

    # Generic
    UNKNOWN = "UNKNOWN_ERROR"
    INVALID_ARGS = "INVALID_ARGS"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"

    # File/Path
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"

    # IDA specific
    IDA_ERROR = "IDA_ERROR"
    ADDRESS_INVALID = "ADDRESS_INVALID"
    FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
    SEGMENT_NOT_FOUND = "SEGMENT_NOT_FOUND"
    TYPE_ERROR = "TYPE_ERROR"

    # State
    DEBUGGER_NOT_RUNNING = "DEBUGGER_NOT_RUNNING"
    DEBUGGER_ACTIVE = "DEBUGGER_ACTIVE"  # When operation requires static mode
    DATABASE_LOCKED = "DATABASE_LOCKED"

    # Limits
    SIZE_LIMIT_EXCEEDED = "SIZE_LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"

def make_error(code: str, message: str, hint: str = None, details: Dict = None) -> Dict[str, Any]:
    """Create a standardized error response."""
    result = {
        "error": True,
        "code": code,
        "message": message
    }
    if hint:
        result["hint"] = hint
    if details:
        result["details"] = details
    return result

def handle_error(e: Exception, context: str = None) -> Dict[str, Any]:
    """Standardized error formatter for tool exceptions."""
    trace = traceback.format_exc()
    msg = f"[{context}] {str(e)}" if context else str(e)
    return make_error(MCPError.UNKNOWN, msg, details={"traceback": trace})

# ============================================================================
# Validation Helpers
# ============================================================================

def parse_address_safe(addr_str: Union[str, int]) -> Tuple[Optional[int], Optional[Dict]]:
    """
    Safely parse an address string or integer.
    Returns (address, None) on success, or (None, error_dict) on failure.
    """
    if addr_str is None:
        return None, make_error(MCPError.INVALID_ARGS, "Address is required", "Provide 'addr' parameter")

    if isinstance(addr_str, int):
        return addr_str, None

    try:
        # Try as hex string
        if isinstance(addr_str, str):
            addr_str = addr_str.strip()
            if addr_str.lower().startswith("0x"):
                return int(addr_str, 16), None
            if addr_str.isdigit():
                return int(addr_str), None

            # Try as symbol name
            try:
                import idc
                ea = idc.get_name_ea_simple(addr_str)
                if ea != idc.BADADDR:
                    return ea, None
            except:
                pass

            # Try hex without prefix if it looks like hex
            try:
                return int(addr_str, 16), None
            except:
                pass

        return None, make_error(MCPError.ADDRESS_INVALID, f"Invalid address format: {addr_str}", "Use hex format (0x401000) or a valid symbol name")
    except Exception as e:
        return None, make_error(MCPError.ADDRESS_INVALID, f"Failed to parse address: {str(e)}")

def validate_addr(addr: Union[str, int], require_code: bool = False, require_func: bool = False) -> Tuple[Optional[int], Optional[Dict]]:
    """
    Validate an address exists and meets requirements.
    Returns (address, None) on success, or (None, error_dict) on failure.
    """
    ea, error = parse_address_safe(addr)
    if error:
        return None, error

    try:
        import idaapi
        import ida_bytes
        import ida_funcs

        # Check if address is valid in IDB
        if not idaapi.is_mapped(ea):
             return None, make_error(MCPError.ADDRESS_INVALID, f"Address {hex(ea)} is not mapped in the database", "Check if the address belongs to any segment")

        if require_code:
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                return None, make_error(MCPError.ADDRESS_INVALID, f"Address {hex(ea)} is not code", "Target must be a code address")

        if require_func:
            func = ida_funcs.get_func(ea)
            if not func:
                return None, make_error(MCPError.FUNCTION_NOT_FOUND, f"No function found at {hex(ea)}", "Use 'funcs.create' to define a function here first")

        return ea, None
    except ImportError:
        # For testing without IDA
        return ea, None
    except Exception as e:
        return None, handle_error(e)

def validate_range(start: Union[str, int], end: Union[str, int]) -> Tuple[Optional[int], Optional[int], Optional[Dict]]:
    """
    Validate an address range.
    Returns (start, end, None) on success.
    """
    start_ea, error = parse_address_safe(start)
    if error: return None, None, error

    end_ea, error = parse_address_safe(end)
    if error: return None, None, error

    if start_ea >= end_ea:
        return None, None, make_error(MCPError.INVALID_ARGS, f"Invalid range: start ({hex(start_ea)}) >= end ({hex(end_ea)})")

    # Limit range size to prevent DOS
    MAX_RANGE = 0x10000000 # 256MB
    if end_ea - start_ea > MAX_RANGE:
        return None, None, make_error(MCPError.SIZE_LIMIT_EXCEEDED, f"Range too large ({end_ea - start_ea} bytes)", f"Keep ranges under {MAX_RANGE} bytes")

    return start_ea, end_ea, None

def check_debugger(require_active: bool = True) -> Optional[Dict]:
    """
    Check debugger state.
    Returns None if state is valid, error dict otherwise.
    """
    try:
        import ida_dbg
        is_active = ida_dbg.is_debugger_on()

        if require_active and not is_active:
            return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Debugger is not active", "Use 'debug.start' to launch the process")

        if not require_active and is_active:
            # Some operations might be unsafe during debugging
            # But usually we just warn or handle it
            pass

        return None
    except ImportError:
        return None

def validate_path_safe(path: str, allow_absolute: bool = True) -> Tuple[Optional[str], Optional[Dict]]:
    """
    Validate file path to prevent traversal attacks.
    """
    import os
    if not path:
        return None, make_error(MCPError.INVALID_ARGS, "Path required")

    try:
        normalized = os.path.normpath(path)
        if ".." in normalized and not allow_absolute:
            return None, make_error(MCPError.PATH_TRAVERSAL, "Path traversal detected", "Use absolute paths or paths within CWD")
        return normalized, None
    except Exception as e:
        return None, handle_error(e)
