"""
Unified error handling for IDA Pro MCP tools.
Provides standardized error codes, validation helpers, and safe execution wrappers.

Every error includes an LLM-actionable hint so the calling model can self-correct
without burning context tokens on repeated trial-and-error.
"""

import errno
import traceback
from typing import Any, Dict, Optional, Tuple

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py). This module is otherwise
# pure stdlib (host-side code and standalone bridge tests import it without
# IDA), so a failed compat import degrades to None instead of failing load.
try:
    from . import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        try:
            import compat as _compat  # type: ignore[import-not-found,no-redef]
        except ImportError:
            _compat = None  # type: ignore[no-redef]


class MCPError:
    """Structured error codes with LLM-guiding hints.

    Each code maps to a specific error category.  Use ``ERROR_HINTS`` for the
    default recovery suggestion the LLM should follow.
    """

    # --- Generic (1-9) ---
    UNKNOWN = "UNKNOWN_ERROR"
    INVALID_ARGS = "INVALID_ARGS"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_FOUND = "NOT_FOUND"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    MISSING_REQUIRED_ARG = "MISSING_REQUIRED_ARG"
    INVALID_ARG_TYPE = "INVALID_ARG_TYPE"
    INVALID_ARG_VALUE = "INVALID_ARG_VALUE"
    INVALID_ARG_COMBINATION = "INVALID_ARG_COMBINATION"
    MUTUALLY_EXCLUSIVE_ARGS = "MUTUALLY_EXCLUSIVE_ARGS"

    # --- File / Path (10-19) ---
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    FILE_READ_ERROR = "FILE_READ_ERROR"
    FILE_WRITE_ERROR = "FILE_WRITE_ERROR"
    FILE_PERMISSION_DENIED = "FILE_PERMISSION_DENIED"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    FILE_ENCODING_ERROR = "FILE_ENCODING_ERROR"
    DIRECTORY_NOT_FOUND = "DIRECTORY_NOT_FOUND"
    FILE_ALREADY_EXISTS = "FILE_ALREADY_EXISTS"
    INVALID_FILE_FORMAT = "INVALID_FILE_FORMAT"

    # --- IDA / Address (20-39) ---
    IDA_ERROR = "IDA_ERROR"
    ADDRESS_INVALID = "ADDRESS_INVALID"
    ADDRESS_NOT_MAPPED = "ADDRESS_NOT_MAPPED"
    ADDRESS_NOT_CODE = "ADDRESS_NOT_CODE"
    ADDRESS_NOT_DATA = "ADDRESS_NOT_DATA"
    ADDRESS_ALIGNMENT = "ADDRESS_ALIGNMENT"
    FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
    FUNCTION_ALREADY_EXISTS = "FUNCTION_ALREADY_EXISTS"
    FUNCTION_OVERLAP = "FUNCTION_OVERLAP"
    FUNCTION_TOO_LARGE = "FUNCTION_TOO_LARGE"
    SEGMENT_NOT_FOUND = "SEGMENT_NOT_FOUND"
    SEGMENT_OVERLAP = "SEGMENT_OVERLAP"
    TYPE_ERROR = "TYPE_ERROR"
    TYPE_PARSE_ERROR = "TYPE_PARSE_ERROR"
    TYPE_APPLY_ERROR = "TYPE_APPLY_ERROR"
    NAME_CONFLICT = "NAME_CONFLICT"
    NAME_INVALID = "NAME_INVALID"
    STRUCT_NOT_FOUND = "STRUCT_NOT_FOUND"
    STRUCT_MEMBER_ERROR = "STRUCT_MEMBER_ERROR"
    XREF_NOT_FOUND = "XREF_NOT_FOUND"

    # --- Decompiler (40-49) ---
    DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
    DECOMPILER_FAILED = "DECOMPILER_FAILED"
    DECOMPILER_TIMEOUT = "DECOMPILER_TIMEOUT"
    CTREE_ERROR = "CTREE_ERROR"
    MICROCODE_ERROR = "MICROCODE_ERROR"

    # --- Debugger (50-59) ---
    DEBUGGER_NOT_RUNNING = "DEBUGGER_NOT_RUNNING"
    DEBUGGER_ACTIVE = "DEBUGGER_ACTIVE"
    DEBUGGER_BREAKPOINT_ERROR = "DEBUGGER_BREAKPOINT_ERROR"
    DEBUGGER_MEMORY_ERROR = "DEBUGGER_MEMORY_ERROR"
    DEBUGGER_REGISTER_ERROR = "DEBUGGER_REGISTER_ERROR"
    DEBUGGER_STEP_ERROR = "DEBUGGER_STEP_ERROR"
    DEBUGGER_PROCESS_ERROR = "DEBUGGER_PROCESS_ERROR"
    DEBUGGER_THREAD_ERROR = "DEBUGGER_THREAD_ERROR"

    # --- Session (60-69) ---
    SESSION_REQUIRED = "SESSION_REQUIRED"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_ALREADY_EXISTS = "SESSION_ALREADY_EXISTS"
    SESSION_CORRUPTED = "SESSION_CORRUPTED"
    SESSION_LOCKED = "SESSION_LOCKED"
    SESSION_EXPIRED = "SESSION_EXPIRED"

    # --- Database (70-79) ---
    DATABASE_LOCKED = "DATABASE_LOCKED"
    DATABASE_CORRUPTED = "DATABASE_CORRUPTED"
    DATABASE_READ_ONLY = "DATABASE_READ_ONLY"
    DATABASE_NOT_LOADED = "DATABASE_NOT_LOADED"
    DB_ERROR = "DB_ERROR"
    IDB_NOT_FOUND = "IDB_NOT_FOUND"
    IDB_VERSION_MISMATCH = "IDB_VERSION_MISMATCH"

    # --- Limits (80-89) ---
    SIZE_LIMIT_EXCEEDED = "SIZE_LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    RESULT_TOO_LARGE = "RESULT_TOO_LARGE"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    ITERATION_LIMIT = "ITERATION_LIMIT"
    RECURSION_LIMIT = "RECURSION_LIMIT"
    RATE_LIMIT = "RATE_LIMIT"

    # --- Search / Pattern (90-99) ---
    PATTERN_INVALID = "PATTERN_INVALID"
    PATTERN_TOO_SHORT = "PATTERN_TOO_SHORT"
    REGEX_ERROR = "REGEX_ERROR"
    NO_RESULTS = "NO_RESULTS"
    SEARCH_TIMEOUT = "SEARCH_TIMEOUT"

    # --- Export / Import (100-109) ---
    EXPORT_FAILED = "EXPORT_FAILED"
    IMPORT_FAILED = "IMPORT_FAILED"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    PLUGIN_NOT_FOUND = "PLUGIN_NOT_FOUND"
    PLUGIN_ERROR = "PLUGIN_ERROR"
    SIGNATURE_ERROR = "SIGNATURE_ERROR"
    PDB_ERROR = "PDB_ERROR"
    DWARF_ERROR = "DWARF_ERROR"

    # --- Emulation / Analysis (110-119) ---
    EMULATION_ERROR = "EMULATION_ERROR"
    EMULATION_TIMEOUT = "EMULATION_TIMEOUT"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    ARCH_UNSUPPORTED = "ARCH_UNSUPPORTED"
    CALLING_CONVENTION_ERROR = "CALLING_CONVENTION_ERROR"

    # --- Batch (120-124) ---
    BATCH_PARTIAL_FAILURE = "BATCH_PARTIAL_FAILURE"
    BATCH_EMPTY = "BATCH_EMPTY"
    BATCH_TOO_LARGE = "BATCH_TOO_LARGE"

    # --- Truncation / Pagination (125-129) ---
    TRUNCATION_TOKEN_EXPIRED = "TRUNCATION_TOKEN_EXPIRED"
    TRUNCATION_TOKEN_INVALID = "TRUNCATION_TOKEN_INVALID"
    TRUNCATION_FIELD_MISSING = "TRUNCATION_FIELD_MISSING"
    PAGINATION_OUT_OF_RANGE = "PAGINATION_OUT_OF_RANGE"

    # --- Security (130-134) ---
    YARA_COMPILE_ERROR = "YARA_COMPILE_ERROR"
    YARA_SCAN_ERROR = "YARA_SCAN_ERROR"
    CRYPTO_DETECTION_ERROR = "CRYPTO_DETECTION_ERROR"
    VULN_SCAN_ERROR = "VULN_SCAN_ERROR"

    # --- Hook / Script (135-139) ---
    SCRIPT_ERROR = "SCRIPT_ERROR"
    SCRIPT_TIMEOUT = "SCRIPT_TIMEOUT"
    HOOK_ERROR = "HOOK_ERROR"
    IDC_ERROR = "IDC_ERROR"

    # --- Bookmark (140-144) ---
    BOOKMARK_NOT_FOUND = "BOOKMARK_NOT_FOUND"
    BOOKMARK_DUPLICATE = "BOOKMARK_DUPLICATE"

    # --- Diff / Compare (145-149) ---
    DIFF_NO_CHANGES = "DIFF_NO_CHANGES"
    COMPARE_INCOMPATIBLE = "COMPARE_INCOMPATIBLE"

    # --- Network / RPC (150-154) ---
    RPC_CONNECTION_ERROR = "RPC_CONNECTION_ERROR"
    RPC_TIMEOUT = "RPC_TIMEOUT"
    RPC_PROTOCOL_ERROR = "RPC_PROTOCOL_ERROR"

    # --- Annotation (155-159) ---
    ANNOTATION_ERROR = "ANNOTATION_ERROR"
    COMMENT_TOO_LONG = "COMMENT_TOO_LONG"

    # --- Governance (160-164) ---
    GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"

    # --- Bridge / Wire (165-169) ---
    # Codes the IDA-side RPC bridge (server_script) emits for protocol, auth,
    # and payload-limit failures. They ride the same envelope as tool errors so
    # the host's client matching on error.category is uniform on the wire.
    UNAUTHORIZED = "UNAUTHORIZED"
    INVALID_REQUEST = "INVALID_REQUEST"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    INTERNAL = "INTERNAL"


# Default LLM-actionable hints for each error code
ERROR_HINTS: Dict[str, str] = {
    MCPError.UNKNOWN: "An unexpected error occurred. Check the traceback for details and retry.",
    MCPError.UNAUTHORIZED: "Authenticate with the correct session token and retry.",
    MCPError.INVALID_REQUEST: "The request envelope is malformed. Check the request shape.",
    MCPError.REQUEST_TOO_LARGE: "The request payload exceeds the size limit. Reduce it, or raise the request-size limit for trusted local sessions.",
    MCPError.INTERNAL: "An internal failure occurred. Check the traceback for details and retry.",
    MCPError.INVALID_ARGS: "Check the operation schema for valid parameters and retry.",
    MCPError.NOT_IMPLEMENTED: "This operation is not available. Use a different operation.",
    MCPError.NOT_FOUND: "The requested item was not found. Verify the identifier and retry.",
    MCPError.TOOL_NOT_FOUND: "The tool name is wrong. Call tools/list to see available tools.",
    MCPError.ACTION_NOT_FOUND: "The operation is not valid. Use ida_help or tools/list to see valid operations.",
    MCPError.MISSING_REQUIRED_ARG: "A required parameter is missing. Check the error details for which one.",
    MCPError.INVALID_ARG_TYPE: "A parameter has the wrong type (e.g. string instead of int). Fix the type and retry.",
    MCPError.INVALID_ARG_VALUE: "A parameter value is out of range or invalid. Check the allowed values.",
    MCPError.INVALID_ARG_COMBINATION: "The combination of parameters is invalid. Check which params work together.",
    MCPError.MUTUALLY_EXCLUSIVE_ARGS: "Two mutually exclusive parameters were provided. Use only one.",
    MCPError.FILE_NOT_FOUND: "The file does not exist. Verify the path is correct and the file has not been moved.",
    MCPError.PATH_TRAVERSAL: "Path traversal detected. Use absolute paths without '..' components.",
    MCPError.FILE_READ_ERROR: "Cannot read the file. Check permissions and encoding.",
    MCPError.FILE_WRITE_ERROR: "Cannot write the file. Check permissions and disk space.",
    MCPError.FILE_PERMISSION_DENIED: "Permission denied. Check filesystem permissions.",
    MCPError.FILE_TOO_LARGE: "The file is too large to process. Try with a smaller file or use pagination.",
    MCPError.FILE_ENCODING_ERROR: "Encoding error. Try encoding='binary' for binary data or specify the correct encoding.",
    MCPError.DIRECTORY_NOT_FOUND: "The directory does not exist. Create it first or use a valid path.",
    MCPError.FILE_ALREADY_EXISTS: "The file already exists. Use a different name or delete the existing file first.",
    MCPError.INVALID_FILE_FORMAT: "The file format is not recognized. Check it is a valid binary/IDB.",
    MCPError.IDA_ERROR: "An IDA SDK error occurred. Check the details for the specific error.",
    MCPError.ADDRESS_INVALID: "The address format is invalid. Use hex (0x401000) or a symbol name.",
    MCPError.ADDRESS_NOT_MAPPED: "The address is not mapped in the database. Use ida_overview to see mapped ranges and segments.",
    MCPError.ADDRESS_NOT_CODE: "The address does not contain code. Use ida_disassemble to inspect the area, or ida_create_function to define a function at the address.",
    MCPError.ADDRESS_NOT_DATA: "The address does not contain data. It may be code or unexplored.",
    MCPError.ADDRESS_ALIGNMENT: "The address is not properly aligned for this operation.",
    MCPError.FUNCTION_NOT_FOUND: "No function at this address. Use ida_create_function(address='...') to define one, or ida_list_functions to find existing functions.",
    MCPError.FUNCTION_ALREADY_EXISTS: "A function already exists at this address. Delete it first or use a different address.",
    MCPError.FUNCTION_OVERLAP: "The function range overlaps with an existing function.",
    MCPError.FUNCTION_TOO_LARGE: "The function is too large to process in a single request. Use pagination.",
    MCPError.SEGMENT_NOT_FOUND: "No segment found at this address. Use ida_overview to list segments and mapped ranges.",
    MCPError.SEGMENT_OVERLAP: "The segment range overlaps with an existing segment.",
    MCPError.TYPE_ERROR: "Type information error. Check the type declaration syntax.",
    MCPError.TYPE_PARSE_ERROR: "Failed to parse the type declaration. Use C syntax like 'int __cdecl(int, char**)'.",
    MCPError.TYPE_APPLY_ERROR: "Failed to apply the type. The type may be incompatible with this address.",
    MCPError.NAME_CONFLICT: "A symbol with this name already exists. Choose a different name.",
    MCPError.NAME_INVALID: "The name contains invalid characters. Use C identifier rules (a-z, A-Z, 0-9, _).",
    MCPError.STRUCT_NOT_FOUND: "The structure was not found. Search for the type name with ida_find.",
    MCPError.STRUCT_MEMBER_ERROR: "Error adding/modifying structure member. Check offset, size, and type.",
    MCPError.XREF_NOT_FOUND: "No cross-references found at this address.",
    MCPError.DECOMPILER_UNAVAILABLE: "Hex-Rays decompiler is not available. Use ida_disassemble instead.",
    MCPError.DECOMPILER_FAILED: "Decompilation failed for this function. Try ida_disassemble for assembly.",
    MCPError.DECOMPILER_TIMEOUT: "Decompilation timed out. The function may be too complex.",
    MCPError.CTREE_ERROR: "CTree analysis failed. The function may not be decompilable.",
    MCPError.MICROCODE_ERROR: "Microcode extraction failed. Ensure Hex-Rays is available.",
    MCPError.DEBUGGER_NOT_RUNNING: "Debugger is not active. Debugger control is not a public op yet; drive it via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_ACTIVE: "Debugger is active. There is no public debugger op; detach or stop the process via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_BREAKPOINT_ERROR: "No public breakpoint op exists. Manage breakpoints via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_MEMORY_ERROR: "No public debugger-memory op exists. Read/write debugger memory via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_REGISTER_ERROR: "No public debugger-register op exists. Read/write registers via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_STEP_ERROR: "No public step op exists. Step the process via misc(action='python') with the idc/ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_PROCESS_ERROR: "No public process op exists. Start/attach/stop a process via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.DEBUGGER_THREAD_ERROR: "No public thread op exists. Inspect threads via misc(action='python') with the ida_dbg helpers if code execution is authorized.",
    MCPError.SESSION_REQUIRED: "No active session. Create one with ida_open_binary(binary_path='...').",
    MCPError.SESSION_NOT_FOUND: "Session not found. Use ida_session_list to see available sessions.",
    MCPError.SESSION_ALREADY_EXISTS: "A session for this binary already exists. Use force_new=true to create a new one.",
    MCPError.SESSION_CORRUPTED: "Session data is corrupted. Recreate it with ida_open_binary(reanalyze=true).",
    MCPError.SESSION_LOCKED: "Session is locked by another process. Close other IDA instances first.",
    MCPError.SESSION_EXPIRED: "Session has expired. Create a new one with ida_open_binary.",
    MCPError.DATABASE_LOCKED: "The IDB is locked by another process. Close IDA or wait.",
    MCPError.DATABASE_CORRUPTED: "The IDB appears corrupted. Recreate it with ida_open_binary(reanalyze=true).",
    MCPError.DATABASE_READ_ONLY: "The database is read-only. Close other IDA instances.",
    MCPError.DATABASE_NOT_LOADED: "No database is loaded. Load a binary first with ida_open_binary.",
    MCPError.DB_ERROR: "Database error. The index may be corrupted. Delete the .embeddings.db file and re-index.",
    MCPError.IDB_NOT_FOUND: "The IDB file was not found. The session may need to be rebuilt.",
    MCPError.IDB_VERSION_MISMATCH: "IDB version mismatch. The IDB may have been created by a different IDA version.",
    MCPError.SIZE_LIMIT_EXCEEDED: "The requested size exceeds the limit. Use a smaller range or pagination.",
    MCPError.TIMEOUT: "Operation timed out. Try with a smaller scope or increase the timeout.",
    MCPError.RESULT_TOO_LARGE: "The result is too large. Use pagination (offset/count) or add filters.",
    MCPError.DEPTH_LIMIT_EXCEEDED: "Maximum depth reached. Reduce max_depth parameter.",
    MCPError.ITERATION_LIMIT: "Iteration limit reached. Narrow the search scope.",
    MCPError.RECURSION_LIMIT: "Recursion limit reached. The call graph may have cycles.",
    MCPError.RATE_LIMIT: "Too many requests. Wait a moment and retry.",
    MCPError.PATTERN_INVALID: "The search pattern is invalid. Check syntax (regex, glob, or substring).",
    MCPError.PATTERN_TOO_SHORT: "The pattern is too short and would match too many results. Use at least 2 characters.",
    MCPError.REGEX_ERROR: "Invalid regex syntax. Check brackets, escapes, and quantifiers.",
    MCPError.NO_RESULTS: "No results found. Try a broader search or different pattern.",
    MCPError.SEARCH_TIMEOUT: "Search timed out. Narrow the scope with start/end address or limit.",
    MCPError.EXPORT_FAILED: "Export failed. Check the format and output path.",
    MCPError.IMPORT_FAILED: "Import failed. Check the file format and path.",
    MCPError.FORMAT_UNSUPPORTED: "The requested format is not supported.",
    MCPError.PLUGIN_NOT_FOUND: "Plugin not found. No public operation lists plugins; use ida_python if code execution is authorized.",
    MCPError.PLUGIN_ERROR: "Plugin execution failed. Check the plugin name and arguments.",
    MCPError.SIGNATURE_ERROR: "Signature operation failed. Check the signature file format.",
    MCPError.PDB_ERROR: "PDB loading failed. Check the PDB path and format.",
    MCPError.DWARF_ERROR: "DWARF loading failed. Check the debug info format.",
    MCPError.EMULATION_ERROR: (
        "Emulation/emulator operation failed. Check the details for the ida_dbg "
        "call that failed; the active backend may not support the requested "
        "operation. Use emulate(action='info') to see the backend and why it "
        "was chosen."
    ),
    MCPError.EMULATION_TIMEOUT: (
        "The emulation operation timed out (no suspend/breakpoint event within "
        "the timeout). Retry with a larger timeout_ms, step in smaller counts, "
        "or verify the run_to address is reachable. The error is recoverable."
    ),
    MCPError.ANALYSIS_INCOMPLETE: "Analysis is still running. Wait and retry.",
    MCPError.ARCH_UNSUPPORTED: "This architecture is not supported for this operation.",
    MCPError.CALLING_CONVENTION_ERROR: "Calling convention detection failed.",
    MCPError.BATCH_PARTIAL_FAILURE: "Some batch operations failed. Check individual results.",
    MCPError.BATCH_EMPTY: "The batch call list is empty. Provide at least one call.",
    MCPError.BATCH_TOO_LARGE: "Too many batch calls. Limit to 50 calls per batch.",
    MCPError.TRUNCATION_TOKEN_EXPIRED: "The continuation token has expired. Re-run the original query.",
    MCPError.TRUNCATION_TOKEN_INVALID: "Invalid continuation token. Check the token value.",
    MCPError.TRUNCATION_FIELD_MISSING: "The requested field does not exist in the truncated response.",
    MCPError.PAGINATION_OUT_OF_RANGE: "Offset/count is out of range. Check total count.",
    MCPError.YARA_COMPILE_ERROR: "YARA rule compilation failed. Check rule syntax.",
    MCPError.YARA_SCAN_ERROR: "YARA scan failed. Check rule and target.",
    MCPError.CRYPTO_DETECTION_ERROR: "Crypto detection error. Check the address range.",
    MCPError.VULN_SCAN_ERROR: "Vulnerability scan error.",
    MCPError.SCRIPT_ERROR: "Python/IDC script execution failed. Check syntax and IDA API usage.",
    MCPError.SCRIPT_TIMEOUT: "Script execution timed out.",
    MCPError.HOOK_ERROR: "Hook generation failed.",
    MCPError.IDC_ERROR: "IDC script error. Check IDC syntax.",
    MCPError.BOOKMARK_NOT_FOUND: "Bookmark not found. Bookmark mutation isn't a public op; list via idb(action='bookmarks'); manage via misc(action='python') if code execution is authorized.",
    MCPError.BOOKMARK_DUPLICATE: "A bookmark already exists at this address. Bookmark mutation isn't a public op; manage via misc(action='python') if code execution is authorized.",
    MCPError.DIFF_NO_CHANGES: "No differences found between the compared items.",
    MCPError.COMPARE_INCOMPATIBLE: "The items cannot be compared (different architectures or types).",
    MCPError.RPC_CONNECTION_ERROR: "Cannot connect to IDA. The IDA process may have crashed.",
    MCPError.RPC_TIMEOUT: "RPC call timed out. IDA may be busy with analysis.",
    MCPError.RPC_PROTOCOL_ERROR: "RPC protocol error. Unexpected response from IDA.",
    MCPError.ANNOTATION_ERROR: "Annotation operation failed.",
    MCPError.COMMENT_TOO_LONG: "Comment is too long. Keep comments under 1024 characters.",
    MCPError.GOVERNANCE_BLOCKED: "Operation blocked by governance rules. Review the violations and adjust the request accordingly.",
}


# Coarse categories for the error envelope, mirroring ``host/errors.py``
# (user / runtime / policy / internal). Clients match on ``error.category``
# instead of parsing the code, so the IDA-side envelope must carry one too —
# the RPC path passes these dicts through to the wire verbatim.
_CATEGORY_USER = frozenset({
    MCPError.INVALID_ARGS, MCPError.NOT_FOUND, MCPError.TOOL_NOT_FOUND,
    MCPError.ACTION_NOT_FOUND, MCPError.MISSING_REQUIRED_ARG,
    MCPError.INVALID_ARG_TYPE, MCPError.INVALID_ARG_VALUE,
    MCPError.INVALID_ARG_COMBINATION, MCPError.MUTUALLY_EXCLUSIVE_ARGS,
    MCPError.FILE_NOT_FOUND, MCPError.PATH_TRAVERSAL, MCPError.FILE_READ_ERROR,
    MCPError.FILE_WRITE_ERROR, MCPError.FILE_PERMISSION_DENIED,
    MCPError.FILE_TOO_LARGE, MCPError.FILE_ENCODING_ERROR,
    MCPError.DIRECTORY_NOT_FOUND, MCPError.FILE_ALREADY_EXISTS,
    MCPError.INVALID_FILE_FORMAT,
    MCPError.ADDRESS_INVALID, MCPError.ADDRESS_NOT_MAPPED,
    MCPError.ADDRESS_NOT_CODE, MCPError.ADDRESS_NOT_DATA,
    MCPError.ADDRESS_ALIGNMENT, MCPError.FUNCTION_NOT_FOUND,
    MCPError.FUNCTION_ALREADY_EXISTS, MCPError.FUNCTION_OVERLAP,
    MCPError.FUNCTION_TOO_LARGE, MCPError.SEGMENT_NOT_FOUND,
    MCPError.SEGMENT_OVERLAP, MCPError.TYPE_ERROR,
    MCPError.TYPE_PARSE_ERROR, MCPError.TYPE_APPLY_ERROR, MCPError.NAME_CONFLICT,
    MCPError.NAME_INVALID, MCPError.STRUCT_NOT_FOUND,
    MCPError.STRUCT_MEMBER_ERROR, MCPError.XREF_NOT_FOUND,
    MCPError.SIZE_LIMIT_EXCEEDED, MCPError.RESULT_TOO_LARGE,
    MCPError.DEPTH_LIMIT_EXCEEDED, MCPError.ITERATION_LIMIT,
    MCPError.RECURSION_LIMIT, MCPError.RATE_LIMIT, MCPError.PATTERN_INVALID,
    MCPError.PATTERN_TOO_SHORT, MCPError.REGEX_ERROR, MCPError.NO_RESULTS,
    MCPError.FORMAT_UNSUPPORTED, MCPError.PLUGIN_NOT_FOUND,
    MCPError.BATCH_EMPTY, MCPError.BATCH_TOO_LARGE,
    MCPError.TRUNCATION_TOKEN_EXPIRED, MCPError.TRUNCATION_TOKEN_INVALID,
    MCPError.TRUNCATION_FIELD_MISSING, MCPError.PAGINATION_OUT_OF_RANGE,
    MCPError.BOOKMARK_NOT_FOUND, MCPError.BOOKMARK_DUPLICATE,
    MCPError.COMMENT_TOO_LONG, MCPError.COMPARE_INCOMPATIBLE,
    MCPError.DIFF_NO_CHANGES, MCPError.YARA_COMPILE_ERROR,
    # Bridge / wire failures attributable to the caller's request (protocol
    # shape, credentials, oversized payload).
    MCPError.UNAUTHORIZED, MCPError.INVALID_REQUEST, MCPError.REQUEST_TOO_LARGE,
})
_CATEGORY_POLICY = frozenset({
    MCPError.GOVERNANCE_BLOCKED,
})


def _category_for_code(code: str) -> str:
    """Map an error code to its coarse envelope category."""
    if code in _CATEGORY_USER:
        return "user"
    if code in _CATEGORY_POLICY:
        return "policy"
    return "runtime"


def make_error(
    code: str,
    message: str,
    hint: str = None,
    details: Dict = None,
    recoverable: bool = False,
) -> Dict[str, Any]:
    """Create a standardized error response with LLM-actionable guidance.

    If *hint* is not provided, the default from ``ERROR_HINTS`` is used so every
    error automatically carries a recovery suggestion.

    Every envelope carries a ``category`` (user/runtime/policy/internal) so
    clients can branch on it without parsing the code, matching the host-side
    contract in ``host/errors.py``.

    ``recoverable`` is always present (matching :func:`ida_pro_mcp.host.errors.make_error`)
    so clients can rely on the key existing and test it for truthiness rather
    than checking ``"recoverable" in err``.
    """
    result: Dict[str, Any] = {
        "error": True,
        "code": code,
        "category": _category_for_code(code),
        "message": message,
        "recoverable": bool(recoverable),
    }
    resolved_hint = hint or ERROR_HINTS.get(code)
    if resolved_hint:
        result["hint"] = resolved_hint
    if details:
        result["details"] = details
    return result


def _sanitize_exception_message(e: Exception) -> str:
    """Translate common Python exceptions into user-facing messages.

    Prevents raw tracebacks like "'>' not supported between instances of
    'str' and 'int'" from leaking to MCP clients.
    """
    tn = type(e).__name__
    raw = str(e)
    if tn == "TypeError":
        # Common JSON-RPC coercion failures
        if "not supported between instances" in raw:
            return ("Type mismatch in parameter values (string vs int). "
                    "This is usually a JSON-RPC serialization issue — try again.")
        if "missing" in raw and "positional argument" in raw:
            return f"Missing required parameter: {raw}"
        if "unexpected keyword argument" in raw:
            return raw  # already user-friendly
    elif tn == "AttributeError":
        if "has no attribute" in raw:
            # e.g. module 'ida_nalt' has no attribute 'array_parameters'
            return f"IDA API not available in this version: {raw}"
    elif tn == "KeyError":
        return f"Key not found: {raw}"
    elif tn == "ValueError":
        return raw  # usually already descriptive
    elif tn == "OverflowError":
        return f"Value out of range: {raw}"
    return raw


_TIMEOUT_CODES = frozenset({
    MCPError.RPC_TIMEOUT,
    MCPError.DECOMPILER_TIMEOUT,
    MCPError.EMULATION_TIMEOUT,
    MCPError.SEARCH_TIMEOUT,
})


def _timeout_code_for_context(context: Optional[str], message: str = "") -> str:
    """Pick the specialized timeout code for a tool *context* (or message).

    A timeout surfacing from a decompile/search/emulation call is far more
    actionable as its specific code than the generic RPC_TIMEOUT; the RPC
    timeout is the fallback when neither the context nor the exception
    message pins the operation (e.g. a raw ``TimeoutError("decompile hung")``
    raised inside a tool with no context string).
    """
    ctx = str(context or "").lower()
    if "decompil" in ctx or "decompil" in str(message).lower():
        return MCPError.DECOMPILER_TIMEOUT
    if "emulat" in ctx or "emulat" in str(message).lower():
        return MCPError.EMULATION_TIMEOUT
    if "search" in ctx or "search" in str(message).lower():
        return MCPError.SEARCH_TIMEOUT
    return MCPError.RPC_TIMEOUT


def _is_timeout_exception(e: Exception) -> bool:
    """Return True when *e* is a timeout-family exception.

    Covers the ``TimeoutError`` builtin (which ``socket.timeout`` aliases on
    py3.10+) and an ``OSError`` whose errno is ``ETIMEDOUT`` — the two shapes
    a hanging RPC bridge or a wedged IDA operation produces.
    """
    if isinstance(e, TimeoutError):
        return True
    if isinstance(e, OSError):
        etimedout = getattr(errno, "ETIMEDOUT", None)
        if etimedout is not None and getattr(e, "errno", None) == etimedout:
            return True
    return False


def _classify_error_code(e: Exception, context: Optional[str]) -> str:
    """Map an unexpected tool exception to a specific MCPError code.

    Timeouts are the common real-world failure mode — Hex-Rays hanging on a
    pathological function, a slow search over a huge opaque raw blob, an RPC
    socket timing out — and collapsing all of them into ``UNKNOWN_ERROR`` hid
    their retryable nature.  Decompiler/emulation failures that are *not*
    timeouts get their own codes too; only genuinely novel failures fall back
    to ``UNKNOWN`` so they are not mislabeled.
    """
    if _is_timeout_exception(e):
        return _timeout_code_for_context(context, str(e))
    name = type(e).__name__.lower()
    msg = str(e).lower()
    if "decompil" in name or "decompil" in msg:
        return MCPError.DECOMPILER_FAILED
    if "emulat" in name or "emulat" in msg:
        return MCPError.EMULATION_ERROR
    return MCPError.UNKNOWN


def handle_error(e: Exception, context: str = None) -> Dict[str, Any]:
    """Standardized error formatter for tool exceptions.

    Returns a user-facing message instead of a raw Python traceback.
    The full traceback is preserved only in debug details.

    The error ``code`` is dispatched from the exception type (timeouts to
    ``*_TIMEOUT``, decompiler/emulation failures to their codes) so clients
    can react to the actual failure class instead of a blanket UNKNOWN_ERROR.
    Timeout errors are marked ``recoverable`` — retrying the same call is the
    intended remediation.
    """
    trace = traceback.format_exc()
    raw_msg = _sanitize_exception_message(e)
    msg = f"[{context}] {raw_msg}" if context else raw_msg
    code = _classify_error_code(e, context)
    return make_error(
        code,
        msg,
        details={"traceback": trace},
        recoverable=code in _TIMEOUT_CODES,
    )

# ============================================================================
# Validation Helpers
# ============================================================================

def _image_min_ea() -> int:
    """Return the lowest mapped address in the IDB (0 when unavailable)."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_min_ea"):
            return int(ida_ida.inf_get_min_ea())
    except Exception:
        pass
    try:
        import idaapi
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "min_ea", None)
            if v is not None:
                return int(v)
    except Exception:
        pass
    return 0


def _image_max_ea() -> int:
    """Return the highest mapped address in the IDB (BADADDR when unavailable)."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_max_ea"):
            return int(ida_ida.inf_get_max_ea())
    except Exception:
        pass
    try:
        import idaapi
        inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
        if inf is not None:
            v = getattr(inf, "max_ea", None)
            if v is not None:
                return int(v)
    except Exception:
        pass
    return (1 << 64) - 1


def parse_address_canonical(addr_str: str | int) -> Tuple[Optional[int], Optional[Dict]]:
    """Single canonical address parser for every IDA tool.

    Policy (so the same token means the same EA everywhere):
      1. ``int`` (non-negative) → used as-is.
      2. ``"0x"`` / ``"0X"`` prefix → parsed as hex.
      3. known symbol name → resolved via ``idc.get_name_ea_simple``.
      4. bare all-digit string → interpreted as HEX when the hex value maps
         inside the loaded image; rejected with an explicit ``use 0x prefix``
         hint when it is ambiguous (decimal-vs-hex) or unmapped.  This is the
         anti-confusion behavior for opaque raw blobs where addresses are
         habitually written without a prefix (e.g. a RISC-V handler at
         ``800`` in a 0x1000-based image).
      5. floats / booleans / any other token → ``ADDRESS_INVALID``.

    Returns ``(address, None)`` on success or ``(None, error_dict)``.
    """
    if addr_str is None:
        return None, make_error(
            MCPError.MISSING_REQUIRED_ARG,
            "Address is required",
            hint="Provide the 'address' parameter as hex (0x401000) or a symbol name (e.g. 'main').",
        )

    if isinstance(addr_str, bool):
        return None, make_error(
            MCPError.ADDRESS_INVALID,
            f"Invalid address: {addr_str!r} (boolean). Addresses must be hex strings or integers.",
            hint="Provide the 'address' parameter as hex (0x401000) or a symbol name (e.g. 'main').",
        )

    if isinstance(addr_str, int):
        if addr_str < 0:
            return None, make_error(
                MCPError.ADDRESS_INVALID,
                f"Negative address: {addr_str}",
                hint="Addresses must be non-negative integers. Use hex format like 0x401000.",
            )
        return addr_str, None

    if isinstance(addr_str, float):
        # A float address (e.g. 0x401000.9) is almost certainly a caller
        # bug; silently truncating could target the wrong address.
        return None, make_error(
            MCPError.ADDRESS_INVALID,
            f"Invalid address: {addr_str!r} (float). Addresses must be hex strings or integers.",
            hint="Provide the 'address' parameter as hex (0x401000) or a symbol name (e.g. 'main').",
        )

    if not isinstance(addr_str, str):
        return None, make_error(
            MCPError.ADDRESS_INVALID,
            f"Invalid address type: {type(addr_str).__name__!r}. Addresses must be hex strings or integers.",
            hint="Provide the 'address' parameter as hex (0x401000) or a symbol name (e.g. 'main').",
        )

    s = addr_str.strip()
    if not s:
        return None, make_error(
            MCPError.MISSING_REQUIRED_ARG,
            "Address is empty",
            hint="Provide a non-empty address as hex (0x401000) or symbol name.",
        )

    # 1) Explicit 0x/0X prefix — hex, never ambiguous.
    if s.lower().startswith("0x"):
        try:
            ea = int(s, 16)
        except ValueError:
            return None, make_error(
                MCPError.ADDRESS_INVALID,
                f"Invalid hex address: '{addr_str}'",
                hint="Use 0x-prefixed hex like 0x401000, or a symbol name (e.g. 'main').",
            )
        if ea < 0:
            return None, make_error(
                MCPError.ADDRESS_INVALID,
                f"Negative address: {addr_str}",
                hint="Addresses must be non-negative. Use hex format like 0x401000.",
            )
        return ea, None

    # 2) Known symbol.
    try:
        import idc
        ea = idc.get_name_ea_simple(s)
        badaddr = getattr(idc, "BADADDR", -1)
        if ea is not None and ea != badaddr:
            return int(ea), None
    except Exception:
        pass

    # 3) Bare all-digit: interpret as hex only when the hex value maps inside
    #    the loaded image.  Otherwise the token is ambiguous (decimal vs hex)
    #    or points outside the binary — refuse instead of silently picking an
    #    EA, which is exactly how opaque-device analysis gets confused.
    if s.isdigit():
        try:
            ea = int(s, 16)
        except ValueError:
            ea = None
        if ea is not None:
            min_ea = _image_min_ea()
            max_ea = _image_max_ea()
            if min_ea <= ea < max_ea:
                return ea, None
            return None, make_error(
                MCPError.ADDRESS_INVALID,
                f"Ambiguous address '{addr_str}': read as hex {hex(ea)} but it does not map "
                f"inside the loaded image ({hex(min_ea)}..{hex(max_ea - 1)}).",
                hint="Use the 0x prefix (e.g. 0x401000) to force hex, or pass a symbol name.",
            )
        return None, make_error(
            MCPError.ADDRESS_INVALID,
            f"Invalid address: '{addr_str}'",
            hint="Use hex format (0x401000) or a valid symbol name.",
        )

    # 4) Everything else is a weird token — reject rather than guess.
    return None, make_error(
        MCPError.ADDRESS_INVALID,
        f"Invalid address format: '{addr_str}'",
        hint="Use hex format (0x401000) or a valid symbol name. "
             "Use ida_list_functions or ida_find to find addresses.",
    )


def parse_address_safe(addr_str: str | int) -> Tuple[Optional[int], Optional[Dict]]:
    """
    Safely parse an address string or integer.

    Delegates to the single canonical parser (:func:`parse_address_canonical`)
    so a token means the same EA everywhere — bare all-digit strings are read
    as hex when they map inside the image and rejected with a ``use 0x prefix``
    hint when ambiguous or unmapped.

    Returns (address, None) on success, or (None, error_dict) on failure.
    """
    return parse_address_canonical(addr_str)

def validate_addr(addr: str | int, require_code: bool = False, require_func: bool = False) -> Tuple[Optional[int], Optional[Dict]]:
    """
    Validate an address exists and meets requirements.
    Returns (address, None) on success, or (None, error_dict) on failure.
    """
    ea, error = parse_address_safe(addr)
    if error:
        return None, error

    try:
        import ida_bytes
        import idaapi

        # Check if address is valid in IDB
        if not idaapi.is_mapped(ea):
            return None, make_error(
                MCPError.ADDRESS_NOT_MAPPED,
                f"Address {hex(ea)} is not mapped in the database",
                hint="Use ida_overview to see valid address ranges, "
                     "or ida_find to find symbols.",
            )

        if require_code:
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                return None, make_error(
                    MCPError.ADDRESS_NOT_CODE,
                    f"Address {hex(ea)} is not code",
                    hint="Target must be a code address. Use ida_disassemble to inspect the area, "
                         "or ida_create_function to define code at the address.",
                )

        if require_func:
            if _compat is None or _compat.get_func_start(ea) is None:
                return None, make_error(
                    MCPError.FUNCTION_NOT_FOUND,
                    f"No function found at {hex(ea)}",
                    hint=f"Use ida_create_function(address='{hex(ea)}') to define a function here, "
                         f"or ida_list_functions to find existing functions.",
                )

        return ea, None
    except ImportError:
        # For testing without IDA
        return ea, None
    except Exception as e:
        return None, handle_error(e)

def validate_range(start: str | int, end: str | int) -> Tuple[Optional[int], Optional[int], Optional[Dict]]:
    """
    Validate an address range.
    Returns (start, end, None) on success.
    """
    start_ea, error = parse_address_safe(start)
    if error: return None, None, error

    end_ea, error = parse_address_safe(end)
    if error: return None, None, error

    if start_ea >= end_ea:
        return None, None, make_error(
            MCPError.INVALID_ARG_VALUE,
            f"Invalid range: start ({hex(start_ea)}) >= end ({hex(end_ea)})",
            hint="The start address must be less than the end address.",
        )

    # Limit range size to prevent DOS
    MAX_RANGE = 0x10000000  # 256MB
    if end_ea - start_ea > MAX_RANGE:
        return None, None, make_error(
            MCPError.SIZE_LIMIT_EXCEEDED,
            f"Range too large ({end_ea - start_ea} bytes, max {MAX_RANGE})",
            hint=f"Keep ranges under {MAX_RANGE} bytes. Use pagination for large ranges.",
        )

    return start_ea, end_ea, None

def check_debugger(require_active: bool = True) -> Optional[Dict]:
    """
    Check debugger state.
    Returns None if state is valid, error dict otherwise.
    """
    try:
        import ida_dbg
        is_active = bool(ida_dbg.is_debugger_on())
        if not is_active:
            get_state = getattr(ida_dbg, "get_process_state", None)
            state = None
            if callable(get_state):
                try:
                    state = get_state()
                except Exception:
                    state = None
            if state is not None:
                inactive = {
                    getattr(ida_dbg, "DSTATE_NOTASK", None),
                    getattr(ida_dbg, "DSTATE_END", None),
                    getattr(ida_dbg, "DSTATE_PROC_EXIT", None),
                }
                inactive.discard(None)
                if state not in inactive:
                    is_active = True

        if require_active and not is_active:
            return make_error(
                MCPError.DEBUGGER_NOT_RUNNING,
                "Debugger is not active",
            )

        if not require_active and is_active:
            return make_error(
                MCPError.DEBUGGER_ACTIVE,
                "Debugger is active; this operation requires static mode",
            )

        return None
    except ImportError:
        return None

def validate_path_safe(path: str, allow_absolute: bool = True) -> Tuple[Optional[str], Optional[Dict]]:
    """
    Validate file path to prevent traversal attacks.
    """
    import os
    if not path:
        return None, make_error(MCPError.MISSING_REQUIRED_ARG, "Path required")
    if "\x00" in path:
        return None, make_error(MCPError.INVALID_ARG_VALUE, "Path contains null bytes")

    # Check for path traversal (.. components) in the raw path
    if ".." in path.replace("\\", "/").split("/"):
        return None, make_error(MCPError.PATH_TRAVERSAL, "Path traversal detected")
    if not allow_absolute and os.path.isabs(path):
        return None, make_error(MCPError.PATH_TRAVERSAL, "Absolute paths not allowed")

    try:
        normalized = os.path.normpath(path)
        return normalized, None
    except Exception as e:
        return None, handle_error(e)


def require_arg(value, name: str, hint: str = None) -> Optional[Dict]:
    """
    Check that a required argument is present and not None/empty.
    Returns None if valid, error dict if missing.

    Usage:
        err = require_arg(addr, "addr")
        if err: return err
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return make_error(
            MCPError.MISSING_REQUIRED_ARG,
            f"'{name}' parameter is required",
            hint=hint or f"Provide the '{name}' parameter.",
        )
    return None


def require_one_of(**kwargs) -> Optional[Dict]:
    """
    Check that at least one of the specified arguments is present.
    Returns None if valid, error dict if none provided.

    Usage:
        err = require_one_of(addr=addr, name=name, expr=expr)
        if err: return err
    """
    for value in kwargs.values():
        if value is not None and (not isinstance(value, str) or value.strip()):
            return None
    names = ", ".join(f"'{k}'" for k in kwargs)
    return make_error(
        MCPError.MISSING_REQUIRED_ARG,
        f"At least one of {names} is required",
        hint=f"Provide one of: {names}.",
    )


def validate_action(action: str, valid_actions: list, tool_name: str = "") -> Optional[Dict]:
    """
    Validate that an action is in the list of valid actions.
    Returns None if valid, error dict with suggestions if invalid.
    """
    if action in valid_actions:
        return None

    # Find close matches using difflib for better typo correction
    try:
        from ida_pro_mcp.services import best_match
        suggestions = best_match(action or "", list(valid_actions), n=3, cutoff=0.4)
    except ImportError:
        import difflib
        suggestions = difflib.get_close_matches(action or "", valid_actions, n=3, cutoff=0.4)

    msg = f"Unknown action '{action}'"
    if tool_name:
        msg += f" for tool '{tool_name}'"
    hint = f"Valid actions: {', '.join(valid_actions)}"
    if suggestions:
        hint = f"Did you mean: {', '.join(suggestions)}? All valid actions: {', '.join(valid_actions)}"

    return make_error(MCPError.ACTION_NOT_FOUND, msg, hint=hint)


def validate_count(count: int, max_count: int = 10000, param_name: str = "count") -> Optional[Dict]:
    """Validate a count/limit parameter is within range."""
    if count is not None and count < 0:
        return make_error(
            MCPError.INVALID_ARG_VALUE,
            f"'{param_name}' must be non-negative, got {count}",
        )
    if count is not None and count > max_count:
        return make_error(
            MCPError.SIZE_LIMIT_EXCEEDED,
            f"'{param_name}' exceeds maximum ({count} > {max_count})",
            hint=f"Use a value <= {max_count}, or use pagination with offset.",
        )
    return None
