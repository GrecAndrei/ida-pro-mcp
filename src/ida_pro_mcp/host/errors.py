#!/usr/bin/env python3
"""
Host-side error codes, hints, and error factory.

Each error code has a ``category`` — a coarse classification callers can
use to decide whether to retry, give up, or surface to a user. Categories:

  * "user"       — bad input from the caller (wrong arg, unknown action, etc.)
  * "runtime"    — IDA, filesystem, or DB problem at the host
  * "policy"     — governance / safety gate denied the call (needs ack or
                   falls into a phase that requires follow-up)
  * "internal"   — bug or unclassified failure

Clients can match on ``error.category`` instead of parsing the code.
"""

from __future__ import annotations

from typing import Any


class ErrorCategory:
    USER = "user"
    RUNTIME = "runtime"
    POLICY = "policy"
    INTERNAL = "internal"


class MCPError:
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_LOCKED = "FILE_LOCKED"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    IDA_BUSY = "IDA_BUSY"
    IDA_CRASHED = "IDA_CRASHED"
    SAFE_MODE = "SAFE_MODE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    INVALID_ARGS = "INVALID_ARGS"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    BATCH_EMPTY = "BATCH_EMPTY"
    BATCH_TOO_LARGE = "BATCH_TOO_LARGE"
    BOOKMARK_NOT_FOUND = "BOOKMARK_NOT_FOUND"
    TRUNCATION_TOKEN_EXPIRED = "TRUNCATION_TOKEN_EXPIRED"
    TRUNCATION_TOKEN_INVALID = "TRUNCATION_TOKEN_INVALID"
    TRUNCATION_FIELD_MISSING = "TRUNCATION_FIELD_MISSING"
    RPC_CONNECTION_ERROR = "RPC_CONNECTION_ERROR"
    IO_ERROR = "IO_ERROR"
    DB_ERROR = "DB_ERROR"
    NOT_FOUND = "NOT_FOUND"
    IDA_ERROR = "IDA_ERROR"
    POLICY_DENIED = "POLICY_DENIED"
    PHASE_GATE = "PHASE_GATE"
    DECOMPILER_FAILED = "DECOMPILER_FAILED"
    YARA_COMPILE_ERROR = "YARA_COMPILE_ERROR"
    YARA_SCAN_ERROR = "YARA_SCAN_ERROR"
    YARA_DISABLED = "YARA_DISABLED"
    NO_RESULTS = "NO_RESULTS"
    ADDRESS_INVALID = "ADDRESS_INVALID"
    SIZE_LIMIT_EXCEEDED = "SIZE_LIMIT_EXCEEDED"
    RATE_LIMIT = "RATE_LIMIT"
    STUCK_LOOP = "STUCK_LOOP"
    # Optional radare2/Rizin subprocess engine (Architecture A, Phase 1)
    R2_ENGINE_START_FAILED = "R2_ENGINE_START_FAILED"
    R2_TIMEOUT = "R2_TIMEOUT"
    R2_PROCESS_DIED = "R2_PROCESS_DIED"
    R2_BINARY_NOT_FOUND = "R2_BINARY_NOT_FOUND"
    INTERNAL = "INTERNAL"


# Code → category. Codes absent from this map fall back to "internal".
_ERROR_CATEGORIES: dict[str, str] = {
    MCPError.FILE_NOT_FOUND: ErrorCategory.USER,
    MCPError.FILE_LOCKED: ErrorCategory.RUNTIME,
    MCPError.NOT_FOUND: ErrorCategory.USER,
    MCPError.TOOL_NOT_FOUND: ErrorCategory.USER,
    MCPError.ACTION_NOT_FOUND: ErrorCategory.USER,
    MCPError.INVALID_ARGS: ErrorCategory.USER,
    MCPError.BOOKMARK_NOT_FOUND: ErrorCategory.USER,
    MCPError.SESSION_NOT_FOUND: ErrorCategory.USER,
    MCPError.SESSION_REQUIRED: ErrorCategory.USER,
    MCPError.BATCH_EMPTY: ErrorCategory.USER,
    MCPError.BATCH_TOO_LARGE: ErrorCategory.USER,
    MCPError.TRUNCATION_TOKEN_EXPIRED: ErrorCategory.USER,
    MCPError.TRUNCATION_TOKEN_INVALID: ErrorCategory.USER,
    MCPError.TRUNCATION_FIELD_MISSING: ErrorCategory.USER,
    MCPError.NOT_IMPLEMENTED: ErrorCategory.USER,
    MCPError.IDA_TIMEOUT: ErrorCategory.RUNTIME,
    MCPError.IDA_BUSY: ErrorCategory.RUNTIME,
    MCPError.SAFE_MODE: ErrorCategory.POLICY,
    MCPError.IDA_CRASHED: ErrorCategory.RUNTIME,
    MCPError.RPC_CONNECTION_ERROR: ErrorCategory.RUNTIME,
    MCPError.IDA_ERROR: ErrorCategory.RUNTIME,
    MCPError.DECOMPILER_FAILED: ErrorCategory.RUNTIME,
    MCPError.IO_ERROR: ErrorCategory.RUNTIME,
    MCPError.DB_ERROR: ErrorCategory.RUNTIME,
    MCPError.POLICY_DENIED: ErrorCategory.POLICY,
    MCPError.PHASE_GATE: ErrorCategory.POLICY,
    MCPError.YARA_COMPILE_ERROR: ErrorCategory.USER,
    MCPError.YARA_SCAN_ERROR: ErrorCategory.RUNTIME,
    MCPError.YARA_DISABLED: ErrorCategory.RUNTIME,
    MCPError.NO_RESULTS: ErrorCategory.USER,
    MCPError.ADDRESS_INVALID: ErrorCategory.USER,
    MCPError.SIZE_LIMIT_EXCEEDED: ErrorCategory.USER,
    MCPError.RATE_LIMIT: ErrorCategory.RUNTIME,
    MCPError.STUCK_LOOP: ErrorCategory.RUNTIME,
    MCPError.R2_ENGINE_START_FAILED: ErrorCategory.RUNTIME,
    MCPError.R2_TIMEOUT: ErrorCategory.RUNTIME,
    MCPError.R2_PROCESS_DIED: ErrorCategory.RUNTIME,
    MCPError.R2_BINARY_NOT_FOUND: ErrorCategory.USER,
}


_HOST_ERROR_HINTS = {
    MCPError.NOT_FOUND: "The requested item was not found.",
    MCPError.FILE_NOT_FOUND: "The file does not exist. Verify the path is correct.",
    MCPError.FILE_LOCKED: "The IDB or file is locked. Close other IDA instances first.",
    MCPError.IDA_TIMEOUT: "IDA took too long to start. Increase IDA_MCP_STARTUP_TIMEOUT or check IDA installation.",
    MCPError.IDA_CRASHED: "IDA exited unexpectedly. Check the log for details.",
    MCPError.NOT_IMPLEMENTED: "This operation is not available in the current runtime/build.",
    MCPError.SESSION_REQUIRED: "No active session. Create one with ida_open_binary(binary_path='...').",
    MCPError.INVALID_ARGS: "Invalid arguments. Check the operation schema for valid parameters.",
    MCPError.ACTION_NOT_FOUND: "Unknown operation. Use ida_help or tools/list to see valid operations.",
    MCPError.SAFE_MODE: "IDA auto-analysis is still running for this session. Only manual, small-area operations are allowed until analysis completes; poll ida_session_status for safe_mode to clear.",
    MCPError.TOOL_NOT_FOUND: "Unknown tool. Call tools/list to see valid tool names.",
    MCPError.SESSION_NOT_FOUND: "Session not found. Use ida_session_list to see available sessions.",
    MCPError.BATCH_EMPTY: "The batch call list is empty. Provide at least one call.",
    MCPError.BATCH_TOO_LARGE: "Too many batch calls. Limit to 50 calls per batch.",
    MCPError.BOOKMARK_NOT_FOUND: "Bookmark not found. Bookmark mutation isn't a public op; list via idb(action='bookmarks'); manage via misc(action='python') if code execution is authorized.",
    MCPError.TRUNCATION_TOKEN_EXPIRED: "Continuation token expired. Re-run the original query.",
    MCPError.TRUNCATION_TOKEN_INVALID: "Invalid continuation token. Check the token value.",
    MCPError.TRUNCATION_FIELD_MISSING: "Requested field not in truncated response.",
    MCPError.RPC_CONNECTION_ERROR: "Cannot connect to IDA. The process may have crashed.",
    MCPError.IO_ERROR: "I/O error while writing to disk. Check disk space and permissions.",
    MCPError.DB_ERROR: "Database error. The index may be corrupted. Delete the .embeddings.db file and re-index.",
    MCPError.POLICY_DENIED: "Action denied by the safety policy. Retry with the required acknowledgement, or operate in a different mode.",
    MCPError.PHASE_GATE: "The session phase requires a follow-up call before this tool can return a final answer. See required_followup_call in the response.",
    MCPError.DECOMPILER_FAILED: "The decompiler refused this function. Try ida_disassemble for assembly.",
    MCPError.YARA_COMPILE_ERROR: "YARA rule compilation failed. Check rule syntax.",
    MCPError.YARA_SCAN_ERROR: "YARA scan failed. Check rule and target.",
    MCPError.YARA_DISABLED: "yara-python is not installed. Run `pip install yara-python` in the MCP host venv.",
    MCPError.NO_RESULTS: "No results found for this query.",
    MCPError.ADDRESS_INVALID: "The address format is invalid. Use hex (0x401000) or a symbol name.",
    MCPError.SIZE_LIMIT_EXCEEDED: "The requested size exceeds the limit. Use a smaller range or pagination.",
    MCPError.RATE_LIMIT: "Rate limit exceeded. Reduce call frequency or wait a moment before retrying.",
    MCPError.STUCK_LOOP: "Repeated identical analysis steps detected. Change approach before continuing.",
    MCPError.R2_ENGINE_START_FAILED: "The radare2/Rizin engine failed to start. Verify the binary is installed and executable, then retry.",
    MCPError.R2_TIMEOUT: "The r2 engine subprocess exceeded its wall-clock cap. Increase IDA_MCP_R2_TIMEOUT_SEC or reduce the request size.",
    MCPError.R2_PROCESS_DIED: "The r2 engine subprocess died before returning a result. Check the engine binary and retry.",
    MCPError.R2_BINARY_NOT_FOUND: "The r2 target binary was not found, or no engine binary (rz/r2) is installed. Set IDA_MCP_R2_BIN or install the engine with the installer --with-r2 flag.",
}

# Recovery actions: suggested public operations the LLM can auto-execute when this error occurs.
_RECOVERY_ACTIONS: dict[str, list[dict]] = {
    MCPError.DECOMPILER_FAILED: [
        {"tool": "ida_disassemble", "args": {"address": "$addr"}, "note": "Fall back to disassembly"},
    ],
    MCPError.SESSION_REQUIRED: [
        {"tool": "ida_open_binary", "args": {"binary_path": "$binary_path"}, "note": "Create a session first"},
    ],
    MCPError.ADDRESS_INVALID: [
        {"tool": "ida_calc_convert", "args": {"value": "$addr"}, "note": "Verify address is valid hex"},
    ],
    MCPError.IDA_TIMEOUT: [
        {"tool": "ida_session_health", "args": {}, "note": "Check IDA health"},
    ],
}


def make_error(
    code: str,
    message: str,
    recoverable: bool = False,
    details: dict | None = None,
    hint: str | None = None,
) -> dict:
    res: dict[str, Any] = {
        "error": True,
        "code": code,
        "category": _ERROR_CATEGORIES.get(code, ErrorCategory.INTERNAL),
        "message": message,
        "recoverable": recoverable,
    }
    resolved_hint = hint or _HOST_ERROR_HINTS.get(code)
    if resolved_hint:
        res["hint"] = resolved_hint
    if details:
        res["details"] = details
    recovery = _RECOVERY_ACTIONS.get(code)
    if recovery:
        res["recovery"] = recovery
    return res


def is_error_result(payload) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("error"):
        return True
    return payload.get("ok") is False
