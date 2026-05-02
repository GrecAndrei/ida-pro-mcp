#!/usr/bin/env python3
"""
Host-side error codes, hints, and error factory.
"""
from typing import Optional


class MCPError:
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_LOCKED = "FILE_LOCKED"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    IDA_CRASHED = "IDA_CRASHED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    INVALID_ARGS = "INVALID_ARGS"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
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


_HOST_ERROR_HINTS = {
    MCPError.FILE_NOT_FOUND: "The file does not exist. Verify the path is correct.",
    MCPError.FILE_LOCKED: "The IDB or file is locked. Close other IDA instances first.",
    MCPError.IDA_TIMEOUT: "IDA took too long to start. Increase IDA_MCP_STARTUP_TIMEOUT or check IDA installation.",
    MCPError.IDA_CRASHED: "IDA exited unexpectedly. Check the log for details.",
    MCPError.NOT_IMPLEMENTED: "This action is not available in the current runtime/build.",
    MCPError.SESSION_REQUIRED: "No active session. Create one with session(action='create', binary_path='...').",
    MCPError.INVALID_ARGS: "Invalid arguments. Check the tool description for valid parameters.",
    MCPError.ACTION_NOT_FOUND: "Unknown action. Check the tool description for valid actions.",
    MCPError.SESSION_NOT_FOUND: "Session not found. Use session(action='list') to see available sessions.",
    MCPError.BATCH_EMPTY: "The batch call list is empty. Provide at least one call.",
    MCPError.BATCH_TOO_LARGE: "Too many batch calls. Limit to 50 calls per batch.",
    MCPError.BOOKMARK_NOT_FOUND: "Bookmark not found. Use bookmarks(action='list') to see bookmarks.",
    MCPError.TRUNCATION_TOKEN_EXPIRED: "Continuation token expired. Re-run the original query.",
    MCPError.TRUNCATION_TOKEN_INVALID: "Invalid continuation token. Check the token value.",
    MCPError.TRUNCATION_FIELD_MISSING: "Requested field not in truncated response.",
    MCPError.RPC_CONNECTION_ERROR: "Cannot connect to IDA. The process may have crashed.",
    MCPError.IO_ERROR: "I/O error while writing to disk. Check disk space and permissions.",
    MCPError.DB_ERROR: "Database error. The index may be corrupted. Try schemaboot(action='delete') then re-ingest.",
}


def make_error(
    code: str,
    message: str,
    recoverable: bool = False,
    details: dict = None,
    hint: str = None,
) -> dict:
    res = {"error": True, "code": code, "message": message, "recoverable": recoverable}
    resolved_hint = hint or _HOST_ERROR_HINTS.get(code)
    if resolved_hint:
        res["hint"] = resolved_hint
    if details:
        res["details"] = details
    return res
