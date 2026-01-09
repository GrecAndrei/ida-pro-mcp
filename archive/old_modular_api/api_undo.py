"""Undo/Redo operations for IDA Pro MCP.

This module provides access to IDA's undo/redo stack.
"""

from typing import Annotated

try:
    import ida_undo
except ImportError:
    ida_undo = None # Older IDA versions

from .rpc import tool, unsafe
from .sync import idawrite, IDAError


@tool
@idawrite
def undo() -> dict:
    """Undo the last operation"""
    if not ida_undo:
        return {"error": "Undo API not available in this IDA version"}
        
    if ida_undo.undo():
        return {"ok": True}
    else:
        return {"error": "Nothing to undo or undo failed"}


@tool
@idawrite
def redo() -> dict:
    """Redo the previously undone operation"""
    if not ida_undo:
        return {"error": "Undo API not available in this IDA version"}
        
    if ida_undo.redo():
        return {"ok": True}
    else:
        return {"error": "Nothing to redo or redo failed"}
