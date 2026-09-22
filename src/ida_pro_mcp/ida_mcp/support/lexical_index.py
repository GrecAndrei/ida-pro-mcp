"""Open the deterministic per-IDB lexical signature index from inside IDA."""

from __future__ import annotations


def get_lexical_index(idb_path: str | None = None):
    """Return ``(index, path)`` without constructing host intelligence state.

    The IDA process uses this adapter for local signature retrieval. Provider
    configuration and credentials are resolved only by the MCP host.
    """
    if not idb_path:
        try:
            import idc

            idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        except Exception:
            idb_path = ""
    if not idb_path:
        return None, ""
    try:
        from ida_pro_mcp.host.intelligence.lexical import LexicalFunctionIndex, signature_index_path
    except ImportError:
        try:
            from host.intelligence.lexical import LexicalFunctionIndex, signature_index_path  # type: ignore
        except ImportError:
            return None, str(idb_path)
    try:
        return LexicalFunctionIndex(signature_index_path(str(idb_path))), str(idb_path)
    except Exception:
        return None, str(idb_path)
