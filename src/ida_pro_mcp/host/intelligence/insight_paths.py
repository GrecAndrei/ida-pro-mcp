"""Filesystem helpers for L1 insight-index persistence."""

from __future__ import annotations

import os
import tempfile


def resolve_insight_index_path(cache_dir: str | None = None) -> str:
    """Return the insight index JSON path scoped to the active IDB when possible."""
    try:
        import idc as _idc

        idb_path = str(_idc.get_idb_path() or "").strip()
        if idb_path:
            return idb_path + ".insight_index.json"
    except Exception:
        pass

    root = (
        cache_dir
        or os.environ.get("IDA_MCP_CACHE_DIR")
        or os.environ.get("IDA_MCP_DATA_DIR")
    )
    if not root:
        root = os.path.join(tempfile.gettempdir(), "ida-pro-mcp")
    return os.path.join(root, "insight_index.json")
