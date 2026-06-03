"""SchemaBoot tool shim - forwarded to structural actions in the intelligence tool.

Maintains backward compatibility for legacy clients, CLI shortcuts, and scripts.
"""
from __future__ import annotations
from typing import Literal, Annotated, Optional

try:
    from ._common import *
except ImportError:
    from _common import *

try:
    from .intelligence import intelligence as _intelligence
except ImportError:
    try:
        from intelligence import intelligence as _intelligence
    except ImportError:
        from ida_pro_mcp.ida_mcp.tools.intelligence import intelligence as _intelligence

try:
    from .string_ops import shannon_entropy as _shannon_entropy
except ImportError:
    from string_ops import shannon_entropy as _shannon_entropy

@tool
@idaread
def schemaboot(
    action: Annotated[Literal["extract", "extract_single", "ingest", "query", "get", "stats", "delete", "refresh"], "Action"],
    addr: Annotated[Optional[str], "Function address"] = None,
    **kwargs
) -> dict:
    """Backward compatibility wrapper mapping schemaboot actions to intelligence structural actions."""
    mapped = f"structural_{action}"
    return _intelligence(action=mapped, addr=addr, **kwargs)
