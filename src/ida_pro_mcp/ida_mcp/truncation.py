"""
Back-compat shim.

The canonical implementation of truncation helpers now lives in
``ida_pro_mcp.host.truncation``. This module re-exports the public names so
existing imports of ``ida_pro_mcp.ida_mcp.truncation`` keep working. The
shared module-level state (``_TRUNCATION_STORE`` / ``_TRUNCATION_ORDER``)
remains a single dict, so a ``truncate_response`` call from one side and a
``continue_truncated`` call from the other side see the same tokens.

Phase 2 of DEDUPE_PLAN.md: cross-file helper dedup. Do not add new logic
here; change ``host.truncation`` instead.
"""
from ida_pro_mcp.host.truncation import (  # noqa: F401
    _MAX_TRUNCATION_STORE,
    _MIN_MAX_TOKENS,
    _TRUNCATION_ORDER,
    _TRUNCATION_STORE,
    _store_truncation,
    continue_truncated,
    truncate_response,
)

__all__ = [
    "_MAX_TRUNCATION_STORE",
    "_MIN_MAX_TOKENS",
    "_TRUNCATION_ORDER",
    "_TRUNCATION_STORE",
    "_store_truncation",
    "continue_truncated",
    "truncate_response",
]
