#!/usr/bin/env python3
"""
Host package initialization — re-exports all public APIs.
"""
from .analysis.patterns import compile_smart_pattern, smart_match
from .config import (
    BRIDGE_LOG,
    CACHE_DIR,
    PROCESS_TERMINATION_TIMEOUT_SECONDS,
    RUNTIME_LEASE_HEARTBEAT_SECONDS,
    RUNTIME_LEASE_TTL,
    SEMANTIC_GADGET_SOURCE_ACTIONS,
    SEMANTIC_INDEX_DB_NAME,
    SEMANTIC_INDEX_MAX_QUERY_WORKERS,
    SEMANTIC_INDEX_MAX_WORKERS,
    SEMANTIC_INDEX_SOURCE_LIMIT,
    SEMANTIC_INDEX_VERSION,
    SEMANTIC_INDEX_WAIT_SECONDS,
    SEMANTIC_SCORE_PATTERN_MATCH,
    SEMANTIC_SCORE_PER_TOKEN,
    SEMANTIC_SCORE_SUBSTRING_MATCH,
    _bounded_int,
    _coerce_bool,
    _default_runtime_dir,
    _env_bool,
    _normalize_session_id,
    _parse_iso_datetime,
    _parse_line_range,
    _parse_str_list,
    _resolve_runtime_dir,
    _select_runtime_dir,
    log_rpc,
)
from .errors import MCPError, make_error
from .schemas import (
    ACTION_ALIASES_BY_TOOL,
    ADVERTISED_TOOLS,
    ARG_ALIASES_BY_TOOL,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_ALIASES,
    TOOL_ARG_SCHEMAS,
    TOOL_DESCRIPTIONS,
    TOOLS,
    _resolve_tool_alias,
    _strip_balanced_wrappers,
    build_input_schema,
    build_input_schema_lean,
    build_input_schema_ultra,
    build_tool_description_lean,
    build_tool_description_ultra,
    classify_tool_category,
    sanitize_schema_for_vertex,
)
from .stores.truncation import continue_truncated, peek_truncated, search_truncated, summary_truncated, truncate_response


# Lazy import to break a module-load cycle:
#   host.__init__ → server.server → server.server_blackboard → host.config
# When server_blackboard does ``from ..config import _bounded_int`` it re-enters
# host.__init__, which would otherwise re-trigger ``from .server.server import
# IDAMCPServer`` before that submodule has finished loading.  Deferring the
# import to attribute access time means the submodule is fully loaded by then.
def __getattr__(name: str):  # noqa: E501 — PEP 562 lazy import
    if name == "IDAMCPServer":
        from .server.server import IDAMCPServer as _srv
        return _srv
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "CACHE_DIR",
    "BRIDGE_LOG",
    "RUNTIME_LEASE_TTL",
    "RUNTIME_LEASE_HEARTBEAT_SECONDS",
    "PROCESS_TERMINATION_TIMEOUT_SECONDS",
    "SEMANTIC_INDEX_VERSION",
    "SEMANTIC_INDEX_DB_NAME",
    "SEMANTIC_INDEX_MAX_WORKERS",
    "SEMANTIC_INDEX_WAIT_SECONDS",
    "SEMANTIC_GADGET_SOURCE_ACTIONS",
    "SEMANTIC_INDEX_SOURCE_LIMIT",
    "SEMANTIC_SCORE_SUBSTRING_MATCH",
    "SEMANTIC_SCORE_PATTERN_MATCH",
    "SEMANTIC_SCORE_PER_TOKEN",
    "SEMANTIC_INDEX_MAX_QUERY_WORKERS",
    "log_rpc",
    "_bounded_int",
    "_coerce_bool",
    "_env_bool",
    "_parse_str_list",
    "_parse_line_range",
    "_normalize_session_id",
    "_parse_iso_datetime",
    "_select_runtime_dir",
    "_resolve_runtime_dir",
    "_default_runtime_dir",
    "MCPError",
    "make_error",
    "compile_smart_pattern",
    "smart_match",
    "TOOLS",
    "TOOL_DESCRIPTIONS",
    "TOOL_ACTIONS",
    "TOOL_ARG_SCHEMAS",
    "TOOL_ALIASES",
    "ARG_ALIASES_BY_TOOL",
    "ACTION_ALIASES_BY_TOOL",
    "ADVERTISED_TOOLS",
    "HIDDEN_TOOLS_IN_LIST",
    "_resolve_tool_alias",
    "_strip_balanced_wrappers",
    "build_input_schema",
    "build_input_schema_lean",
    "build_input_schema_ultra",
    "build_tool_description_ultra",
    "build_tool_description_lean",
    "classify_tool_category",
    "sanitize_schema_for_vertex",
    "IDAMCPServer",
    "truncate_response",
    "continue_truncated",
    "peek_truncated",
    "search_truncated",
    "summary_truncated",
]
