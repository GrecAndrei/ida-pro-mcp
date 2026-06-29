#!/usr/bin/env python3
"""
IDA Pro MCP Server — stdio entry point (thin shim).

All implementation lives in src/ida_pro_mcp/host/.
This file preserves backward compatibility for tests and MCP clients.
"""
import os
import sys

# =============================================================================
# STREAM ISOLATION — must happen before ANY other imports
# =============================================================================
_real_stdout = sys.stdout
sys.stdout = sys.stderr

# Ensure src/ is on path so host/ package resolves
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)
_src_dir = os.path.join(_SCRIPT_DIR, "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

# Inject the original stdout into the server module before it is imported.
# CRITICAL: `ida_pro_mcp.host.server` is a *package* with a lazy __init__,
# so we must reach into the submodule `ida_pro_mcp.host.server.server`
# (where `_real_stdout` is defined at module level, server.py:794).
# Setting the attribute on the package alone has no effect — `IDAMCPServer.run()`
# uses the submodule's name binding, which captures `sys.stdout` at module
# import time (already swapped to stderr by then).
import ida_pro_mcp.host.server as _server_pkg  # noqa: E402
import ida_pro_mcp.host.server.server as _server_mod  # noqa: E402

_server_mod._real_stdout = _real_stdout
_server_pkg._real_stdout = _real_stdout  # type: ignore[attr-defined]  # belt-and-braces in case anything else imports from the package

# Re-export everything from the host package so existing imports keep working.
# All re-exports marked `noqa: F401` — they exist for backward compatibility
# with external callers that do `from ida_mcp_stdio import <name>`.
from ida_pro_mcp.host import *  # noqa: E402,F403,F401
from ida_pro_mcp.host.analysis.patterns import (  # noqa: E402,F401
    compile_smart_pattern,
    smart_match,
)
from ida_pro_mcp.host.config import (  # noqa: E402,F401
    BRIDGE_LOG,
    CACHE_DIR,
    _bounded_int,
    _coerce_bool,
    _env_bool,
    _normalize_session_id,
    _parse_iso_datetime,
    _parse_line_range,
    _parse_str_list,
    log_rpc,
    validate_path,
)
from ida_pro_mcp.host.errors import MCPError, make_error  # noqa: E402,F401
from ida_pro_mcp.host.schemas import (  # noqa: E402,F401
    ACTION_ALIASES_BY_TOOL,
    ADVERTISED_TOOLS,
    ARG_ALIASES_BY_TOOL,
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
from ida_pro_mcp.host.server.server import IDAMCPServer  # noqa: E402,F401
from ida_pro_mcp.host.server.session import (  # noqa: E402,F401
    BookmarkManager,
    Session,
    SessionManager,
)
from ida_pro_mcp.host.stores.truncation import (  # noqa: E402,F401
    continue_truncated,
    truncate_response,
)

if __name__ == "__main__":
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
