#!/usr/bin/env python3
"""
IDA Pro MCP Server — stdio entry point (thin shim).

All implementation lives in src/ida_pro_mcp/host/.
This file preserves backward compatibility for tests and MCP clients.
"""
import sys
import os

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

# Inject the original stdout into the server module before it is imported
import ida_pro_mcp.host.server as _server_mod  # noqa: E402
_server_mod._real_stdout = _real_stdout

# Re-export everything from the host package so existing imports keep working
from ida_pro_mcp.host import *  # noqa: E402,F403
from ida_pro_mcp.host.server.session import (  # noqa: E402
    Session,
    SessionManager,
    BookmarkManager,
)
from ida_pro_mcp.host.server.server import IDAMCPServer  # noqa: E402
from ida_pro_mcp.host.errors import MCPError, make_error  # noqa: E402
from ida_pro_mcp.host.analysis.patterns import (  # noqa: E402
    compile_smart_pattern,
    smart_match,
)
from ida_pro_mcp.host.config import (  # noqa: E402
    CACHE_DIR,
    BRIDGE_LOG,
    log_rpc,
    validate_path,
    _bounded_int,
    _coerce_bool,
    _env_bool,
    _parse_str_list,
    _parse_line_range,
    _normalize_session_id,
    _parse_iso_datetime,
)
from ida_pro_mcp.host.schemas import (  # noqa: E402
    TOOLS,
    TOOL_DESCRIPTIONS,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOL_ALIASES,
    ARG_ALIASES_BY_TOOL,
    ACTION_ALIASES_BY_TOOL,
    ADVERTISED_TOOLS,
    build_input_schema,
    build_input_schema_lean,
    build_input_schema_ultra,
    build_tool_description_ultra,
    build_tool_description_lean,
    classify_tool_category,
    sanitize_schema_for_vertex,
    _strip_balanced_wrappers,
    _resolve_tool_alias,
)
from ida_pro_mcp.host.stores.truncation import (  # noqa: E402
    truncate_response,
    continue_truncated,
)

if __name__ == "__main__":
    try:
        server = IDAMCPServer()
        server.run()
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
