"""IDA Pro MCP Plugin - Consolidated API

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Tools are consolidated into action-parameterized mega-tools to keep LLM
context windows small. The IDA-side tool modules live in ``ida_mcp/tools/``
(each exposing one ``@tool`` function with an ``action`` enum):

  idb, code, data, search, types, memory, modify, misc, funcs, segments,
  graph, ctree, imports_deep, symbols, firmware_view, wiki, intelligence,
  gadgets, stack_analysis, annotation, blackboard, governance, knowledge,
  batch, analysis, calc

Host-side session/batch/workflow tools are defined in the ``host`` package.
Shared helpers live in ``ida_mcp/tools/_common.py`` and ``ida_mcp/support/``;
the sync/cache/rpc/error-handling infrastructure in this package is what the
IDA plugin runtime uses.
"""

# Import infrastructure modules
# ============================================================================
# MODULAR API - 39 tools
# ============================================================================
# Prompts (LLM workflow guides)
from . import prompts, rpc, sync, tools, utils
from .mcp_http import IdaMcpHttpRequestHandler
from .rpc import MCP_SERVER, MCP_UNSAFE, prompt, resource, tool, unsafe

# Additional consolidated tools (separate files for organization)
# from . import api_enums      # enum tool (list, info, create, delete, add/del_member, apply, search)
# from . import api_bookmarks  # bookmark tool (list, set, delete, jump)
# from . import api_signatures # signatures tool (FLIRT, TIL, Lumina)
# Resources (read-only browsable state)
# from . import api_resources
# Re-export key components for external use
from .sync import IDAError, IDASyncError, idaread, idawrite

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # Modular API
    "tools",
    # Prompts
    "prompts",
    # Re-exported components
    "idaread",
    "idawrite",
    "IDAError",
    "IDASyncError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "prompt",
    "IdaMcpHttpRequestHandler",
]
