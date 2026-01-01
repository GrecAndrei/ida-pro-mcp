"""IDA Pro MCP Plugin - Consolidated API

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

OPTIMIZED: 10 mega-tools covering all functionality.
This is much more efficient for LLM context windows.

CORE TOOLS (api_consolidated.py):
1. idb       - database metadata, segments, cursor, entrypoints
2. code      - decompile, disassemble, xrefs, callgraph, blocks
3. data      - functions, globals, strings, imports, exports, lookup
4. search    - find bytes, strings, immediate values, names, xrefs
5. types     - local types, structs, prototypes, infer
6. memory    - read/write all data types
7. modify    - rename, comments, set type, patch assembly
8. misc      - python exec, idc, undo, stack, reanalyze
9. debug     - debugger control, breakpoints, registers, memory
10. agent    - high-level automated analysis helpers
"""

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# ============================================================================
# CONSOLIDATED API - Only 8 tools!
# ============================================================================
from . import api_consolidated

# Additional consolidated tools (separate files for organization)
# from . import api_enums      # enum tool (list, info, create, delete, add/del_member, apply, search)
# from . import api_bookmarks  # bookmark tool (list, set, delete, jump)
# from . import api_signatures # signatures tool (FLIRT, TIL, Lumina)

# Resources (read-only browsable state)
# from . import api_resources

# Re-export key components for external use
from .sync import idaread, idawrite, IDAError, IDASyncError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource
from .http import IdaMcpHttpRequestHandler

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # Consolidated API
    "api_consolidated",
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
    "IdaMcpHttpRequestHandler",
]
