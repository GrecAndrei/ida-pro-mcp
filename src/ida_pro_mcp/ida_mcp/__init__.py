"""IDA Pro MCP Plugin - Consolidated API

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

OPTIMIZED: 23 mega-tools instead of 100+, each with action parameter.
This is much more efficient for LLM context windows.

MODULAR TOOLS (tools/):
1. idb       - database metadata, segments, cursor, entrypoints
2. code      - decompile, disassemble, xrefs, callgraph, basic blocks
3. data      - functions, globals, strings, imports, exports, lookup
4. search    - find bytes, strings, immediate values, names
5. types     - local types, structs, prototypes
6. memory    - read/write all data types
7. modify    - rename, comments, set type
8. misc      - python exec, signatures, bookmarks, undo, stack
9. debug     - debugger control, breakpoints, registers
10. funcs    - function create/delete/flags
11. segments - segment management
12. files    - file operations
13. plugins  - plugin management
14. trace    - execution tracing
15. fixups   - relocation management
16. data_ops - data definition operations
17. agent    - high-level agent helpers
18. microcode - Hex-Rays intermediate representation
19. graph    - call graphs, CFGs, xref graphs (JSON/DOT)
20. bulk     - bulk rename/comment/type operations

ADDITIONAL TOOLS (separate files):
21. enum      - enum management (api_enums.py)
22. bookmark  - bookmark management (api_bookmarks.py)
23. signatures - FLIRT/TIL/Lumina (api_signatures.py)
"""

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# ============================================================================
# MODULAR API - 39 tools
# ============================================================================
from . import tools

# Prompts (LLM workflow guides)
from . import prompts

# Additional consolidated tools (separate files for organization)
# from . import api_enums      # enum tool (list, info, create, delete, add/del_member, apply, search)
# from . import api_bookmarks  # bookmark tool (list, set, delete, jump)
# from . import api_signatures # signatures tool (FLIRT, TIL, Lumina)

# Resources (read-only browsable state)
from . import api_resources

# Re-export key components for external use
from .sync import idaread, idawrite, IDAError, IDASyncError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource, prompt
from .mcp_http import IdaMcpHttpRequestHandler

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
