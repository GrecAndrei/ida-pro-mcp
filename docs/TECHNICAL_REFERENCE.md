# IDA Pro MCP - Technical Reference

Architecture and design decisions for the IDA Pro MCP server.

## Overview

IDA Pro MCP is a JSON-RCP stdio server that exposes IDA Pro's reverse
engineering capabilities to LLM clients. It uses a tool-action model where
each tool (e.g., `code`, `search`, `intelligence`) exposes multiple actions
(e.g., `decompile`, `find`, `index_fast`).

## Tool-Action Model

```
tool:code
  ├── action:decompile      → Hex-Rays decompilation
  ├── action:disasm         → Disassembly listing
  ├── action:smart_decompile→ Decompile + CFG + behavior tags
  └── action:diff_functions → Compare two functions

tool:search
  ├── action:find           → Search names, strings, imports
  ├── action:nl             → Natural language (embedding-based)
  ├── action:vulnerable     → Dangerous API pattern scan
  └── action:semantic       → Embedding-index similarity
```

## Architecture

```
src/ida_pro_mcp/
├── ida_mcp/
│   ├── tools/              ← IDA-side tool implementations
│   │   ├── code.py         ← @tool decorated functions
│   │   ├── search/         ← Package (basic + advanced)
│   │   └── __init__.py     ← Lazy loader + _TOOL_MODULE_MAP
│   ├── host/
│   │   ├── schemas_data.py ← TOOLS, TOOL_DESCRIPTIONS, TOOL_ACTIONS
│   │   ├── server/
│   │   │   ├── tool_registry.py ← _TOOL_ACTIONS dict (action lists)
│   │   │   ├── server_dispatch.py ← Routes tool→handler
│   │   │   └── server.py ← Main MCP server class
│   │   └── config.py       ← Runtime configuration
│   └── utils.py            ← Shared utilities
└── scripts/
    └── test_registry_check.py ← Test binding enforcement
```

## Key Design Decisions

### 1. Single Source of Truth

Tool lists are defined in one place:
- `host/server/tool_registry.py` → `_TOOL_ACTIONS` (action lists per tool)
- `host/schemas_data.py` → `TOOLS` (all tools), `ADVERTISED_TOOLS` (exposed to LLM)

All other locations derive from these.

### 2. Embedding Index

The `intelligence` tool manages a SQLite-backed embedding index:
- `index_fast` — disassembly-based, seconds
- `index_batch` — decompile-based, minutes (best quality)
- `semantic_search` — cosine similarity over stored embeddings
- `similar_functions` — nearest neighbors by embedding distance

### 3. Test Binding Registry

Tests declare what code entities they interact with via `@@TEST_REGISTRY@@`
headers. The `test_registry_check.py` script enforces that when code changes,
corresponding tests are updated or marked as false positives.

## Adding a New Tool

1. Create `ida_mcp/tools/newtool.py` with `@tool` decorated function
2. Add to `_TOOL_ACTIONS` in `host/server/tool_registry.py`
3. Add to `TOOLS` in `host/schemas_data.py`
4. Add description to `TOOL_DESCRIPTIONS`
5. Add a test file with `@@TEST_REGISTRY@@` header
6. Run `python scripts/test_registry_check.py --discover`

## Removed Tools

The following tools were removed to reduce complexity:

| Tool | Reason |
|------|--------|
| `agent` | Superseded by `intelligence` tool |
| `query` | Thin wrapper, no unique value |
| `llm_helpers` | Replaced by standard tool composition |
| `colorize` | Visual-only, no analysis value |
| `predictor` | Heuristic-based, replaced by embedding search |
