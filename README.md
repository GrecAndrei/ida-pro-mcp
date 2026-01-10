# IDA Pro MCP Server

A high-performance Model Context Protocol (MCP) server providing structured integration between AI agents and IDA Pro 9.2+.

## Overview

The IDA Pro MCP Server enables AI assistants to interact programmatically with IDA's analysis engine. It provides a comprehensive suite of over 40 tools for binary analysis, decompilation, debugging, and database annotation, all exposed via a standardized JSON-RPC interface.

## Key Features

- **Modern IDA 9.2 Integration**: Fully optimized for the IDA 9.2 API, including support for the latest type system and headless execution mode.
- **Multi-Session Parallelism**: Each session runs in its own headless IDA process for safe concurrent analysis.
- **Persistent Forensic Bookmarks**: Custom JSON-backed bookmarking system that supports rich technical notes and AI-driven annotations.
- **Comprehensive SDK**: Full access to Hex-Rays pseudocode, CTree ASTs, cross-references, and topological analysis (CFG/Callgraphs).
- **Automated Process Recovery**: Intelligent detection and cleanup of stale IDA instances and locked virtual environments.
- **Flexible Transport**: Support for both STDIO and HTTP-based MCP transport protocols.

## Requirements

- **IDA Pro**: Version 9.2 or later.
- **Python**: Version 3.11 or later.
- **uv**: Recommended for high-performance dependency management and sub-second startup.

## Installation

The project includes a professional installer that handles self-relocation to a stable system path (`%LOCALAPPDATA%` on Windows) and configures various MCP clients automatically.

```bash
python install.py
```

The installer will:
1. Detect and migrate the server to a permanent location.
2. Synchronize core code while preserving user data and analysis cache.
3. Register the server with supported MCP clients (Gemini, Claude, Copilot, etc.).
4. Link the modular SDK components to your IDA Pro installation.

## Tool Registry

The server exposes a wide range of analytical tools, including:

| Tool | Description |
| :--- | :--- |
| `analysis` | Loader/processor settings and reanalysis controls. |
| `batch` | Execute multiple tool calls in a single request. |
| `idb` | Database metadata, segment mapping, and entrypoints. |
| `query` | Consolidated read-only entry point (data/search/symbols/patterns). |
| `edit` | Consolidated write/edit entry point (modify/funcs/segments/bulk). |
| `code` | Decompilation (Hex-Rays), disassembly, and cross-reference analysis. |
| `data` | Function listing, global variable tracking, and string extraction. |
| `types` | Type Library (TIL) management and structure reconstruction. |
| `nav` | Advanced navigation, including JSON-backed forensic bookmarks. |
| `debug` | Execution control, register inspection, and memory manipulation. |
| `agent` | High-level analysis orchestrator for triage and exploration. |
| `yara_hunt` | Surgical pattern matching using YARA rules. |

## Development and Testing

A dedicated test client is provided for manual verification of tool functionality:

```bash
python tests/test_mcp_client.py --tool idb --args "action=meta"
```

## Architecture

The system utilizes a session-based bridge architecture. The MCP server (`ida_mcp_stdio.py`) manages local process lifecycles and communicates with a background IDA instance via a high-speed socket bridge (`server_script.py`). This ensures that the AI context remains responsive even during heavy analysis tasks.

## License

MIT License. See `LICENSE` for details.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
