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
| `session` | Session management (discover, create, list, switch, close, status). |
| `bookmarks` | Session-correlated forensic bookmarking with rich metadata. |
| `batch` | Execute multiple tool calls in a single request. |
| `analysis` | Loader/processor settings and reanalysis controls. |
| `query` | Consolidated read-only entry point (data/search/symbols/patterns). |
| `edit` | Consolidated write/edit entry point (modify/funcs/segments/bulk). |
| `idb` | Database metadata, segment mapping, and entrypoints. |
| `code` | Decompilation (Hex-Rays), disassembly, and cross-reference analysis. |
| `data` | Function listing, global variables, strings, imports, and exports. |
| `search` | Pattern/reference search (bytes, string, immediate, name, etc.). |
| `types` | Type Library (TIL) management and structure reconstruction. |
| `memory` | Direct database memory read/write operations. |
| `modify` | Rename, comment, set type, and patch assembly. |
| `funcs` | Function boundary management and metadata. |
| `segments` | Segment management (list, add, delete, permissions). |
| `bulk` | Bulk rename/comment/type operations for efficiency. |
| `misc` | Utilities (Python exec, IDC, signature loading). |
| `calc` | Mathematical and address resolution utilities. |
| `nav` | Navigation and triage (goto, cursor, interesting). |
| `debug` | Debugger control, breakpoints, registers, and memory. |
| `trace` | Execution tracing operations. |
| `coverage` | Code coverage import and analysis (DrCov, Lighthouse). |
| `trace_analysis` | Post-mortem execution trace processing. |
| `project` | Project I/O and file system operations. |
| `agent` | High-level analysis orchestrator (triage, context_pack). |
| `microcode` | Hex-Rays Microcode (IR) access. |
| `graph` | CFG and callgraph visualization (JSON, DOT, Mermaid). |
| `ctree` | Hex-Rays AST (CTree) analysis. |
| `taint` | Static data flow and vulnerability analysis. |
| `emulate` | Static tracing and emulation utilities. |
| `entropy` | Entropy analysis and packing detection. |
| `structs` | Structure recovery and vtable reconstruction. |
| `strings_xref` | Deep string analysis and encoded string detection. |
| `imports_deep` | Advanced import resolution (thunks, delay, forwarded). |
| `patterns` | Signature and pattern matching. |
| `symbols` | PDB/DWARF symbol management. |
| `diff` | Binary differential analysis. |
| `lumina` | Lumina server interaction. |
| `export` | Database export (listing, HTML, IDC, JSON, BinExport). |
| `history` | Undo/redo and database snapshots. |
| `comments_ai` | Structured AI-friendly annotation management. |
| `colorize` | Visual highlighting of code regions. |
| `data_ops` | Data type conversion (make_data, make_array, make_string). |
| `fixups` | Relocation/fixup management. |
| `hooks` | Hook suggestion and Frida script generation. |
| `wiki` | Built-in documentation system. |
| `yara_hunt` | YARA pattern matching. |

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
Doc status: Reviewed and updated tool descriptions to match actual implementations.
Last reviewed: 2026-01-11
