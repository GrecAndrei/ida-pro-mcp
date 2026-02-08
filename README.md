# IDA Pro MCP Server

A high-performance Model Context Protocol (MCP) server providing structured integration between AI agents and IDA Pro 9.2+.

## Overview

The IDA Pro MCP Server enables AI assistants to interact programmatically with IDA's analysis engine. It provides a comprehensive suite of over 60 tools for binary analysis, decompilation, debugging, vulnerability hunting, and database annotation — all exposed via a standardized JSON-RPC interface with compact, LLM-optimized output.

## Key Features

- **Modern IDA 9.2 Integration**: Fully optimized for the IDA 9.2 API, including support for the latest type system and headless execution mode.
- **Multi-Session Parallelism**: Each session runs in its own headless IDA process for safe concurrent analysis.
- **Persistent Forensic Bookmarks**: Custom JSON-backed bookmarking system that supports rich technical notes and AI-driven annotations.
- **Comprehensive SDK**: Full access to Hex-Rays pseudocode, CTree ASTs, cross-references, and topological analysis (CFG/Callgraphs).
- **LLM-Optimized Output**: All tools return compact, newline-delimited text instead of verbose JSON — minimizing context token usage.
- **Smart Pattern Matching**: All query/filter parameters auto-detect regex, glob, or plain substring patterns.
- **ARM + x86 Support**: All analysis tools work across x86/x64 and ARM/AArch64 architectures.
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
3. Register the server with supported MCP clients (see below).
4. Link the modular SDK components to your IDA Pro installation.

### Supported MCP Clients

The installer automatically configures the following MCP clients:

- **Gemini CLI** - Google's CLI-based AI assistant
- **Antigravity** - Gemini-based AI tool
- **Claude Code** - Anthropic's command-line coding assistant
- **Claude Desktop** - Anthropic's desktop application
- **Codex** - OpenAI Codex CLI tool
- **Copilot CLI** - GitHub Copilot command-line tool
- **OpenCode** - Open source AI coding agent for terminal/IDE/desktop
- **Cursor** - AI-powered code editor
- **VS Code** - With GitHub Copilot extension
- **Windsurf** - AI development environment
- **Cline** - AI coding assistant extension
- **Roo Code** - Code assistant extension

Each client uses its native configuration format:
- **Standard JSON**: Claude Desktop, Cursor, VS Code, Windsurf, Cline, Roo Code
- **TOML**: Codex
- **OpenCode Schema**: OpenCode uses `type: "local"` with `command` array format
- **GitHub Copilot CLI**: Special format with `type: "local"` and `tools: ["*"]`

## Tool Registry

The server exposes over 60 tools organized by domain:

### Session Management

**Important**: Once you create or switch to a session, the `idb` parameter becomes optional for all subsequent tool calls. The system automatically uses the active session's IDB path.

**Workflow:**
1. Create a session: `session(action="create", binary_path="path/to/binary.exe")`
2. Use any tool without `idb` parameter: `data(action="functions")`
3. Switch sessions if needed: `session(action="switch", session_id="ABCD1234")`
4. Continue using tools: `code(action="decompile", addr="0x401000")`

### Core Tools

| Tool | Description |
| :--- | :--- |
| `session` | Session management (discover, create, list, switch, close, status). **WARNING**: 'close' permanently deletes the session and IDB. |
| `bookmarks` | Session-correlated forensic bookmarking with rich metadata. |
| `batch` | Execute multiple tool calls in a single request. |
| `analysis` | Loader/processor settings and reanalysis controls. |
| `query` | Consolidated read-only entry point (data/search/symbols/patterns). |
| `edit` | Consolidated write/edit entry point (modify/funcs/segments/bulk). |

### Data Access & Search

| Tool | Description |
| :--- | :--- |
| `idb` | Database metadata, segment mapping, and entrypoints. |
| `code` | Decompilation (Hex-Rays), disassembly, and cross-reference analysis. |
| `data` | Function listing, global variables, strings, imports, and exports. Query supports regex. |
| `search` | Pattern/reference search (bytes, string, immediate, name, regex, vulnerable, constants). |
| `types` | Type Library (TIL) management and structure reconstruction. |
| `memory` | Direct database memory read/write operations. |

### Modification & Annotation

| Tool | Description |
| :--- | :--- |
| `modify` | Rename, comment, set type, and patch assembly. |
| `funcs` | Function boundary management and metadata. |
| `segments` | Segment management (list, add, delete, permissions). |
| `bulk` | Bulk rename/comment/type operations for efficiency. |
| `annotation` | Intelligent auto-commenting: label loops, mark dangerous APIs, propagate names. Supports dry_run. |
| `comments_ai` | Structured AI-friendly annotation management (get_context, set_structured, export/import markdown). |
| `colorize` | Visual highlighting of code regions. |
| `data_ops` | Data type conversion (make_data, make_array, make_string). |
| `fixups` | Relocation/fixup management. |

### Security & Vulnerability Analysis

| Tool | Description |
| :--- | :--- |
| `vuln_scan` | Automated vulnerability scanner with CWE classification (buffer overflow, format string, UAF, command injection, etc.). |
| `taint` | Static data flow and vulnerability analysis (find_sinks, backward_trace, slice). |
| `gadgets` | ROP/JOP/COP gadget discovery, stack pivots, mitigations detection. x86/x64 + ARM/AArch64. |
| `c2_detect` | C2/malware behavior detection (persistence, evasion, injection, IOC extraction). |

### Deobfuscation & Crypto

| Tool | Description |
| :--- | :--- |
| `deobfuscate` | XOR scan, stack strings, opaque predicates, control flow flattening, API hashing, anti-disasm. |
| `crypto_id` | Cryptographic algorithm identification (AES, SHA, CRC, Base64 tables, custom crypto). |
| `entropy` | Entropy analysis and packing detection. |

### Advanced Analysis

| Tool | Description |
| :--- | :--- |
| `agent` | High-level analysis orchestrator (analyze_function, context_pack, rename_suggestions). |
| `summarize` | LLM-friendly binary/function summarization (complexity, call hierarchy, security posture). |
| `classify` | Function purpose classification (crypto, network, file_io, wrappers, callbacks, hot_functions). |
| `compare` | Function comparison and similarity analysis (diff, clone detection, batch similarity). |
| `xref_analysis` | Deep cross-reference analysis (call chains, hub functions, dominators, dead functions). |
| `cfg_analysis` | Control flow graph analysis (complexity, loops, dominators, back edges, flatten detection). |
| `stack_analysis` | Deep stack frame analysis (buffers, canary detection, spills, uninitialized vars). |
| `abi` | ABI/calling convention analysis (detect, stack/reg args, tail calls, prologue/epilogue). |

### String & Data Analysis

| Tool | Description |
| :--- | :--- |
| `string_ops` | Advanced string operations (URLs, IPs, emails, paths, registry keys, suspicious strings). Query supports regex. |
| `binary_info` | Binary metadata and format analysis (headers, sections, relocations, resources, compiler). |
| `protocol` | Network protocol structure analysis (detect, parsers, handlers, endpoints, packet struct). |

### Debugging & Tracing

| Tool | Description |
| :--- | :--- |
| `debug` | Debugger control, breakpoints, registers, and memory. |
| `trace` | Execution tracing operations. |
| `coverage` | Code coverage import and analysis (DrCov, Lighthouse). |
| `trace_analysis` | Post-mortem execution trace processing. |

### Structural Analysis

| Tool | Description |
| :--- | :--- |
| `structs` | Structure recovery and vtable reconstruction. |
| `imports_deep` | Advanced import resolution (thunks, delay, forwarded). |
| `patterns` | Signature and pattern matching. |
| `symbols` | PDB/DWARF symbol management. |
| `microcode` | Hex-Rays Microcode (IR) access. |
| `graph` | CFG and callgraph visualization (JSON, DOT, Mermaid). |
| `ctree` | Hex-Rays AST (CTree) analysis. |
| `emulate` | Static tracing and emulation utilities. |

### Export & Utilities

| Tool | Description |
| :--- | :--- |
| `export` | Database export (listing, HTML, IDC, JSON, BinExport). |
| `history` | Undo/redo and database snapshots. |
| `diff` | Binary differential analysis. |
| `lumina` | Lumina server interaction. |
| `hooks` | Hook suggestion and Frida script generation. |
| `misc` | Utilities (Python exec, IDC, signature loading, file I/O). |
| `calc` | Mathematical and address resolution utilities. |
| `nav` | Navigation and triage (goto, cursor, interesting). |
| `project` | Project I/O and file system operations. |
| `wiki` | Built-in documentation system. |
| `yara_hunt` | YARA pattern matching. |

### LLM Helpers

| Tool | Description |
| :--- | :--- |
| `llm_helpers` | LLM-specific helpers (context_window, function_digest, binary_digest, suggest_next, cheatsheet). |

## Development and Testing

A dedicated test client is provided for manual verification of tool functionality:

```bash
python tests/test_mcp_client.py --tool idb --args "action=meta"
```

## Architecture

The system utilizes a session-based bridge architecture. The MCP server (`ida_mcp_stdio.py`) manages local process lifecycles and communicates with a background IDA instance via a high-speed socket bridge (`server_script.py`). This ensures that the AI context remains responsive even during heavy analysis tasks.
