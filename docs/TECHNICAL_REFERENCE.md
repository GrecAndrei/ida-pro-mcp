# 🧠 IDA Pro MCP Technical Reference

This document provides an exhaustive technical breakdown of the IDA Pro MCP Server architecture, session management, and the Modular SDK.

---

## 🏗️ System Architecture

The system operates as a three-tier bridge between the LLM and the IDA Pro kernel:

### 1. The MCP Stdio Host (`ida_mcp_stdio.py`)
*   **Role**: Entry point for MCP clients (Claude, Gemini, etc.).
*   **Protocol**: JSON-RPC over `stdin`/`stdout`.
*   **Responsibility**: Session management, file locking, process spawning, and high-level input validation.
*   **Process Management**: Dynamically spawns and tracks one headless IDA instance per session (`idat.exe` or `ida.exe -A`).

### 2. The Persistent TCP Server (`server_script.py`)
*   **Role**: Resident agent inside IDA's internal Python environment.
*   **Protocol**: Custom length-prefixed JSON over TCP (local ephemeral ports).
*   **Responsibility**: Dynamic tool loading, main-thread synchronization, and direct IDAPython execution.
*   **Performance**: Maintains a "warm" IDA process per session to avoid the overhead of re-launching IDA for every tool call.

### 3. The Modular SDK (`tools/*.py`)
*   **Role**: Functional units of the API.
*   **Structure**: 40+ specialized modules, each focused on a specific IDA subsystem (Decompiler, Debugger, Taint, etc.).
*   **Isolation**: Each tool uses a robust dual-mode import block to resolve infrastructure (`utils`, `sync`) regardless of IDA's non-standard package resolution.

---

## 🔑 Session Management & Atomic Locking

To support multi-agent swarms without corrupting databases, the server implements a session-based isolation layer.

### SimpleLock Primitive
Located in `ida_mcp_stdio.py`, `SimpleLock` provides cross-platform, process-level atomic locking using `os.O_CREAT | os.O_EXCL`. 
*   **Stale Lock Detection**: Automatically detects and reclaims locks from crashed processes by checking PID heartbeat and file modification times.
*   **Race Protection**: Uses an atomic "rename-to-temp then delete" pattern to avoid TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities during cleanup.

### Session Isolation
Sessions are stored in `.ida_mcp_cache/sessions/`. Each session gets a unique 8-character ID and a dedicated `.i64` database. This allows:
*   **Multi-Agent Parallelism**: Two different LLMs can analyze the same binary simultaneously without interference.
*   **Persistence**: Analysis state is preserved across tool calls within the same session.

---

## 🚦 IDA 9.2 Main Thread Synchronization

IDA 9.2 introduced strict threading restrictions. Many API calls (especially `ida_auto`, `ida_hexrays`, and GUI-related functions) now throw `RuntimeError` if called from a background thread.

**Solution**: The MCP server uses a custom `@idaread` / `@idawrite` decorator system implemented in `sync.py`. This ensures that every tool call is marshaled onto IDA's main execution thread, preventing crashes and ensuring deterministic results.

---

## 🛠️ Exhaustive Tool Reference

Below is the complete list of tools available in the Modular SDK. All tools (except `session` and `bookmarks`) require either an active session or an explicit `idb` path.

### 1. Core & Metadata
*   **`session`**: Management of LLM workflows.
    *   Actions: `discover`, `create`, `list`, `switch`, `close`, `status`.
    *   Args: `binary_path`, `use_existing`, `session_id`.
*   **`bookmarks`**: Enhanced session-correlated bookmarking.
    *   Actions: `add`, `list`, `delete`, `update`, `clear`, `find`, `export`.
    *   Args: `addr`, `id`, `name`, `notes`, `category`, `priority`, `tags`, `query`.
*   **`analysis`**: Loader/processor settings and reanalysis controls.
    *   Actions: `get_options`, `set_options`, `set_processor`, `set_loader_options`, `set_architecture`, `reanalyze`.
    *   Args: `options`, `processor`, `flags`, `loader`, `value`, `bitness`, `endian`, `start`, `end`.
*   **`batch`**: Multi-tool call batching on the host side.
    *   Args: `calls`, `continue_on_error`.
*   **`idb`**: Database-level information.
    *   Actions: `meta`, `summary`, `segments`, `entrypoints`, `bookmarks`.
*   **`query`**: Consolidated read-only dispatcher.
    *   Actions: `data`, `search`, `strings_xref`, `imports_deep`, `symbols`, `patterns`, `idb`.
    *   Args: `subaction`, `args`.
*   **`edit`**: Consolidated write dispatcher.
    *   Actions: `modify`, `funcs`, `segments`, `data_ops`, `fixups`, `colorize`, `comments_ai`, `bulk`.
    *   Args: `subaction`, `args`.
*   **`calc`**: r2-style address and number utilities.
    *   Actions: `eval`, `offset`, `convert`, `resolve`, `deref`, `chain`, `align`.
    *   Args: `expr`, `addr`, `target`, `value`, `type`, `size`, `offsets`.
*   **`yara_hunt`**: Surgical signature matching.
    *   Actions: `scan`, `compile`, `list_rules`.
    *   Args: `rules` (str/path), `addr` (optional), `size` (int).
*   **`wiki`**: On-demand documentation server.
    *   Actions: `list_topics`, `read`, `search`, `sections`, `index`.
    *   Args: `topic` (str), `section` (optional).

### 2. Middleware & Context Optimization

*   **Token-Aware Truncation**: Automatically prunes responses exceeding 4000 tokens (approx). High-frequency lists (functions, strings) are limited to safe counts with "Read More" markers.
*   **Sparse Descriptions**: Tool definitions in the MCP manifest are stripped to essentials. Deep documentation is offloaded to the `wiki` tool to reclaim context window space.

### 3. Code Analysis
*   **`code`**: The primary analysis engine.
    *   Actions: `decompile`, `disasm`, `xrefs_to`, `xrefs_from`, `xrefs_to_field`, `callees`, `callers`, `blocks`, `analyze`, `callgraph`, `export`, `find_paths`, `strings_in_func`.
    *   Args: `addrs` (list/str), `max_depth` (int), `max_items` (int), `field_name` (str), `target` (str).
*   **`microcode`**: Access to Hex-Rays IR.
    *   Actions: `get`, `blocks`, `instructions`.
    *   Args: `addr` (str), `maturity` (0-7).
*   **`ctree`**: Decompiler AST traversal.
    *   Actions: `get`, `traverse`, `find_calls`, `find_vars`, `find_strings`, `find_conditions`, `get_logic_flow`.
    *   Args: `addr` (str), `depth` (int), `query` (str).
*   **`graph`**: Exporting CFGs and callgraphs.
    *   Actions: `callgraph`, `cfg`.
    *   Args: `addr` (str), `format` ("json"|"dot").

### 3. Data & Types
*   **`data`**: Bulk enumeration of binary objects.
*   Actions: `functions`, `globals`, `strings`, `imports`, `exports`, `lookup`, `bulk_query`.
*   Args: `query` (glob), `offset` (int), `count` (int), `items` (list).
*   **`types`**: Type library management.
*   Actions: `list`, `get`, `set_prototype`, `parse_decl`, `declare`, `apply`, `search_structs`, `infer`, `read_struct`, `import_header`.
    *   Args: `name` (str), `decl` (C code), `addr` (str).
*   **`structs`**: Structure recovery logic.
*   Actions: `recover`, `analyze_usage`, `list`, `create`, `add_member`, `apply`, `reconstruct_vtable`.
    *   Args: `addr` (str), `decl` (C code), `name` (str).

### 4. Annotation & Modification
*   **`modify`**: Single-point annotations.
    *   Actions: `rename`, `comment`, `set_type`, `patch_asm`.
    *   Args: `addr` (str), `value` (str).
*   **`bulk`**: High-performance batch operations.
    *   Actions: `rename`, `comment`, `set_type`, `import_json`, `export_json`.
    *   Args: `items` (list of {addr, value}), `path` (str).
*   **`comments_ai`**: Structured, AI-friendly commenting.
    *   Actions: `get_context`, `set_structured`, `bulk_set`, `export_md`, `import_md`, `summary`.
    *   Args: `addr` (str), `text` (str), `items` (json).

### 5. Advanced Reverse Engineering
*   **`taint`**: Static data flow analysis.
*   Actions: `find_arg_usage`, `trace_return`, `find_sinks`, `data_flow`, `backward_trace`, `slice`.
    *   Args: `addr` (str), `arg_num` (int), `depth` (int), `max_hits` (int).
*   **`emulate`**: Code emulation and trace.
*   Actions: `static_trace`, `appcall`, `decrypt_strings`, `eval_expr`.
    *   Args: `addr` (str), `max_steps` (int), `args` (list), `follow_calls` (bool), `max_depth` (int), `include_blocks` (bool), `expr` (str).
*   **`entropy`**: Packed/Encrypted region detection.
    *   Actions: `section`, `region`, `packed_detect`, `crypto_detect`, `compare`, `window`, `summary`.
    *   Args: `addr` (str), `size` (int), `threshold` (float), `end_addr` (str), `window` (int), `step` (int), `limit` (int).
*   **`strings_xref`**: Context-aware string analysis.
    *   Actions: `analyze`, `xref_chain`, `detect_encoded`, `find_format`, `clusters`.
    *   Args: `addr` (str), `depth` (int).

### 6. Debugging & Dynamic Analysis
*   **`debug`**: Live process control.
    *   Actions: `start`, `stop`, `continue`, `step_into`, `step_over`, `run_to`, `breakpoints`, `add_bp`, `del_bp`, `enable_bp`, `regs`, `callstack`, `read_mem`, `write_mem`.
    *   Args: `addr` (str), `size` (int), `data` (hex), `enabled` (bool), `tid` (int).
*   **`coverage`**: Code coverage management.
    *   Actions: `import_drcov`, `import_lighthouse`, `highlight`, `report`, `uncovered`.
    *   Args: `path` (str), `addr` (str), `color` (str).
*   **`trace_analysis`**: Post-mortem execution trace.
    *   Actions: `import_trace`, `analyze_coverage`, `find_loops`, `extract_api_calls`, `basic_blocks_hit`.
    *   Args: `path` (str), `trace_data` (list).

---

## 🚨 Error Code Reference

| Code | Meaning | Context |
|------|---------|---------|
| `UNKNOWN_ERROR` | Unhandled exception | Includes Python traceback in `details` |
| `IDA_CRASHED` | Background process died | Usually binary/IDB incompatibility |
| `SESSION_LOCKED` | IDB in use by another session | Atomic lock collision |
| `PATH_TRAVERSAL` | Security violation | Attempt to access files outside allowed scope |
| `FUNCTION_NOT_FOUND` | Logic error | Target address does not contain a function |
| `DECOMPILE_FAILED` | Hex-Rays error | Usually lack of decompiler license or complex obfuscation |

---
<p align="center">
  <sub>Document Version: 2.0.0 (Modular Era)</sub>
</p>
---
Doc status: Updated tool descriptions to match actual implementations.
Last reviewed: 2026-01-11
