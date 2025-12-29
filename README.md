<p align="center">
  <img src="https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue?style=for-the-badge" alt="IDA Pro 9.0+"/>
  <img src="https://img.shields.io/badge/Python-3.11%2B-green?style=for-the-badge" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/MCP-2.0-purple?style=for-the-badge" alt="MCP 2.0"/>
  <img src="https://img.shields.io/badge/Tools-40-orange?style=for-the-badge" alt="39 Tools"/>
  <img src="https://img.shields.io/badge/Sessions-Yes-brightgreen?style=for-the-badge" alt="Session Support"/>
</p>

<h1 align="center">
  <br>
  🔬 IDA Pro MCP Server
  <br>
  <sub>Standalone Model Context Protocol for IDA Pro</sub>
</h1>

<p align="center">
  <strong>AI-powered reverse engineering without launching IDA Pro GUI.</strong><br>
  40 comprehensive tools for binary analysis, decompilation, and annotation.<br>
  <strong>Multi-session support</strong> - multiple LLMs can analyze the same binary simultaneously.<br>
  Works with Claude, Gemini, Cursor, VS Code, and any MCP-compatible client.
</p>

---

## ⚡ Quick Start

### 1. Add to MCP Config

Add the server to your MCP client's configuration (e.g., `mcp_config.json` for VS Code, `claude_desktop_config.json` for Claude):

```json
{
    "mcpServers": {
        "ida-pro-mcp": {
            "type": "stdio",
            "command": "python",
            "args": ["C:/path/to/ida-pro-mcp/ida_mcp_stdio.py"],
            "env": {
                "IDADIR": "C:/Program Files/IDA Professional 9.2"
            }
        }
    }
}
```

> **Important**: Set the `IDADIR` environment variable to your IDA Pro installation path.

### 2. Use It

```python
# Get IDB metadata
idb(idb="C:/samples/malware.exe.i64", action="meta")

# List all functions
data(idb="C:/samples/malware.exe.i64", action="functions", count=50)

# Decompile a function
code(idb="C:/samples/malware.exe.i64", action="decompile", addrs="0x401000")

# Search for patterns
search(idb="C:/samples/malware.exe.i64", action="bytes", pattern="48 83 EC ?? 48 8B")
```

### Common Analysis Workflows

**Workflow 1: Function Analysis Pipeline**
```python
# Step 1: Find interesting functions
data(idb="sample.i64", action="functions", query="*crypt*")

# Step 2: Decompile the function
code(idb="sample.i64", action="decompile", addr="0x401234")

# Step 3: Find who calls it
code(idb="sample.i64", action="callers", addr="0x401234", max_depth=3)

# Step 4: Rename based on analysis
modify(idb="sample.i64", action="rename", addr="0x401234", name="decrypt_data")
```

**Workflow 2: String-Based Triage**
```python
# Step 1: Find suspicious strings
data(idb="sample.i64", action="strings", query="*password*")

# Step 2: For each string, find code that uses it
code(idb="sample.i64", action="xrefs_to", addr="<string_address>")

# Step 3: Decompile the referencing function
code(idb="sample.i64", action="decompile", addr="<function_address>")
```

**Workflow 3: Comprehensive First-Pass Analysis**
```python
# Use the agent tool for automatic comprehensive analysis
agent(idb="sample.i64", action="analyze_function", addr="main")
# Returns: decompilation + xrefs + strings + comments in one call
```

---

## 🎯 Architecture

```
┌─────────────────┐     MCP Protocol     ┌──────────────────┐
│   AI Client     │◄────────────────────►│  ida_mcp_stdio   │
│ (Claude, Gemini)│      stdio           │  (Python)        │
└─────────────────┘                      └────────┬─────────┘
                                                  │ spawns
                                                  ▼
                                         ┌──────────────────┐
                                         │    idat.exe      │
                                         │  (Headless IDA)  │
                                         │   per-request    │
                                         └────────┬─────────┘
                                                  │ IDAPython
                                                  ▼
                                         ┌──────────────────┐
                                         │  api_consolidated│
                                         │   40 tools       │
                                         └──────────────────┘
```

**Key Features:**

- **Fully Standalone**: No IDA GUI required - uses headless `idat.exe`
- **MCP Stdio Protocol**: Works with any MCP-compatible client
- **40 comprehensive tools**: Covers all reverse engineering needs
- **Session Management**: Multiple LLMs can analyze the same binary with separate IDBs
- **File Locking**: Automatic lock detection prevents conflicts
- **Structured Errors**: Clear error codes for LLM understanding

---

## 📦 Complete Tool Reference

### Session Management

| Tool      | Description               | Key Actions                                     |
| --------- | ------------------------- | ----------------------------------------------- |
| `session` | Multi-file/multi-LLM mgmt | `discover`, `create`, `list`, `switch`, `close` |

> **Sessions enable:**
>
> - Multiple LLMs analyzing the same binary with separate IDBs
> - Seamless switching between multiple open files
> - Automatic file locking to prevent conflicts
> - IDB discovery with "in use" status

### Static Analysis Tools

| Tool     | Description                 | Key Actions                                                          |
| -------- | --------------------------- | -------------------------------------------------------------------- |
| `idb`    | Database metadata           | `meta`, `segments`, `cursor`, `entrypoints`                          |
| `code`   | Decompilation & disassembly | `decompile`, `disasm`, `xrefs_to`, `xrefs_from`, `callgraph`, `analyze` |
| `data`   | Data enumeration            | `functions`, `globals`, `strings`, `imports`, `exports`              |
| `search` | Pattern search              | `bytes`, `string`, `immediate`, `name`, `pattern`, `data_ref`, `code_ref` |
| `types`  | Type management             | `list`, `get`, `define`, `apply`, `get_members`                      |

### Modification Tools

| Tool          | Description            | Key Actions                                                   |
| ------------- | ---------------------- | ------------------------------------------------------------- |
| `modify`      | Rename, comment, patch | `rename`, `comment`, `set_type`, `patch`                      |
| `funcs`       | Function management    | `create`, `delete`, `set_flags`, `add_comment`                |
| `segments`    | Segment management     | `list`, `add`, `delete`, `set_attr`                           |
| `bulk`        | Batch operations       | `rename`, `comment`, `set_type`, `import_json`, `export_json` |
| `comments_ai` | AI-optimized comments  | `get_context`, `set_structured`, `bulk_set`, `export_md`      |

### Advanced Analysis Tools

| Tool             | Description                | Key Actions                                                             |
| ---------------- | -------------------------- | ----------------------------------------------------------------------- |
| `agent`          | High-level helpers         | `analyze_function`, `explore_address`, `find_references`, `search_all`  |
| `microcode`      | Hex-Rays IR                | `get`, `blocks`, `instructions`                                         |
| `graph`          | Graph export               | `callgraph`, `cfg`                                                      |
| `memory`         | Memory read/write          | `read`, `write`                                                         |
| `ctree`          | Hex-Rays AST access        | `get`, `find_calls`, `find_vars`, `find_strings`, `find_conditions`     |
| `diff`           | Binary diffing             | `functions`, `bytes`, `signatures`, `names`, `summary`                  |
| `lumina`         | Cloud function recognition | `pull`, `push`, `status`, `history`, `search`                           |
| `symbols`        | Debug symbols (PDB/DWARF)  | `load_pdb`, `load_dwarf`, `status`, `apply`, `export`                   |
| `patterns`       | FLIRT pattern matching     | `generate`, `match`, `list_sigs`, `apply_sig`, `create_sig`             |
| `structs`        | Struct recovery            | `recover`, `analyze_usage`, `list`, `create`, `apply`                   |
| `emulate`        | Code emulation             | `snippet`, `appcall`, `trace`, `decrypt_strings`, `eval_expr`           |
| `export`         | Multi-format export        | `listing`, `html`, `idc`, `json`, `binexport`, `headers`                |
| `history`        | DB version control         | `undo`, `redo`, `list`, `snapshot`, `restore`, `diff`                   |
| `strings_xref`   | Advanced string analysis   | `analyze`, `xref_chain`, `detect_encoded`, `find_format`, `clusters`    |
| `entropy`        | Entropy analysis           | `section`, `region`, `packed_detect`, `crypto_detect`, `compare`        |
| `imports_deep`   | Deep import analysis       | `thunks`, `delay`, `forwarded`, `ordinal`, `api_sets`, `resolve`        |
| `trace_analysis` | Execution trace analysis   | `import_trace`, `analyze_coverage`, `find_loops`, `extract_api_calls`   |
| `hooks`          | Hook script generation     | `suggest`, `generate_frida`, `generate_detours`, `find_targets`         |
| `taint`          | Static taint analysis      | `trace_arg`, `trace_return`, `find_sinks`, `data_flow`, `slice`         |
| `coverage`       | Code coverage analysis     | `import_drcov`, `import_lighthouse`, `highlight`, `report`, `uncovered` |

### Utility Tools

| Tool       | Description             | Key Actions                                                |
| ---------- | ----------------------- | ---------------------------------------------------------- |
| `misc`     | Python exec, signatures | `python`, `idc`, `load_sig`, `bookmarks`                   |
| `files`    | Database I/O            | `save`, `close`, `open`, `batch`                           |
| `plugins`  | Plugin management       | `list`, `run`                                              |
| `trace`    | Debugger traces         | `get`, `clear`, `set_options`                              |
| `fixups`   | Relocations             | `list`, `get`, `add`, `delete`                             |
| `data_ops` | Data creation           | `make_data`, `make_array`, `make_string`, `make_code`      |
| `debug`    | Debugger control        | `start`, `stop`, `continue`, `step`, `breakpoints`, `regs` |
| `nav`      | Navigation helpers      | `bookmarks`, `goto`, `cursor`, `interesting`               |
| `colorize` | Code coloring           | `set_func`, `set_range`, `get`, `clear`, `palette`         |

---

## 📖 Detailed Parameter Reference

### Universal Parameters

All tools (except `session`) accept these parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `idb` | string | Yes* | Path to IDB file (`.i64`/`.idb`) or original binary. *Optional if a session is active. |
| `action` | string | Yes | The operation to perform. See tool-specific actions above. |

> **Note on `idb` parameter**: When a session is active (created via `session(action="create")`), the `idb` parameter becomes optional - the server will use the session's IDB automatically.

### Address Formats

Addresses can be specified in multiple formats:

| Format | Example | Description |
|--------|---------|-------------|
| Hex string | `"0x401000"` | Hexadecimal with `0x` prefix |
| Decimal | `"4198400"` | Decimal number as string |
| Symbol name | `"main"` | Function or symbol name |
| Expression | `"start+0x100"` | Simple arithmetic expressions |

### Pagination Parameters

Tools that return large result sets support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `offset` | int | 0 | Starting index (0-based) |
| `count` | int | 100 | Maximum number of items to return |

**Example with pagination:**
```python
# Get first 50 functions
data(idb="sample.i64", action="functions", offset=0, count=50)

# Get next 50 functions
data(idb="sample.i64", action="functions", offset=50, count=50)
```

### Tool-Specific Parameters

#### `code` Tool Parameters

| Parameter | Actions | Type | Description |
|-----------|---------|------|-------------|
| `addrs` | all | string/list | Single address or list of addresses |
| `addr` | all | string | Alias for `addrs` (single address) |
| `max_items` | graph, find_paths | int | Maximum results (default: 1000) |
| `max_depth` | callgraph, find_paths | int | Traversal depth (default: 5) |
| `format` | export | string | Output format: `json`, `c_header`, `prototypes` |
| `field_name` | xrefs_to_field | string | Struct field in format `struct.field` |
| `target` | find_paths | string | Target address for path finding |

#### `data` Tool Parameters

| Parameter | Actions | Type | Description |
|-----------|---------|------|-------------|
| `query` | all | string | Filter pattern (supports `*` wildcards) |
| `offset` | all | int | Pagination start index |
| `count` | all | int | Max items to return |

#### `search` Tool Parameters

| Parameter | Actions | Type | Description |
|-----------|---------|------|-------------|
| `query`/`pattern` | all | string | Search pattern |
| `start` | all | string | Start address for search range |
| `end` | all | string | End address for search range |

**Byte pattern format:** Use `??` for wildcards: `"48 83 EC ?? 48 8B"` matches `48 83 EC 20 48 8B`, etc.

---

## 🔄 Response Formats

### Success Responses

All successful responses return a JSON object with the requested data:

```json
{
  "functions": [...],
  "_execution_time": 1.23,
  "_session": "ABC12345"
}
```

The `_execution_time` and `_session` fields are added by the server for diagnostics.

### Error Responses

Errors return a structured object:

```json
{
  "error": true,
  "code": "FILE_NOT_FOUND",
  "message": "File not found: /path/to/file.idb",
  "recoverable": false,
  "details": {
    "path": "/path/to/file.idb"
  }
}
```

For recoverable errors, a `retry_after_seconds` field indicates when to retry.

---

## 🔌 Supported MCP Clients

| Client                 | Status         | Notes                               |
| ---------------------- | -------------- | ----------------------------------- |
| **Google Antigravity** | ✅ Recommended | Configure in MCP settings           |
| Claude Desktop         | ✅ Full        | Add to `claude_desktop_config.json` |
| Cursor                 | ✅ Full        | Add to settings.json                |
| VS Code                | ✅ Full        | MCP extension                       |
| Gemini CLI             | ✅ Full        | Google's CLI                        |

---

## 🛠️ Alternative: HTTP Daemon Mode

For batch analysis or custom integrations, use the HTTP daemon:

```bash
# Start daemon (default port is 13337)
python ida_mcp_daemon.py --port 13337

# Call tools via HTTP
curl -X POST http://127.0.0.1:13337 -d '{
  "action": "tool",
  "tool": "data",
  "idb": "C:/samples/malware.exe.i64",
  "args": {"action": "functions", "count": 10}
}'
```

---

## 📁 Project Structure

```
ida-pro-mcp/
├── ida_mcp_stdio.py        # MCP stdio server (main entry point)
├── ida_mcp_daemon.py       # HTTP daemon (alternative mode)
├── src/ida_pro_mcp/
│   └── ida_mcp/
│       ├── api_consolidated.py  # All 40 tool implementations
│       ├── utils.py             # Helper functions
│       └── zeromcp/             # MCP protocol library
├── archive/                # Legacy files (tests, docs)
├── IMPROVEMENTS.md         # Detailed improvement analysis
└── README.md
```

---

## 🛡️ Requirements

- **IDA Pro 9.0+** with Hex-Rays decompiler
- **Python 3.11+**
- **Windows** (primary), Linux/macOS (experimental)

Set `IDADIR` environment variable to your IDA installation path:

```bash
# Windows
set IDADIR=C:\Program Files\IDA Professional 9.2

# Linux/macOS
export IDADIR=/opt/idapro
```

---

## 🔧 Advanced Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IDADIR` | Path to IDA Pro installation | Auto-detected |
| `IDA_MCP_CACHE` | Path to cache directory | `~/.ida_mcp_cache` |
| `IDA_MCP_DEBUG` | Enable debug logging | `0` |

### Debug Mode

Enable detailed IDA execution logging for troubleshooting by setting the `IDA_MCP_DEBUG` environment variable:

```bash
# Windows
set IDA_MCP_DEBUG=1

# Linux/macOS
export IDA_MCP_DEBUG=1
```

When enabled, the server will:
- Capture IDA console output to log files
- Include detailed diagnostics in error messages:
  - Exit codes and stderr output
  - Last 50 lines of IDA log on failures
  - Resolved paths (idat.exe, working directory, IDADIR)
  - Environment configuration status

This helps diagnose issues such as:
- "Can't initialize help system" errors
- Missing resource files even when they exist
- IDA crashes or initialization failures
- Problems with specific tool arguments

---

## 🚨 Error Codes Reference

The server returns structured errors with codes that LLMs can understand and act upon:

| Code | Description | Recovery Action |
|------|-------------|-----------------|
| `FILE_NOT_FOUND` | IDB or binary file doesn't exist | Verify path, check working directory |
| `FILE_LOCKED` | IDB is being used by another process | Wait and retry, or use session tool to check status |
| `FILE_CORRUPT` | IDB file is corrupted | Re-analyze original binary |
| `IDA_NOT_FOUND` | idat.exe not found | Set IDADIR environment variable |
| `IDA_CRASHED` | IDA process terminated unexpectedly | Check IDB compatibility, enable debug mode |
| `IDA_TIMEOUT` | Operation took too long (>300s) | Try smaller scope, or use batch mode |
| `IDA_LICENSE` | IDA license issue | Check IDA license configuration |
| `SESSION_NOT_FOUND` | Invalid session ID | Use `session(action="list")` to find valid sessions |
| `SESSION_LOCKED` | Session IDB is locked | Close other IDA instances |
| `SESSION_REQUIRED` | No IDB specified and no active session | Provide `idb` parameter or create session |
| `TOOL_NOT_FOUND` | Unknown tool name | Check available tools list |
| `INVALID_ARGS` | Missing or invalid parameters | Check required parameters for the action |
| `DECOMPILE_FAILED` | Hex-Rays decompilation failed | Try `disasm` action instead |

### Error Response Format

```json
{
  "error": true,
  "code": "FILE_NOT_FOUND",
  "message": "File not found: C:/samples/malware.exe",
  "recoverable": false,
  "details": {
    "path": "C:/samples/malware.exe"
  }
}
```

For recoverable errors, `retry_after_seconds` indicates when to retry:

```json
{
  "error": true,
  "code": "FILE_LOCKED",
  "message": "IDB is locked by another process",
  "recoverable": true,
  "retry_after_seconds": 5,
  "details": {
    "owner": {"pid": 1234, "locked_at": "2024-01-15T10:30:00"}
  }
}
```

---

## 📝 License

MIT License

---

<p align="center">
  <sub>Built for reverse engineers who prefer AI assistance over tedious clicking.</sub>
</p>
