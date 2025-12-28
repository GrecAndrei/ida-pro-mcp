<p align="center">
  <img src="https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue?style=for-the-badge" alt="IDA Pro 9.0+"/>
  <img src="https://img.shields.io/badge/Python-3.11%2B-green?style=for-the-badge" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/MCP-2.0-purple?style=for-the-badge" alt="MCP 2.0"/>
  <img src="https://img.shields.io/badge/Tools-40-orange?style=for-the-badge" alt="40 Tools"/>
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

### 1. Install for Google Antigravity / IDE Integration

```bash
cd ida-pro-mcp
python install_antigravity.py
```

This adds the MCP server to your IDE's `mcp_config.json`. Restart your IDE.

### 2. Or Add Manually to MCP Config

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

### 3. Use It

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
                                         │   23 tools       │
                                         └──────────────────┘
```

**Key Features:**

- **Fully Standalone**: No IDA GUI required - uses headless `idat.exe`
- **MCP Stdio Protocol**: Works with any MCP-compatible client
- **40 Comprehensive Tools**: Covers all reverse engineering needs
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

| Tool     | Description                 | Key Actions                                                   |
| -------- | --------------------------- | ------------------------------------------------------------- |
| `idb`    | Database metadata           | `meta`, `segments`, `cursor`, `entrypoints`                   |
| `code`   | Decompilation & disassembly | `decompile`, `disassemble`, `xrefs_to`, `xrefs_from`, `graph` |
| `data`   | Data enumeration            | `functions`, `globals`, `strings`, `imports`, `exports`       |
| `search` | Pattern search              | `bytes`, `string`, `immediate`, `name`, `pattern`             |
| `types`  | Type management             | `list`, `get`, `define`, `apply`, `get_members`               |

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

## 🔌 Supported MCP Clients

| Client                 | Status         | Notes                               |
| ---------------------- | -------------- | ----------------------------------- |
| **Google Antigravity** | ✅ Recommended | Use `install_antigravity.py`        |
| Claude Desktop         | ✅ Full        | Add to `claude_desktop_config.json` |
| Cursor                 | ✅ Full        | Add to settings.json                |
| VS Code                | ✅ Full        | MCP extension                       |
| Gemini CLI             | ✅ Full        | Google's CLI                        |

---

## 🛠️ Alternative: HTTP Daemon Mode

For batch analysis or custom integrations, use the HTTP daemon:

```bash
# Start daemon
python ida_mcp_daemon.py --port 13338

# Call tools via HTTP
curl -X POST http://127.0.0.1:13338 -d '{
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
├── install_antigravity.py  # IDE installer
├── src/ida_pro_mcp/
│   └── ida_mcp/
│       ├── api_consolidated.py  # All 20 tool implementations
│       ├── utils.py             # Helper functions
│       └── zeromcp/             # MCP protocol library
├── archive/                # Legacy files (tests, docs)
└── README.md
```

---

## 🛡️ Requirements

- **IDA Pro 9.0+** with Hex-Rays decompiler
- **Python 3.11+**
- **Windows** (Linux support planned)

Set `IDADIR` environment variable to your IDA installation path:

```bash
set IDADIR=C:\Program Files\IDA Professional 9.2
```

---

## 🔧 Advanced Configuration

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

## 📝 License

MIT License

---

<p align="center">
  <sub>Built for reverse engineers who prefer AI assistance over tedious clicking.</sub>
</p>
