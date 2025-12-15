<p align="center">
  <img src="https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue?style=for-the-badge" alt="IDA Pro 9.0+"/>
  <img src="https://img.shields.io/badge/Python-3.11%2B-green?style=for-the-badge" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/MCP-2.0-purple?style=for-the-badge" alt="MCP 2.0"/>
  <img src="https://img.shields.io/badge/Tools-23-orange?style=for-the-badge" alt="23 Tools"/>
  <img src="https://img.shields.io/badge/Actions-120%2B-red?style=for-the-badge" alt="120+ Actions"/>
</p>

<h1 align="center">
  <br>
  🔬 IDA Pro MCP Server
  <br>
  <sub>Model Context Protocol for IDA Pro</sub>
</h1>

<p align="center">
  <strong>The most comprehensive MCP server for IDA Pro.</strong><br>
  23 mega-tools with 120+ actions for AI-powered reverse engineering.<br>
  Optimized for LLM context windows with action-based tool consolidation.
</p>

---

## ⚡ Quick Start

```bash
# Install
pip install -e .
ida-pro-mcp --install

# Start in IDA Pro
# Edit → Plugins → MCP (or Ctrl+Alt+M)

# Configure your MCP client
ida-pro-mcp --config
```

---

## 🎯 Architecture

```
┌─────────────────┐     MCP Protocol     ┌──────────────────┐
│   AI Client     │◄────────────────────►│   MCP Server     │
│ (Claude, Gemini)│      stdio/SSE       │  (Python, uv)    │
└─────────────────┘                      └────────┬─────────┘
                                                  │ HTTP/JSON
                                                  ▼
                                         ┌──────────────────┐
                                         │   IDA Plugin     │
                                         │  (ida_mcp.py)    │
                                         │  :13337          │
                                         └────────┬─────────┘
                                                  │ IDAPython
                                                  ▼
                                         ┌──────────────────┐
                                         │     IDA Pro      │
                                         │   + Hex-Rays     │
                                         └──────────────────┘
```

**Key Design Decisions:**

- **Consolidated API**: 23 mega-tools instead of 100+ individual functions
- **Action-based routing**: Each tool uses an `action` parameter for sub-operations
- **Thread-safe**: `@idaread` / `@idawrite` decorators ensure safe IDA calls
- **IDA 9.0+ compatible**: All deprecated APIs replaced with modern equivalents

---

## 📦 Complete Tool Reference

### Core Database Tools

#### `idb` — Database Information

| Action        | Description                            | Returns                                         |
| ------------- | -------------------------------------- | ----------------------------------------------- |
| `meta`        | Database metadata (path, base, hashes) | `{path, module, base, size, md5, sha256}`       |
| `segments`    | List all segments                      | `{segments: [{name, start, end, size, perms}]}` |
| `cursor`      | Current cursor position                | `{addr, function?: {addr, name}}`               |
| `entrypoints` | Program entry points                   | `{entrypoints: [{addr, name, ordinal}]}`        |

```python
idb(action="meta")
idb(action="segments")
```

---

#### `code` — Decompilation & Analysis

| Action            | Description                                 | Required Params      |
| ----------------- | ------------------------------------------- | -------------------- |
| `decompile`       | Hex-Rays pseudocode                         | `addrs`              |
| `disasm`          | Assembly listing                            | `addrs`              |
| `xrefs_to`        | Cross-references TO address                 | `addrs`              |
| `xrefs_from`      | Cross-references FROM address               | `addrs`              |
| `callees`         | Functions called by target                  | `addrs`              |
| `callers`         | Functions calling target                    | `addrs`              |
| `blocks`          | Basic blocks (CFG nodes)                    | `addrs`              |
| `analyze`         | Full analysis (decompile + xrefs + strings) | `addrs`              |
| `callgraph`       | Generate call graph                         | `addrs`, `max_depth` |
| `find_paths`      | Find paths between addresses                | `addrs`, `target`    |
| `strings_in_func` | Strings referenced in function              | `addrs`              |

```python
code(action="decompile", addrs="main")
code(action="callees", addrs=["0x401000", "0x402000"])
code(action="callgraph", addrs="WinMain", max_depth=3)
```

---

#### `data` — Data Enumeration

| Action      | Description           | Returns                                      |
| ----------- | --------------------- | -------------------------------------------- |
| `functions` | List functions        | `{functions: [{addr, name, size}], total}`   |
| `globals`   | List global variables | `{globals: [{addr, name}]}`                  |
| `strings`   | List strings          | `{strings: [{addr, string, length}], total}` |
| `imports`   | List imports          | `{imports: [{addr, name, module}], total}`   |
| `exports`   | List exports          | `{exports: [{addr, name, ordinal}]}`         |
| `lookup`    | Resolve name↔address  | `{addr, name, is_func}`                      |

```python
data(action="functions", count=10, query="init")
data(action="lookup", query="main")
```

---

#### `search` — Pattern Search

| Action      | Pattern Format                | Example               |
| ----------- | ----------------------------- | --------------------- |
| `bytes`     | Hex bytes with `??` wildcards | `"48 83 EC ?? 48 8B"` |
| `string`    | Substring match               | `"password"`          |
| `immediate` | Constant value                | `"0xDEADBEEF"`        |
| `name`      | Glob pattern                  | `"*crypt*"`           |
| `insns`     | Mnemonic sequence             | `"push, mov, call"`   |
| `data_ref`  | Data references to address    | `"0x404000"`          |
| `code_ref`  | Code references to address    | `"main"`              |

```python
search(action="bytes", pattern="E8 ?? ?? ?? ?? 48 8B", limit=50)
search(action="name", pattern="*printf*")
```

---

### Type System Tools

#### `types` — Type Management

| Action          | Description                               | Params         |
| --------------- | ----------------------------------------- | -------------- |
| `list`          | List all types (structs, enums, typedefs) | —              |
| `get`           | Get type definition                       | `name`         |
| `set_prototype` | Set function prototype                    | `addr`, `decl` |
| `parse_decl`    | Validate C declaration                    | `decl`         |
| `declare`       | Create new type                           | `decl`         |
| `apply`         | Apply type at address                     | `addr`, `name` |
| `infer`         | Infer type at address                     | `addr`         |
| `read_struct`   | Read struct from memory                   | `addr`, `name` |

```python
types(action="declare", decl="struct Packet { int id; char data[256]; };")
types(action="apply", addr="0x405000", name="DWORD")
```

---

#### `enum` — Enum Management

| Action       | Description      | Params                         |
| ------------ | ---------------- | ------------------------------ |
| `list`       | List all enums   | —                              |
| `info`       | Get enum members | `name`                         |
| `create`     | Create enum      | `name`, `bitfield`             |
| `delete`     | Delete enum      | `name`                         |
| `add_member` | Add member       | `name`, `member_name`, `value` |
| `del_member` | Remove member    | `name`, `value`                |
| `apply`      | Apply to operand | `addr`, `operand`, `name`      |
| `search`     | Find by value    | `value`                        |

---

### Modification Tools

#### `modify` — Database Modifications

| Action      | Description    | Params                          |
| ----------- | -------------- | ------------------------------- |
| `rename`    | Rename address | `addr`, `value`                 |
| `comment`   | Add comment    | `addr`, `value`, `comment_type` |
| `set_type`  | Apply type     | `addr`, `value`                 |
| `patch_asm` | Patch assembly | `addr`, `value`                 |

```python
modify(action="rename", addr="sub_401000", value="initialize_connection")
modify(action="comment", addr="0x401000", value="Entry point", comment_type="anterior")
```

---

#### `bulk` — Batch Operations (LLM-Optimized)

| Action               | Description               | Params                          |
| -------------------- | ------------------------- | ------------------------------- |
| `rename`             | Bulk rename               | `items: [{addr, value}]`        |
| `comment`            | Bulk comment              | `items: [{addr, value, type?}]` |
| `apply_type`         | Bulk type application     | `items: [{addr, value}]`        |
| `export_annotations` | Export all names/comments | `path` (optional)               |
| `import_annotations` | Import from JSON          | `path`                          |

```python
bulk(action="rename", items=[
    {"addr": "0x401000", "value": "main"},
    {"addr": "0x401100", "value": "init_crypto"},
    {"addr": "0x401200", "value": "connect_server"}
])
```

---

### Memory & Debug Tools

#### `memory` — Memory Operations

| Action  | Type Values                                  | Description       |
| ------- | -------------------------------------------- | ----------------- |
| `read`  | `u8`, `u16`, `u32`, `u64`, `bytes`, `string` | Read from address |
| `write` | —                                            | Patch bytes       |

```python
memory(action="read", addr="0x400000", type="bytes", size=32)
memory(action="write", addr="0x401000", data="90 90 90 90")
```

---

#### `debug` — Debugger Control

| Action                            | Description         |
| --------------------------------- | ------------------- |
| `start`                           | Launch debugger     |
| `stop`                            | Terminate process   |
| `continue`                        | Resume execution    |
| `step_into` / `step_over`         | Single step         |
| `run_to`                          | Run to address      |
| `breakpoints`                     | List breakpoints    |
| `add_bp` / `del_bp` / `enable_bp` | Manage breakpoints  |
| `regs`                            | Get register values |
| `callstack`                       | Get call stack      |
| `read_mem` / `write_mem`          | Debug memory access |

---

### Advanced Analysis Tools

#### `microcode` — Hex-Rays IR Access

| Action         | Description            | Returns                                       |
| -------------- | ---------------------- | --------------------------------------------- |
| `get`          | Microcode metadata     | `{qty, fullsize}`                             |
| `blocks`       | Microcode basic blocks | `{blocks: [{idx, start, end, npred, nsucc}]}` |
| `instructions` | Microcode instructions | `{instructions: [{opcode, ea, text}]}`        |

```python
microcode(action="blocks", addr="main", maturity=7)
```

---

#### `graph` — Graph Export

| Action       | Format         | Description           |
| ------------ | -------------- | --------------------- |
| `callgraph`  | `json` / `dot` | Function call graph   |
| `cfg`        | `json` / `dot` | Control flow graph    |
| `xref_graph` | `json` / `dot` | Cross-reference graph |

```python
graph(action="callgraph", addr="main", depth=3, format="dot")
graph(action="cfg", addr="0x401000", format="json")
```

---

#### `agent` — High-Level AI Helpers

| Action             | Description                                    |
| ------------------ | ---------------------------------------------- |
| `analyze_function` | Comprehensive function analysis                |
| `explore_address`  | Explore address context                        |
| `find_references`  | Find all references to target                  |
| `search_all`       | Universal search (functions + strings + names) |

```python
agent(action="search_all", query="password")
```

---

### Utility Tools

#### `misc` — Miscellaneous

| Action                   | Description            |
| ------------------------ | ---------------------- |
| `python`                 | Execute Python code    |
| `idc`                    | Execute IDC expression |
| `undo` / `redo`          | Undo/redo operations   |
| `sig_list` / `sig_apply` | FLIRT signatures       |
| `til_load`               | Load type library      |
| `bookmark_list`          | List bookmarks         |
| `stack_get`              | Get stack variables    |
| `reanalyze`              | Force reanalysis       |
| `auto_wait`              | Wait for auto-analysis |

---

#### `files` — File Operations

| Action                      | Description            |
| --------------------------- | ---------------------- |
| `save`                      | Save database          |
| `open`                      | Open database (idalib) |
| `close`                     | Close database         |
| `load_binary`               | Load additional binary |
| `get_cwd` / `set_cwd`       | Working directory      |
| `list_dir`                  | Directory listing      |
| `exists` / `read` / `write` | File operations        |

---

#### `funcs` — Function Management

| Action      | Description                |
| ----------- | -------------------------- |
| `create`    | Create function at address |
| `delete`    | Delete function            |
| `set_flags` | Modify function flags      |
| `comment`   | Set function comment       |

---

#### `segments` — Segment Management

| Action     | Description       |
| ---------- | ----------------- |
| `list`     | List segments     |
| `add`      | Create segment    |
| `delete`   | Delete segment    |
| `set_attr` | Modify attributes |
| `move`     | Rebase segment    |

---

#### `signatures` — FLIRT/TIL/Lumina

| Action                                   | Description             |
| ---------------------------------------- | ----------------------- |
| `list_applied`                           | Applied signature count |
| `list_available`                         | Available .sig files    |
| `apply`                                  | Apply FLIRT signature   |
| `list_tils` / `load_til` / `loaded_tils` | Type libraries          |
| `lumina_pull` / `lumina_push`            | Lumina integration      |

---

## 🔌 Supported MCP Clients

| Client                 | Status         | Notes                |
| ---------------------- | -------------- | -------------------- |
| **Google Antigravity** | ✅ Recommended | Full tool support    |
| Claude Desktop         | ✅ Full        | Native MCP           |
| Cursor                 | ✅ Full        | Add to settings.json |
| VS Code                | ✅ Full        | MCP extension        |
| Gemini CLI             | ✅ Full        | Google's CLI         |
| Amazon Q               | ✅ Full        | AWS integration      |

```bash
# Get config for your client
ida-pro-mcp --config
```

---

## 🛡️ IDA 9.0+ Compatibility

This server is fully compatible with IDA Pro 9.0+ and handles all API deprecations:

| Deprecated API           | Replacement                   |
| ------------------------ | ----------------------------- |
| `ida_struct` module      | `ida_typeinf`                 |
| `ida_enum` module        | `ida_typeinf`                 |
| `ida_nalt.get_entry_*`   | `ida_entry` / `idaapi`        |
| `ida_search.find_binary` | `ida_bytes.bin_search`        |
| `ida_dbg.call_stack_t`   | `ida_dbg.collect_stack_trace` |
| Plugin enumeration       | Not available (returns error) |

All tools include `hasattr` checks and graceful fallbacks.

---

## 📊 Performance

- **23 tools** instead of 100+ (efficient context usage)
- **Batch-first design** for minimal round-trips
- **Thread-safe** with IDA's main thread synchronization
- **Pagination** on large result sets

---

## 📖 Complete API Reference

See **[MCP_API_REFERENCE.md](./MCP_API_REFERENCE.md)** for detailed documentation with:

- All parameters (required/optional)
- Return value schemas
- Usage examples
- Common error handling

---

## 📝 License

MIT License

---

<p align="center">
  <sub>Built for reverse engineers who prefer AI assistance over tedious clicking.</sub>
</p>
