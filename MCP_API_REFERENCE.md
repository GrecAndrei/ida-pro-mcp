# IDA Pro MCP - Complete API Reference

This document provides comprehensive documentation for all MCP tools, designed for LLM consumption.
Each tool uses an `action` parameter to specify the operation.

---

## 1. idb - Database Information

Get information about the IDA Database (IDB).

| Action        | Required Params | Returns                                         | Example                     |
| ------------- | --------------- | ----------------------------------------------- | --------------------------- |
| `meta`        | -               | `{path, module, base, size, md5, sha256}`       | `idb(action="meta")`        |
| `segments`    | -               | `{segments: [{name, start, end, size, perms}]}` | `idb(action="segments")`    |
| `cursor`      | -               | `{addr, function?: {addr, name}}`               | `idb(action="cursor")`      |
| `entrypoints` | -               | `{entrypoints: [{addr, name, ordinal}]}`        | `idb(action="entrypoints")` |

---

## 2. code - Code Analysis

Decompilation, disassembly, and graph traversal.

| Action            | Required Params   | Returns                                                | Example                                                          |
| ----------------- | ----------------- | ------------------------------------------------------ | ---------------------------------------------------------------- |
| `decompile`       | `addrs`           | `[{addr, code, prototype}]`                            | `code(action="decompile", addrs="main")`                         |
| `disasm`          | `addrs`           | `[{addr, disasm: [{ea, mnemonic, operands}]}]`         | `code(action="disasm", addrs="0x401000")`                        |
| `xrefs_to`        | `addrs`           | `[{addr, xrefs: [{from, type}]}]`                      | `code(action="xrefs_to", addrs="main")`                          |
| `xrefs_from`      | `addrs`           | `[{addr, xrefs: [{to, type}]}]`                        | `code(action="xrefs_from", addrs="0x401000")`                    |
| `callees`         | `addrs`           | `[{addr, callees: [{addr, name}]}]`                    | `code(action="callees", addrs="main")`                           |
| `callers`         | `addrs`           | `[{addr, callers: [{addr, name}]}]`                    | `code(action="callers", addrs="printf")`                         |
| `blocks`          | `addrs`           | `[{addr, blocks: [{start, end, type}]}]`               | `code(action="blocks", addrs="main")`                            |
| `analyze`         | `addrs`           | `[{addr, code, prototype, callees, callers, strings}]` | `code(action="analyze", addrs="main")`                           |
| `callgraph`       | `addrs`           | `[{addr, callgraph: [{caller, callee}]}]`              | `code(action="callgraph", addrs="main", max_depth=3)`            |
| `find_paths`      | `addrs`, `target` | `[{addr, paths: [[addr1, addr2, ...]]}]`               | `code(action="find_paths", addrs="0x401000", target="0x402000")` |
| `strings_in_func` | `addrs`           | `[{addr, strings: [{addr, value}]}]`                   | `code(action="strings_in_func", addrs="main")`                   |

**Notes:**

- `addrs` accepts: hex strings (`"0x401000"`), names (`"main"`), or lists (`["main", "0x402000"]`)
- `max_items` (default 1000) limits results
- `max_depth` (default 5) limits graph traversal depth

---

## 3. data - Data Enumeration

Query functions, globals, strings, imports, exports.

| Action      | Required Params | Optional                   | Returns                              | Example                               |
| ----------- | --------------- | -------------------------- | ------------------------------------ | ------------------------------------- |
| `functions` | -               | `query`, `count`, `offset` | `{functions: [{addr, name, size}]}`  | `data(action="functions", count=10)`  |
| `globals`   | -               | `query`, `count`, `offset` | `{globals: [{addr, name}]}`          | `data(action="globals", query="g_")`  |
| `strings`   | -               | `query`, `count`, `offset` | `{strings: [{addr, value, length}]}` | `data(action="strings", count=50)`    |
| `imports`   | -               | `count`                    | `{imports: [{module, name, addr}]}`  | `data(action="imports")`              |
| `exports`   | -               | -                          | `{exports: [{addr, name, ordinal}]}` | `data(action="exports")`              |
| `lookup`    | `query`         | -                          | `{addr, name}` or `{error}`          | `data(action="lookup", query="main")` |

**Notes:**

- `query` filters by substring match on name
- `lookup` resolves name→address or address→name

---

## 4. search - Pattern Search

Find bytes, strings, immediates, names, instructions.

| Action      | Required Params | Returns                       | Example                                            |
| ----------- | --------------- | ----------------------------- | -------------------------------------------------- |
| `bytes`     | `pattern`       | `{matches: [{addr}]}`         | `search(action="bytes", pattern="48 83 EC 28")`    |
| `string`    | `pattern`       | `{matches: [{addr, value}]}`  | `search(action="string", pattern="password")`      |
| `immediate` | `pattern`       | `{matches: [{addr}]}`         | `search(action="immediate", pattern="0xDEADBEEF")` |
| `name`      | `pattern`       | `{matches: [{addr, name}]}`   | `search(action="name", pattern="*crypt*")`         |
| `insns`     | `pattern`       | `{matches: [{addr, disasm}]}` | `search(action="insns", pattern="push, mov, sub")` |
| `data_ref`  | `pattern`       | `{matches: [{addr}]}`         | `search(action="data_ref", pattern="0x404000")`    |
| `code_ref`  | `pattern`       | `{matches: [{addr}]}`         | `search(action="code_ref", pattern="main")`        |

**Notes:**

- `bytes`: Use `??` for wildcards: `"E8 ?? ?? ?? ??"` (call instruction)
- `name`: Use `*` for glob matching: `"*printf*"`
- `insns`: Comma-separated mnemonics: `"push, push, call"`
- `limit` (default 100) caps results

---

## 5. types - Type Management

Manage types, structs, enums, prototypes.

| Action          | Required Params | Returns                         | Example                                                                    |
| --------------- | --------------- | ------------------------------- | -------------------------------------------------------------------------- |
| `list`          | -               | `{types: [{name, size, kind}]}` | `types(action="list")`                                                     |
| `get`           | `name`          | `{name, decl, members?}`        | `types(action="get", name="SOCKET")`                                       |
| `set_prototype` | `addr`, `decl`  | `{ok, addr}`                    | `types(action="set_prototype", addr="main", decl="int main(int, char**)")` |
| `parse_decl`    | `decl`          | `{ok, size}` or `{error}`       | `types(action="parse_decl", decl="struct Foo { int x; }")`                 |
| `declare`       | `decl`          | `{ok, name}`                    | `types(action="declare", decl="typedef int HANDLE;")`                      |
| `apply`         | `addr`, `name`  | `{ok}`                          | `types(action="apply", addr="0x404000", name="DWORD")`                     |
| `infer`         | `addr`          | `{addr, type}`                  | `types(action="infer", addr="0x401000")`                                   |
| `read_struct`   | `addr`, `name`  | `{fields: [{name, value}]}`     | `types(action="read_struct", addr="0x405000", name="IMAGE_DOS_HEADER")`    |

---

## 6. memory - Memory Read/Write

Read or write raw memory.

| Action  | Required Params | Optional       | Returns                            | Example                                                         |
| ------- | --------------- | -------------- | ---------------------------------- | --------------------------------------------------------------- |
| `read`  | `addr`          | `type`, `size` | `{addr, value}` or `{addr, bytes}` | `memory(action="read", addr="0x400000", type="bytes", size=16)` |
| `write` | `addr`, `data`  | -              | `{ok}`                             | `memory(action="write", addr="0x401000", data="90 90 90")`      |

**Type values:** `u8`, `u16`, `u32`, `u64`, `bytes`, `string`

---

## 7. modify - Database Modifications

Rename, comment, set types, patch assembly.

| Action      | Required Params | Optional       | Returns            | Example                                                             |
| ----------- | --------------- | -------------- | ------------------ | ------------------------------------------------------------------- |
| `rename`    | `addr`, `value` | -              | `{ok, addr, name}` | `modify(action="rename", addr="sub_401000", value="main")`          |
| `comment`   | `addr`, `value` | `comment_type` | `{ok}`             | `modify(action="comment", addr="0x401000", value="Entry point")`    |
| `set_type`  | `addr`, `value` | -              | `{ok}`             | `modify(action="set_type", addr="0x401000", value="int __cdecl()")` |
| `patch_asm` | `addr`, `value` | -              | `{ok, bytes}`      | `modify(action="patch_asm", addr="0x401000", value="ret")`          |

**Comment types:** `regular` (default), `repeatable`, `anterior`, `posterior`

---

## 8. misc - Miscellaneous Utilities

Python execution, signatures, bookmarks, undo.

| Action          | Required Params | Returns                          | Example                                                |
| --------------- | --------------- | -------------------------------- | ------------------------------------------------------ |
| `python`        | `code`          | `{result: <output>}`             | `misc(action="python", code="len(list(Functions()))")` |
| `idc`           | `code`          | `{result}`                       | `misc(action="idc", code="ScreenEA()")`                |
| `undo`          | -               | `{ok}`                           | `misc(action="undo")`                                  |
| `redo`          | -               | `{ok}`                           | `misc(action="redo")`                                  |
| `sig_list`      | -               | `{signatures: [...]}`            | `misc(action="sig_list")`                              |
| `sig_apply`     | `name`          | `{ok}`                           | `misc(action="sig_apply", name="vc32rtf")`             |
| `til_load`      | `name`          | `{ok}`                           | `misc(action="til_load", name="mssdk")`                |
| `bookmark_list` | -               | `{bookmarks: [{slot, addr}]}`    | `misc(action="bookmark_list")`                         |
| `stack_get`     | `addr`          | `{vars: [{name, type, offset}]}` | `misc(action="stack_get", addr="main")`                |
| `reanalyze`     | `addr`          | `{ok}`                           | `misc(action="reanalyze", addr="0x401000")`            |
| `auto_wait`     | -               | `{ok}`                           | `misc(action="auto_wait")`                             |

---

## 9. debug - Debugger Control

Control debugger, breakpoints, registers.

| Action        | Required Params   | Returns                            | Example                                                 |
| ------------- | ----------------- | ---------------------------------- | ------------------------------------------------------- |
| `start`       | -                 | `{ok}`                             | `debug(action="start")`                                 |
| `stop`        | -                 | `{ok}`                             | `debug(action="stop")`                                  |
| `continue`    | -                 | `{ok}`                             | `debug(action="continue")`                              |
| `step_into`   | -                 | `{ok}`                             | `debug(action="step_into")`                             |
| `step_over`   | -                 | `{ok}`                             | `debug(action="step_over")`                             |
| `run_to`      | `addr`            | `{ok}`                             | `debug(action="run_to", addr="0x401100")`               |
| `breakpoints` | -                 | `{breakpoints: [{addr, enabled}]}` | `debug(action="breakpoints")`                           |
| `add_bp`      | `addr`            | `{ok}`                             | `debug(action="add_bp", addr="main")`                   |
| `del_bp`      | `addr`            | `{ok}`                             | `debug(action="del_bp", addr="main")`                   |
| `enable_bp`   | `addr`, `enabled` | `{ok}`                             | `debug(action="enable_bp", addr="main", enabled=False)` |
| `regs`        | -                 | `{regs: {rax, rbx, ...}}`          | `debug(action="regs")`                                  |
| `callstack`   | -                 | `{frames: [{addr, name}]}`         | `debug(action="callstack")`                             |
| `read_mem`    | `addr`, `size`    | `{bytes}`                          | `debug(action="read_mem", addr="rsp", size=32)`         |
| `write_mem`   | `addr`, `data`    | `{ok}`                             | `debug(action="write_mem", addr="rsp", data="00 00")`   |

**Note:** Most debug actions require an active debugging session.

---

## 10. funcs - Function Management

Create, delete, and modify functions.

| Action      | Required Params   | Returns      | Example                                                 |
| ----------- | ----------------- | ------------ | ------------------------------------------------------- |
| `create`    | `addr`            | `{ok, addr}` | `funcs(action="create", addr="0x401100")`               |
| `delete`    | `addr`            | `{ok}`       | `funcs(action="delete", addr="0x401100")`               |
| `set_flags` | `addr`, `flags`   | `{ok}`       | `funcs(action="set_flags", addr="main", flags=1)`       |
| `comment`   | `addr`, `comment` | `{ok}`       | `funcs(action="comment", addr="main", comment="Entry")` |

---

## 11. segments - Segment Management

| Action     | Required Params         | Returns                            | Example                                                                   |
| ---------- | ----------------------- | ---------------------------------- | ------------------------------------------------------------------------- |
| `list`     | -                       | `{segments: [{name, start, end}]}` | `segments(action="list")`                                                 |
| `add`      | `name`, `start`, `end`  | `{ok}`                             | `segments(action="add", name=".patch", start="0x500000", end="0x501000")` |
| `delete`   | `name` or `start`       | `{ok}`                             | `segments(action="delete", name=".patch")`                                |
| `set_attr` | `name`, `attr`, `value` | `{ok}`                             | `segments(action="set_attr", name=".text", attr="perm", value=5)`         |

---

## 12. files - File Operations

| Action        | Required Params   | Returns                             | Example                                                               |
| ------------- | ----------------- | ----------------------------------- | --------------------------------------------------------------------- |
| `save`        | -                 | `{ok, path}`                        | `files(action="save")`                                                |
| `close`       | -                 | `{ok}` or `{warning}`               | `files(action="close")`                                               |
| `open`        | `path`            | `{ok, path, type}`                  | `files(action="open", path="C:/crackme.exe")`                         |
| `load_binary` | `path`            | `{ok}`                              | `files(action="load_binary", path="lib.dll", base_addr="0x10000000")` |
| `get_cwd`     | -                 | `{cwd}`                             | `files(action="get_cwd")`                                             |
| `set_cwd`     | `path`            | `{ok}`                              | `files(action="set_cwd", path="C:/work")`                             |
| `list_dir`    | `path`            | `{entries: [{name, is_dir, size}]}` | `files(action="list_dir", path=".")`                                  |
| `exists`      | `path`            | `{exists, is_file, is_dir}`         | `files(action="exists", path="./out.idb")`                            |
| `read`        | `path`            | `{content}`                         | `files(action="read", path="./notes.txt")`                            |
| `write`       | `path`, `content` | `{ok}`                              | `files(action="write", path="./out.txt", content="done")`             |

**Note:** `open` uses `idalib.open_database()` in headless mode with CLI args support.

---

## 13-17. Additional Tools

### microcode - Hex-Rays IR

| `get` | `addr` | `{qty, fullsize}` | `microcode(action="get", addr="main")` |
| `blocks` | `addr` | `{blocks: [{idx, start, end}]}` | `microcode(action="blocks", addr="main")` |
| `instructions` | `addr` | `{instructions: [{opcode, ea, text}]}` | `microcode(action="instructions", addr="main")` |

### graph - Graph Export

| `callgraph` | `addr` | `{nodes, edges}` or `{dot}` | `graph(action="callgraph", addr="main", format="dot")` |
| `cfg` | `addr` | `{nodes, edges}` | `graph(action="cfg", addr="main")` |
| `xref_graph` | `addr` | `{nodes, edges}` | `graph(action="xref_graph", addr="0x401000")` |

### bulk - Batch Operations

| `rename` | `items` | `{success, failed}` | `bulk(action="rename", items=[{"addr":"0x401000","value":"main"}])` |
| `comment` | `items` | `{success, failed}` | `bulk(action="comment", items=[{"addr":"0x401000","value":"entry"}])` |
| `export_annotations` | - | `{names, comments}` | `bulk(action="export_annotations", path="./annot.json")` |
| `import_annotations` | `path` | `{stats}` | `bulk(action="import_annotations", path="./annot.json")` |

---

## Error Handling

All tools return `{error: "message"}` on failure. Common errors:

- `"addrs required"` - address parameter missing
- `"No function at <addr>"` - address is not inside a function
- `"Not supported in this version"` - API removed in IDA 9.x
