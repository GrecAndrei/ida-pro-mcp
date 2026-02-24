# Agent Knowledge Base: IDA MCP Tools

This document serves as the agent's internal "source of truth" for tool usage, quirks, and strategies. It will be updated as the agent gains practical experience.

## Critical: Session-Based Workflow (NEW - Makes Everything Easier!)

**Key Change**: The `idb` parameter is now OPTIONAL for all tools once you create or switch to a session!

### Simplified Workflow:
1. **Create a session once**: `session(action="create", binary_path="C:/samples/app.exe")`
   - Returns: `{"ok": true, "session": {"session_id": "ABC12345", ...}}`
2. **Use any tool without `idb`**: All subsequent calls automatically use the active session
   - ✅ `idb(action="meta")` - No idb parameter needed!
   - ✅ `data(action="functions")` - Automatic!
   - ✅ `code(action="decompile", addr="0x401000")` - Just works!
3. **Switch sessions if needed**: `session(action="switch", session_id="XYZ67890")`
4. **Continue without `idb`**: All tools now use the switched session

### Multi-Session Management:
- Each session has a unique ID (e.g., "ABC12345")
- Sessions persist across tool calls
- Switch between sessions with `session(action="switch", session_id="...")`
- List all sessions with `session(action="list")`
- Check current session with `session(action="status")`

**Old way (verbose):**
```
idb(action="meta", idb="C:/samples/app.exe")
data(action="functions", idb="C:/samples/app.exe")
code(action="decompile", addr="0x401000", idb="C:/samples/app.exe")
```

**New way (clean):**
```
session(action="create", binary_path="C:/samples/app.exe")
idb(action="meta")
data(action="functions")
code(action="decompile", addr="0x401000")
```

**IMPORTANT**: Sessions persist indefinitely and survive server restarts. Only use `session(action="close")` when you're completely done analyzing a binary - it **permanently deletes** the IDB and all associated data (bookmarks, logs, metadata).

## Best Practices & Behavioral Heuristics
- **Auto-Analysis Patience**: Always wait for the session creation to return "ok" before any other call. The backend waits for `ida_auto.auto_wait()`, so the IDB is "warm" by the time I get control.
- **Session Lifecycle**: Sessions are persistent. Don't close them unless the user explicitly wants to delete analysis results. Use `switch` to change between sessions, not `close` then `create`.
- **Decompiler Caution**: `code.decompile` is stable but blocking. For massive functions, prefer `code.disasm` or `ctree.get` if just looking for specific patterns to avoid kernel hangs.
- **String Context**: `data.strings` is the fastest way to ID a binary's purpose. Use it immediately after `idb.meta`.
- **Structural Integrity**: When recovering structs with `structs.recover`, verify the offsets with `memory.read` if the decompiler output looks suspicious.
- **Fragility Awareness**: If a tool call times out, assume the IDA process might be hung. Don't immediately retry; check if the process is still alive or if a `_nuclear_reset` is needed.

## Operational Quirks & Session Management
- **Parallel Session Isolation**: Each session runs in its own IDA process. Calls to different sessions do not trigger process swaps.
- **Session Persistence**: Each session maintains its own unique `.i64` database in `ida_mcp_cache/sessions/`. Sessions persist across server restarts.
- **Session Deletion Warning**: `session(action="close")` **permanently deletes** the IDB, bookmarks, logs, and all metadata. Only use when completely done with analysis.
- **Enhanced Session Tool**: The `session` tool now fully supports `discover` (find existing sessions), `list` (view all tracked sessions with pagination), and `status` (current session).
- **Bookmarks Tool**: Use `bookmarks` for persistent, session-correlated forensic markers with rich metadata (tags, priority, notes, category). Bookmarks are deleted when the session is closed.
- **Warm-up Time**: First access to a session spins up its IDA process (~3-10s), but analysis state is preserved in the SID-specific IDB across restarts.

## Tool Categories

### Core Session & Batch Tools
- **session**: Session lifecycle management. Actions: discover, create, list, switch, close (WARNING: permanently deletes), status. Sessions persist across restarts - don't close unless explicitly requested.
- **bookmarks**: Forensic bookmarks with metadata. Actions: add, list, delete, update, clear, find, export.
- **batch**: Execute multiple tool calls in a single request for efficiency.

### Deep Analysis & Reasoning
- **code**: High-level logic recovery. `decompile` for C-like output, `analyze` for comprehensive context, `find_paths` for reachability analysis.
- **ctree**: Decompiler AST (C-Tree) traversal. Used for precise queries (e.g., "find all calls where arg1 is a specific struct"). Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow.
- **microcode**: Hex-Rays Intermediate Representation. Actions: get, blocks, instructions. Essential for defeating obfuscation.
- **taint**: Static data flow analysis. Actions: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice.
- **emulate**: Static tracing and execution sandbox. Actions: static_trace, appcall, decrypt_strings, eval_expr.
- **agent**: High-level orchestrator. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack.

### Database & Context Discovery
- **idb**: Database metadata, segments, and entry points. Actions: meta, summary, segments, entrypoints, bookmarks.
- **data**: Functions, globals, strings, imports, exports. Actions: functions, globals, strings, imports, exports, lookup, bulk_query.
- **search**: Low-level byte/pattern/immediate value discovery. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref.
- **symbols**: PDB/DWARF symbol management. Actions: load_pdb, load_dwarf, status, apply, export.
- **types**: Type Library (TIL) management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.

### Database Modification (The "Writing" Phase)
- **modify**: Renaming, commenting, type setting, patching. Actions: rename, comment, set_type, patch_asm.
- **bulk**: Batch operations for efficiency. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.
- **structs**: Structure recovery. Actions: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable.
- **data_ops**: Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.
- **funcs**: Function boundary management. Actions: create, delete, set_flags, set_name, add_comment, list, info.
- **segments**: Segment management. Actions: list, add, delete, set_attr, set_perms, move.

### Navigation & Utilities
- **nav**: Navigation and triage. Actions: goto, cursor, interesting.
- **calc**: Address and mathematical resolution. Actions: eval, offset, convert, resolve, deref, chain, align.
- **graph**: CFG and callgraph visualization. Actions: callgraph, cfg, xref_graph.
- **misc**: Utilities. Actions: python, idc, load_sig.

### Dynamic Analysis & Forensics
- **debug**: Live debugger control. Actions: start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem.
- **trace**: Execution tracing. Actions: get, clear, set_options.
- **trace_analysis**: Post-mortem trace processing. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit.
- **coverage**: Code coverage analysis. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter.
- **yara_hunt**: YARA pattern matching. Actions: scan, compile, list_rules.
- **entropy**: Packing and encryption detection. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.

### Specialized Analysis Tools
- **imports_deep**: Advanced import resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.
- **strings_xref**: Deep string analysis. Actions: analyze, xref_chain, detect_encoded, find_format, clusters.
- **patterns**: Signature matching. Actions: generate, match, list_sigs, apply_sig, create_sig.
- **diff**: Binary differential analysis. Actions: functions, bytes, signatures, summary, export_binexport.
- **lumina**: Lumina server interaction. Actions: pull, push, status, history, search.
- **hooks**: Instrumentation suggestions. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.

### Export & Annotation
- **export**: Database export. Actions: listing, html, idc, json, binexport, headers.
- **history**: Undo/redo and snapshots. Actions: undo, redo, list, snapshot, restore, diff.
- **comments_ai**: Structured AI annotations. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.
- **colorize**: Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.

### Documentation
- **wiki**: Built-in documentation. Actions: list_topics, read, search, sections, index.

---
Doc status: Updated tool descriptions and actions to match actual implementations.
Last reviewed: 2026-01-11
