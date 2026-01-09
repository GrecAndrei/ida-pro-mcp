# Agent Knowledge Base: IDA MCP Tools

This document serves as the agent's internal "source of truth" for tool usage, quirks, and strategies. It will be updated as the agent gains practical experience.

### Best Practices & Behavioral Heuristics
- **Auto-Analysis Patience**: Always wait for the session creation to return "ok" before any other call. The backend waits for `ida_auto.auto_wait()`, so the IDB is "warm" by the time I get control.
- **Decompiler Caution**: `code.decompile` is stable but blocking. For massive functions, prefer `code.disasm` or `ctree.get` if just looking for specific patterns to avoid kernel hangs.
- **String Context**: `data.strings` is the fastest way to ID a binary's purpose. Use it immediately after `idb.meta`.
- **Structural Integrity**: When recovering structs with `structs.recover`, verify the offsets with `memory.read` if the decompiler output looks suspicious.
- **Fragility Awareness**: If a tool call times out, assume the IDA process might be hung. Don't immediately retry; check if the process is still alive or if a `_nuclear_reset` is needed.

### Operational Quirks & Session Management
- **Parallel Session Isolation**: Each session runs in its own IDA process. Calls to different sessions do not trigger process swaps.
- **Session Persistence**: Each session maintains its own unique `.i64` database in `ida_mcp_cache/sessions/`. Creating a new session no longer wipes out existing ones.
- **Enhanced Session Tool**: The `session` tool now fully supports `list` (view all tracked sessions) and `status` (current session).
- **Warm-up Time**: First access to a session spins up its IDA process (~3-10s), but analysis state is preserved in the SID-specific IDB.

### Best Practices & Behavioral Heuristics

### Initial Tool Mapping (Jan 5, 2026)

### Deep Analysis & Reasoning
- **code**: High-level logic recovery. `decompile` for C-like output, `find_paths` for reachability analysis. Primary tool for understanding "what" a function does.
- **ctree**: Decompiler AST (C-Tree) traversal. Used for precise queries (e.g., "find all calls where arg1 is a specific struct"). Bypasses text-based parsing issues.
- **microcode**: Hex-Rays Intermediate Representation. Essential for defeating obfuscation or understanding optimizations before they are "cleaned up" for the decompiler.
- **taint**: Static data flow analysis. Use `slice` for quick argument-to-sink scans.
- **emulate**: Scriptable execution sandbox. Good for analyzing small blocks (decryption, hashing) without a full debugger.

### Database & Context Discovery
- **idb**: Database metadata, segments, and entry points. The "map" of the binary.
- **data**: Search for strings, globals, and imports. The "Google" of the binary.
- **search**: Low-level byte/pattern/immediate value discovery.
- **symbols**: Management of PDB/DWARF information for name recovery.
- **types**: Type Library (TIL) management. Managing structs, enums, and function prototypes.

### Database Modification (The "Writing" Phase)
- **modify**: The primary tool for renaming, commenting, and patching.
- **bulk**: Batch operations for renaming or type application across multiple symbols.
- **structs**: Structure recovery and reconstruction from raw memory offsets.
- **data_ops**: Converting raw bytes into meaningful data types (arrays, strings, etc.).
- **funcs**: Fixing function boundaries and managing function-level metadata.

### Navigation & Orchestration
- **agent**: Autonomous sub-agent for exploring specific addresses or functions. Use `context_pack` for fast grounding.
- **nav**: Bookmarks and "interesting" location management. The agent's memory of the binary.
- **graph**: CFG and callgraph visualization.
- **session**: Connection and state management for the MCP.

### Dynamic & Forensic
- **debug**: Live debugger control (step, break, registers).
- **trace / trace_analysis**: Recording and analyzing execution logs.
- **coverage**: Identifying executed vs. unexecuted code paths.
- **yara_hunt**: Pattern matching using YARA rules for malware/code similarity.
- **entropy**: Detecting packing, encryption, or compressed data.

### Specialized Forensic Tools
- **imports_deep**: Resolving complex imports (thunks, forwarded exports).
- **strings_xref**: Deep analysis of string usage and encoded string detection.
- **diff**: Binary diffing for patch analysis or version comparison.
- **hooks**: Instrumentation suggestions (Frida, etc.).
- **comments_ai**: High-level, structured AI annotations.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
