#!/usr/bin/env python3
"""Shared tool registry data for schemas.py."""
from .schemas_alias_hints import (
    _ACTION_ALIAS_HINTS,  # noqa: F401
    _COMMON_ARG_ALIAS_HINTS,  # noqa: F401
    _TOOL_ACTION_EXTRA_ALIASES,  # noqa: F401
    _TOOL_SPECIFIC_ARG_ALIASES,  # noqa: F401
)
from .server.tool_registry import tool_actions as _tool_actions_from_registry

BASE_TOOL_ALIASES = {
    "plugins": "misc",
}

TOOLS = [
    # Core session and batch tools (host-side)
    "session",
    "truncation",
    "bookmarks",
    "background",
    "batch",
    # Analysis configuration
    "analysis",

    # Primary data access tools
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    # Modification tools
    "modify",
    "funcs",
    "segments",
    # Utilities
    "misc",
    "calc",
    # Debugging and tracing
    # Project and file management

    "graph",
    "ctree",
    # Structure and type recovery
    "imports_deep",
    "symbols",
    # Differential and comparison
    # Export and annotation

    # Documentation
    "wiki",
    # Intelligence subsystem (extracted from agent)
    "intelligence",
    # --- New LLM-optimized tools ---
    "workflow",
    "gadgets",
    # Unified security analysis (merged: packer, hooks, deobfuscate, crypto_id, entropy, protocol, taint)
    # ABI & calling conventions
    # Summarization & classification
    # Function comparison
    # Stack analysis
    "stack_analysis",
    # Intelligent annotation
    "annotation",
    # String operations
    # CFG analysis
    # Binary info

    # Other components
    # --- New infrastructure tools ---
    "blackboard",
    # --- Governance ---
    "governance",
    # --- Cross-session symbol KB ---
    "knowledge",
    # --- Relocation/fixup management (specialized; not advertised) ---
    # --- Raw-binary sidecar engines (default-off) ---
    "r2",
    "firmware",
    # --- New: struct recovery, emulation, binary diffing, multi-session ---
    "multi_session",
    "emulate",
]

# Tier A — default tools/list surface for agents. Everything else stays callable
# by exact name (backward compatible) but is hidden from tools/list.
# See docs/ROADMAP.md for Tier B/C policy.
ADVERTISED_TOOLS = [
    "session",
    "analysis",
    "code",
    "funcs",
    "search",
    "data",
    "modify",
    "types",
    "memory",
    "segments",
    "idb",
    "misc",
    "intelligence",
    "blackboard",
    "graph",
    "batch",
    "truncation",
]

# Compact action enums for tools/list (lean/ultra). Full TOOL_ACTIONS still
# accepted at call time for backward compatibility.
ADVERTISED_ACTIONS: dict[str, list[str]] = {
    "session": [
        "create", "create_background", "switch", "close", "list", "status",
        "state", "logs", "health", "kill",
    ],
    "search": [
        "find", "nl", "string", "bytes", "api", "callers", "callees",
        "xrefs_to_string", "symbol", "symbol_info", "decompiled", "behavior", "analyze",
        "data_value", "query_lang",
    ],
    "intelligence": [
        "index_fast", "index_batch", "semantic_search", "similar_functions",
        "embedder_status", "intelligence_status",
    ],
    "blackboard": [
        "write", "read", "list", "search", "update", "delete",
        "stats", "coverage", "next_target", "frontier", "workspace_brief",
        "decision_card", "mark_examined", "recall", "conflicts", "stale",
        "export", "publish_findings", "import_annotations", "memory_compile",
        "phase_status", "policy_status", "state_health",
        "start_crawler", "crawler_status", "proposal_list", "trace_status",
    ],
    "code": [
        "decompile", "smart_decompile", "disasm", "blocks", "callees", "callers",
    ],
    "funcs": [
        "list", "info", "create", "change", "delete", "set_flags", "metrics",
        "find_similar", "suggest_names",
    ],
    "misc": [
        "python", "idc", "health", "cache_stats", "plugin_list", "read_file", "write_file",
        # reload is dev-only; still callable, not advertised in compact enum
    ],
    "r2": [
        "status", "bininfo", "load_hints", "disassemble_hypothesis", "vxrefs",
    ],
    "firmware": [
        "detect_vector_table", "detect_load_base", "detect_mmio",
        "rtos_scan", "carve",
    ],
}

_EXTRA_TOOL_ALIASES = {
    "embeddings": "intelligence",
    "ai_classifier": "intelligence",
    "agent_intelligence": "intelligence",
    "analysis_tool": "analysis",
    "annotate": "annotation",
    "annotations": "annotation",
    "assembler": "code",
    "assembly": "code",
    "bookmarks_tool": "bookmarks",
    "code_tool": "code",
    "database": "idb",
    "decompiler": "code",
    "decomp": "code",
    "diag": "misc",
    "disasm": "code",
    "disassembly": "code",
    "fn": "funcs",
    "func": "funcs",
    "function": "funcs",
    "functions": "funcs",
    "graphs": "graph",

    "hexrays": "code",
    "i_db": "idb",
    "ida": "idb",
    "imports": "imports_deep",
    "lookup": "data",
    "notes": "bookmarks",
    "plugins_tool": "misc",
    "python": "misc",

    # Legacy/compat aliases kept for older clients and scripts.
    "comments_ai": "annotation",
    "annotations_ai": "annotation",
    "strings_xref": "graph",
    "emu": "emulate",
    "searches": "search",
    "segment": "segments",
    "session_tool": "session",
    "symbols_tool": "symbols",
    "xref": "graph",
    "xrefs": "graph",
    "govern": "governance",
    "rules": "governance",
    "policy": "governance",
}

TOOL_DESCRIPTIONS = {

    "analysis": "Controls IDA analysis engine and on-the-fly IDB management. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, run, analyze, state, set_gp, save_idb, make_code, undefine, get_af, set_af, force_offset, add_entry, snapshot, restore_snapshot, auto_wait. save_idb persists the IDB to disk. make_code forces bytes at an address to be disassembled as an instruction (use when IDA marked code as data). undefine clears code/data annotations so a region can be reinterpreted. get_af/set_af read and toggle IDA AF_* analysis flags. force_offset tells IDA a value is a pointer and creates an xref. set_gp is RISC-V only — sets GP register for GP-relative xref resolution. add_entry marks an address as an entry point; snapshot/restore_snapshot save and restore a named IDB snapshot; auto_wait blocks until IDA analysis is idle.",
    "annotation": "Automatically generates and manages comments, labels, and documentation across functions. Actions: auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate, get_context, set_structured, bulk_set, export_md, import_md, summary.",
    "background": "Background batch execution for long-running analysis tasks and IDAPython scripts. Submit scripts or tool calls to run in background threads without interrupting IDA. Actions: submit, status, cancel, result, list, wait.",
    "batch": "Executes multiple tool calls in a single request to reduce round trips. Pass a calls array of tool invocations.",
    "blackboard": "Durable RE notebook (canonical knowledge store). Prefer write/read/list/search/update/delete, frontier, next_target, decision_card, stats. Other blackboard actions remain callable. wiki is documentation lookup; knowledge is the cross-session symbol KB — use blackboard for findings.",
    "bookmarks": "Manages named address bookmarks for quick navigation and milestone tracking. Actions: add, list, delete, update, clear, find, export.",
    "calc": "Safe address arithmetic and pointer resolution—use instead of mental math. Includes bitwise helper operations. Actions: eval, offset, convert, resolve, deref, chain, align, bitops.",
    "code": "Decompilation, disassembly, and code analysis (≈ IDA View menu / F5/Tab). smart_decompile: best first call — pseudocode + behavior tags + callers/callees + crypto hints + suggested next actions. decompile: pseudocode only. disasm: assembly listing. detect: custom per-session detector — define rules at runtime (api_chain, string_ref, type_match, xor_threshold, caller_of, callee_of). register persistent detectors with register=true. Actions: smart_decompile, decompile, disasm, detect, decompile_chain, semantic_decompile, diff_functions, trace_argument_origin, explain, decompile_all, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, callgraph, find_paths, strings_in_func, decomp_dataflow, export.",

    "ctree": "Query and traverse the Hex-Rays decompiler ctree AST for a function. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph.",
    "data": "Retrieve core IDB data. functions: list all functions — always includes xref count (capped 999). globals: global variables. strings: string literals — always includes xref count. imports: imported modules and functions. exports: exported entry points. annotations: all named items and comments. read_bytes: raw bytes at an address. lookup: resolve name↔address. bulk_query: multiple queries in one call. capability_matrix: binary capability matrix from imports + function classifications. string_xrefs: ranked string-to-function xref map with module clustering.",
    "firmware": "Headerless/raw-blob firmware shaping: detect_vector_table finds Cortex-M reset/ISR vector tables, detect_load_base infers the preferred load address, detect_mmio locates memory-mapped peripheral regions, rtos_scan heuristically detects RTOS kernels, carve extracts a code/data region into a bounded range. Actions: detect_vector_table, detect_load_base, detect_mmio, rtos_scan, carve.",
    "funcs": "Function boundary management (≈ IDA P/Delete keys). create: define a function at addr (≡ pressing P in IDA). change: set the current function end (≡ IDA Set function end). delete: remove function definition. info: full function metadata — pass include_xrefs/include_prototype/include_stack for richer output. metrics: size/complexity/call counts. find_similar: structural similarity search. suggest_names: name candidates from heuristics. list: paginated function listing (like data(functions)) with structured output. Note: regex-based filters live in search, while renames and comments live on modify. Actions: create, change, delete, set_flags, info, metrics, find_similar, suggest_names, list.",
    "gadgets": "Find ROP/JOP/COP gadgets, stack pivots, and classify exploit chains. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, classify_chain, semantic_find.",
    "governance": "Pre-flight validation for edits: detect contradictions, PII, dangerous patches. Actions: check, redact, list_rules, stats.",
    "graph": "Generate call graphs, CFGs, dominator trees, and xref graphs for visualization. Actions: callgraph, cfg, dominators, xref_graph.",
    "idb": "Query top-level IDB metadata: binary info, segments, entrypoints, bookmarks, and architecture profile guidance for raw binaries. Actions: meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile, state, events, registers. events streams recent analysis/audit events; registers dumps the register state at an address (for debugger/emulator captures).",
    "imports_deep": "Deep import analysis: thunks, delay-loads, forwarded, ordinal, and API set resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.",
     "intelligence": "Local embeddings index + behavior classification backend for search.nl. Prefer index_fast (quick) or index_batch (decompile-quality), then search(action=nl). Actions (core): index_fast, index_batch, semantic_search, similar_functions, embedder_status, intelligence_status.",
    "knowledge": "Cross-session symbol knowledge base (not the analysis notebook). For findings and hypotheses use blackboard. Actions: symbol_lookup, import_symbols, export_session.",

    "memory": "Read, write, and inspect raw memory/bytes in the binary or debuggee. search: set literal=true to bypass integer detection for digit-only patterns. compare: returns hamming_distance for large inputs, edit_distance for small. Actions: read, write, hexdump, search, compare, pointers, entropy, strings, struct_walk, histogram.",
    "misc": "Utility grab-bag: run scripts (python/idc), load/list/apply signatures, inspect cache stats, read/write files on the host filesystem, and reload IDA-side tool modules without restarting. reload: pass module='funcs' or modules='funcs,search' (or 'all') to pick up source changes instantly — no opencode restart needed for IDA-side changes. Actions: python, idc, load_sig, list_sigs, cache_stats, plugin_list, plugin_run, read_file, write_file, health, reload.",
    "modify": "Apply edits to the IDB: rename symbols, add comments (regular/repeatable/anterior/posterior), set types, patch bytes/assembly, create data items/string literals, bracket edits in undo_begin/undo_end, and rename local variables in a decompiled function. All actions run a governance pre-check by default (governed=True); patch_asm/patch_bytes into executable segments are blocked unless explicitly acknowledged. Actions: rename, comment, set_type, patch_bytes, patch_asm, rename_local, create_data, create_strlit, undo_begin, undo_end.",
    "r2": "Rizin/radare2 sidecar engine (default-off) for pre-IDA and complementary triage on raw binaries. status: engine availability. bininfo: file metadata (arch/bits/entry/imports). load_hints: suggested load addresses. disassemble_hypothesis: disassemble at an address without an IDB. vxrefs: find raw pointer-word references to a value. Actions: status, bininfo, load_hints, disassemble_hypothesis, vxrefs.",


    "search": "Primary discovery tool. find: unified names (incl. demangled)+strings+imports+comments+xrefs (+insns unless identifier-like) — pass kind='strings' for a dedicated string-literal search, kind='names' for symbols only. Always returns items[].addr. nl: embedding search (index_fast first; mode=quick|expand). analyze: unified structural analysis (neighborhood/outlier/similar/vulnerable/semantic scopes, uses embedding index + cached call graph). symbol/symbol_info: resolve names/addresses. api/callers/callees/xrefs_to_string: refs. string/bytes for raw patterns. data_value: locate raw byte/word values or ASCII strings in memory. query_lang: structured query-language search over names/strings/imports (lenient grammar — free text falls back to unified find). Results always include results text + items with addr/name/type/score. Actions (core): find, nl, string, bytes, api, callers, callees, xrefs_to_string, symbol, symbol_info, decompiled, behavior, analyze, data_value, query_lang.",
    "segments": "List, create, modify, and analyze binary segments and their permissions/attributes. Actions: list, add, delete, set_attr, set_perms, move, info, analyze, find_code, find_data, compare, merge, sreg_get, sreg_set, sreg_list. sreg_get/sreg_set/sreg_list read, write, and enumerate segment-register (segmented-mode) mappings for a code address.",
     "session": "Full session lifecycle. Prefer: create/switch/close/list/status/state/logs/health. create is blocking and waits until IDA auto-analysis completes, so the returned session is fully analyzed (safe_mode off). create_background (ida_open_background) is EXPERIMENTAL and DISABLED by default — it fails with FEATURE_DISABLED unless IDA_MCP_BACKGROUND_OPEN=1. state: analysis snapshot (binary, coverage, blackboard summary) — call at turn start. logs: tail IDA stdout/stderr without RPC when IDA is busy. Actions (core): create, switch, close, list, status, state, logs, health, kill.",
    "stack_analysis": "Analyze stack frames: buffer sizes, canaries, alignment, spills, variables, and uninitialized regions. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.",
    "symbols": "Loads and manages debug symbols (PDB/DWARF) for the current binary. Actions: load_pdb, load_dwarf, status, apply, export.",
    "multi_session": "Multi-binary session groups — link IDA sessions for cross-binary import/export resolution, cross-session decompilation, and cross-binary xref queries. Actions: group_create, group_list, group_link, group_remove, cross_resolve, cross_decompile, cross_xrefs, status.",
    "emulate": "Drive IDA's native emulator/debugger (ida_dbg) end to end. The tool auto-selects a backend at runtime — built-in emulator candidates (Emulator/emulator) are tried first via load_debugger, then the native 'linux' backend, then bochs/gdb — and reports the active backend in every response (backend + backend_reason). info: emulator overview (backend, why chosen, process state, available registers, current IP). backend: explicitly select/reload a backend by name (force reloads). start: launch the emulated process (optional start_addr/args/input_file/dir). state: current process state + instruction pointer. step: single/multi step — mode into|over|ret, count. run_to: run to an address. suspend/continue: pause/resume. stop: terminate the process (unload=true also unloads the backend). get_reg/set_reg: read/write a register (names list for bulk reads). read_mem/set_mem: read/write debuggee memory (data as hex). Mutating actions run a governance pre-check (governed=true default); failures map to EMULATION_ERROR / EMULATION_TIMEOUT. Actions: info, backend, start, state, step, run_to, suspend, continue, stop, get_reg, set_reg, read_mem, set_mem.",

    "truncation": "Manage truncated tool responses. continue reads the next chunk and requires field when the token contains multiple truncated fields; use the exact name listed in the response's _continue.fields. peek shows metadata (fields, totals, offsets) without consuming data. search greps within full original content. summary gives a compact overview. Also usable as per-call params on any tool: no_truncate=true skips truncation, max_tokens=N overrides budget, trunc_offset/trunc_limit paginate directly. Actions: continue, peek, search, summary.",
    "types": "Manages IDA type system: structs, enums, prototypes, type propagation, and header imports. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header, diff, visualize, propagate, enum_values, type_graph, vtable, struct_member_add, struct_member_del, struct_member_rename, struct_member_set_type, enum_member_add, enum_member_rename, enum_member_revalue, til_delete, til_export, til_import. struct_member_*/enum_member_* edit struct members and enum enumerators; til_delete removes a named type; til_export writes matched types to a C header (cross-session carry); til_import parses a header into the local Type Library.",
    "wiki": "Built-in tool/workflow documentation lookup (not the analysis notebook). For findings use blackboard. Actions: list_topics, read, search, semantic_search, index, sections, suggest.",
    "workflow": "Executes predefined multi-step analysis workflows for common RE tasks. audit_plan validates and scores a plan before execution. execute_plan runs a planned call list (or generated plan) through batch execution with execution metadata. prioritize reorders a dry-run plan by strategy (original/coverage/risk_first). compose merges multiple workflow plans into one deduplicated dry-run execution plan. estimate returns dry-run complexity/risk/category projections. explain returns a dry-run plan plus per-step rationale. plan previews another workflow action without executing it. catalog returns available workflows and required inputs. triage_fast auto-checks idb overview and runs guided analysis. recon_sweep runs broader orientation + structured retrieval + protocol + security posture in one pass. Supports dry_run plan preview and include/exclude tool filtering for controlled orchestration. Actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review.",

}

TOOL_ACTIONS = _tool_actions_from_registry()  # derived from tool_registry.py

# Backward-compat aliases so callers can still ``from schemas_data import TOOL_ACTIONS``.
# The literal data was moved to ``tool_registry._TOOL_ACTIONS`` (Phase 2B).


TOOL_ARG_SCHEMAS = {
    "session": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["session"]},
        "binary_path": {"type": "string", "description": "Path to target binary"},
        "force_new": {
            "type": "boolean",
            "description": "Force creation of a new session even if one exists",
        },
        "analysis_options": {
            "type": "object",
            "description": "Advanced analysis payload. Preferred for architecture/loader config at session creation.",
        },
        "architecture": {
            "type": "object",
            "description": "Canonical preload architecture block for create/update (processor, bitness, endian, loader, loader_options, flags).",
        },
        "ida_args": {"type": ["string", "array"], "items": {"type": "string"}},
        "session_id": {"type": "string", "description": "Session ID for switch/close"},
        "idb": {"type": "string", "description": "Alias for session_id: a session ID, SID_* IDB id, or binary/idb path to target status/state/logs explicitly."},
        "query": {
            "type": "string",
            "description": "Filter sessions by name/path (supports regex, glob, substring)",
        },
        "binary_name": {
            "type": "string",
            "description": "Filter sessions by binary file name (substring of the analyzed file's name)",
        },
        "processor": {"type": "string", "description": "Processor name (e.g. arm, mipsl, tricore)."},
        "flags": {"type": "integer"},
        "loader": {"type": "string", "description": "Loader name used before initial analysis."},
        "value": {"type": ["string", "object"], "description": "Loader option payload alias (same as loader_options)."},
        "loader_options": {"type": ["string", "object"], "description": "Loader option payload applied before analysis."},
        "bitness": {"type": "integer", "description": "Target bitness: 16, 32, or 64."},
        "endian": {"type": "string", "description": "Target endianness: le/little or be/big."},
        "reanalyze": {"type": "boolean"},
        "options": {"type": "object"},
        "analysis_actions": {"type": "array", "items": {"type": "object"}},
        "apply_once": {"type": "boolean"},
        "recover": {"type": "boolean"},
        "backup_on_recover": {"type": "boolean"},
        "aggressive_cleanup": {"type": "boolean"},
        "start": {"type": ["string", "integer"]},
        "end": {"type": ["string", "integer"]},
        "baseaddr": {"type": ["string", "integer"]},
        "start_ea": {"type": ["string", "integer"]},
        "min_ea": {"type": ["string", "integer"]},
        "max_ea": {"type": ["string", "integer"]},
        "limit": {
            "type": "integer",
            "description": "Max sessions to return (list action)",
        },
        "offset": {
            "type": "integer",
            "description": "Skip first N sessions (list action)",
        },
        "tags": {
            "type": ["array", "string"],
            "items": {"type": "string"},
            "description": "Tags for the session (create action). Comma-separated string or array.",
        },
        "notes": {
            "type": "string",
            "description": "Free-form notes for the session (create action).",
        },
        "note": {
            "type": "string",
            "description": "Single note payload for add_note action.",
        },
        "name": {
            "type": "string",
            "description": "New name for the session rename action.",
        },
        "verbose": {
            "type": "boolean",
            "description": "Include per-runtime details for health action.",
        },
        "agents": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Allowed agent names for the sso_activate action. The orchestrator pre-registers which subagent identities may log on.",
        },
        "secret": {
            "type": "string",
            "description": "Realm secret for sso_activate. Optional — falls back to IDA_MCP_SSO_SECRET env, else a generated secret is returned once.",
        },
        "ticket": {
            "type": "string",
            "description": "Signed ticket for the agent_login action: <name>.<base64url(payload)>.<hmac-sha256(secret, payload)>, minted by the orchestrator.",
        },
        "agent": {
            "type": "string",
            "description": "Per-call agent identity tag (host-level, accepted on all tools, never forwarded to IDA). Validated against the identity established by agent_login on this connection. Defaults to the connection's unbound behavior when omitted.",
        },
    },
    "truncation": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
        "token": {"type": "string"},
        "field": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "pattern": {"type": "string", "description": "Search pattern for search action"},
        "query": {"type": "string", "description": "Alias for pattern"},
        "is_regex": {"type": "boolean"},
        "case_sensitive": {"type": "boolean"},
        "limit": {"type": "integer"},
    },
    "bookmarks": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bookmarks"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "notes": {"type": "string"},
        "category": {"type": "string"},
        "priority": {"type": "integer"},
        "tags": {"type": ["array", "string"], "items": {"type": "string"}},
        "query": {"type": "string"},
    },
    "funcs": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["funcs"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "end": {"type": "string"},
        "name": {"type": "string"},
        "flags": {"type": "integer"},
        "force": {"type": "boolean"},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "named_only": {"type": "boolean"},
        "include_prototype": {"type": "boolean"},
        "include_stack": {"type": "boolean"},
        "include_xrefs": {"type": "boolean"},
        "limit": {"type": "integer"},
        "min_score": {"type": "number"},
        "threshold": {"type": "number"},
        "top_k": {"type": "integer"},
        "ea": {"type": "string"},
        "start": {"type": "string"},
        "function": {"type": "string"},
        "target": {"type": "string"},
        "end_ea": {"type": "string"},
        "stop": {"type": "string"},
    },
    "calc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["calc"]},
        "expr": {"type": "string"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "target": {"type": "string"},
        "value": {"type": ["string", "integer"]},
        "bit_op": {"type": "string"},
        "type": {"type": "string"},
        "size": {"type": "integer"},
        "offsets": {"type": ["array", "string"], "items": {"type": "string"}},
        # eval reads a natural-language `query` for action/value inference
        # (e.g. "what is 0x401000 + 0x20"). Previously stripped, so NL eval
        # inference was unreachable through MCP (only bare `expr` worked).
        # `op` is an alias for `bit_op` in bitops.
        "query": {"type": "string"},
        "op": {"type": "string"},
        "to_va": {"type": "boolean", "description": "For resolve: convert file_offset→VA instead of VA→file_offset"},
        "from_file": {"type": "boolean", "description": "Alias for to_va (file_offset→VA direction)"},
        "deref_depth": {"type": "integer", "description": "Multi-hop pointer dereference depth (default 1)"},
        "persist": {"type": "boolean", "description": "Save result to blackboard for external memory"},
        "intent": {"type": "string", "description": "Natural language intent (alias for query)"},
    },
    "memory": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["memory"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "type": {
            "type": "string",
            "enum": [
                "bytes",
                "u8",
                "u16",
                "u32",
                "u64",
                "s8",
                "s16",
                "s32",
                "s64",
                "f32",
                "f64",
                "ptr",
                "string",
            ],
        },
        "size": {"type": "integer"},
        "data": {"type": "string", "description": "Hex-encoded bytes to write for the write action"},
        # Region end + search/compare knobs. `end_addr` is a named handler
        # param; without schema admission it was always None, so search
        # always scanned a fixed ea+0x10000 window and compare could never
        # specify its second region ("addr1/addr2 required"). `regex` /
        # `int_width` select search modes; `depth` bounds struct_walk.
        "end_addr": {"type": "string"},
        "depth": {"type": "integer"},
        "pattern": {"type": "string"},
        "regex": {"type": "boolean"},
        "int_width": {"type": "integer"},
        "addr1": {"type": "string"},
        "addr2": {"type": "string"},
        "governed": {"type": "boolean", "description": "If true, treat the region as governed (constrained) memory for scan/walk semantics"},
    },
    "modify": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["modify"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion. Not required for undo_begin/undo_end."},
        "address": {"type": "string", "description": "Alias for addr"},
        "value": {"type": "string", "description": "New name, comment text, type declaration, assembly instruction(s), or hex bytes"},
        "name": {"type": "string", "description": "Alias for value (when action=rename)"},
        "text": {"type": "string", "description": "Alias for value (when action=comment)"},
        "type_str": {"type": "string", "description": "Alias for value (when action=set_type)"},
        "asm": {"type": "string", "description": "Alias for value (when action=patch_asm)"},
        "comment_type": {"type": "string", "enum": ["regular", "repeatable", "anterior", "posterior"], "description": "Comment type (when action=comment)"},
        "governed": {"type": "boolean", "description": "Run deterministic governance pre-check (default true)"},
        "comment": {"type": "string", "description": "Alias for value (when action=comment)"},
        "hex_bytes": {"type": "string", "description": "Hex byte string for patch_bytes (e.g. '9090')"},
        "nop": {"type": "boolean", "description": "If true, overwrite instruction(s) at addr with NOPs (patch_bytes)"},
        "new_name": {"type": "string", "description": "New local variable name (rename_local)"},
        "var_name": {"type": "string", "description": "Current local variable name (rename_local)"},
        "item_type": {"type": "string", "description": "Data item kind for create_data: byte|word|dword|qword|pointer|array"},
        "size": {"type": "integer", "description": "Byte length for create_strlit, or element count for create_data array/pointer"},
        "count": {"type": "integer", "description": "Number of consecutive items for create_data (default 1), or NOP count for patch_bytes"},
        "strtype": {"type": "string", "enum": ["c", "c16", "c32"], "description": "String type for create_strlit (c/c16/c32)"},
    },
    "misc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["misc"]},
        "expr": {
            "type": "string",
            "description": "Python expression or IDC script to evaluate",
        },
        "code": {"type": "string", "description": "Multi-line Python code to execute"},
        "name": {"type": "string", "description": "Signature name for load_sig / plugin_run"},
        "path": {"type": "string", "description": "Filesystem path for read_file/write_file"},
        "content": {"type": "string", "description": "File content for write_file"},
        "encoding": {"type": "string", "description": "File encoding (default utf-8; binary for hex)"},
        "arg": {"type": "integer", "description": "Plugin argument for plugin_run"},
        "verbose": {"type": "boolean", "description": "Include per-runtime details for health"},
        "module": {"type": "string", "description": "Module name to reload (for reload action, e.g. 'funcs')"},
        "modules": {"type": "string", "description": "Comma-separated module names to reload (for reload action, e.g. 'funcs,search')"},
    },
    "analysis": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["analysis"]},
        "options": {"type": "object"},
        "processor": {"type": "string"},
        "flags": {"type": "integer"},
        "loader": {"type": "string"},
        "value": {"type": ["string", "object"]},
        "bitness": {"type": "integer"},
        "endian": {"type": "string"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "name": {"type": "string", "description": "Plugin name for plugin_run"},
        "arg": {"type": "integer", "description": "Plugin argument for plugin_run"},
        # Blocking / observe knobs for run+wait. Previously NOT admitted by the
        # schema, so the dispatch arg-filter silently stripped them: callers
        # passing blocking=true/pump=true got silent non-blocking behavior with
        # no error. The in-IDA handler bounds the bare-call default to 10s
        # (under IDA_MCP_RPC_TIMEOUT) so these are safe to expose.
        "blocking": {"type": "boolean"},
        "wait": {"type": "boolean"},
        "pump": {"type": "boolean"},
        "poll_timeout": {"type": "number"},
        "gp": {"type": "string", "description": "RISC-V GP value as hex string for set_gp action (e.g. '0x2556f0')"},
        "addr": {"type": "string", "description": "Target address (hex) for make_code, undefine, force_offset"},
        "ea": {"type": "string", "description": "Entry-point address (hex) for add_entry"},
        "size": {"type": "integer", "description": "Byte count for make_code/undefine/force_offset"},
        "af_flag": {"type": "string", "description": "AF_* flag name for get_af/set_af (e.g. 'AF_MARKCODE')"},
        "af_value": {"type": "boolean", "description": "Enable/disable flag for set_af"},
        "path": {"type": "string", "description": "IDB save path for save_idb (default: current IDB)"},
        # snapshot / add_entry / auto_wait actions
        "ordinal": {"type": "integer", "description": "Snapshot ordinal for restore_snapshot"},
        "timeout_ms": {"type": "integer", "description": "Wait timeout in milliseconds for auto_wait (default: bounded by RPC timeout)"},
        "snapshot_id": {"type": "string", "description": "Snapshot id/name for restore_snapshot"},
    },
    "annotation": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["annotation"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "limit": {"type": "integer", "description": "Result limit for list/import"},
        "prefix": {"type": "string", "description": "Comment prefix filter for list"},
        "dry_run": {"type": "boolean", "description": "Report what would be written without touching the IDB"},
        "text": {"type": "string", "description": "Comment text"},
        "items": {"type": "array", "items": {"type": "object"}, "description": "Annotation items for import"},
        "path": {"type": "string", "description": "File path for import/export"},
        "fmt": {"type": "string", "description": "Comment format: plain|markdown|structured (alias: format)"},
        "value": {"type": "string", "description": "Proposed comment text to validate (for validate action)"},
    },
    "data": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["data"]},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "include_prototype": {"type": "boolean"},
        "include_xrefs": {"type": "boolean"},
        "min_size": {"type": "integer"},
        "named_only": {"type": "boolean"},
        "items": {"type": "array", "items": {"type": "object"}},
        # `queries` is the alias bulk_query reads alongside `items`.
        "queries": {"type": "array", "items": {"type": "object"}},
        # read_bytes action
        "addr": {"type": "string"},
        "size": {"type": "integer"},
    },
    "search": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["search"]},
        "pattern": {"type": "string"},
        "query": {"type": "string"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "limit": {"type": "integer"},
        "offset": {"type": "integer"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "case_sensitive": {"type": "boolean"},
        "include_context": {"type": "boolean"},
        "include_items": {"type": "boolean"},
        "include_breakdown": {"type": "boolean"},
        "timeout_ms": {"type": "integer"},
        "max_functions": {"type": "integer"},
        "preview_lines": {"type": "integer", "description": "Lines of pseudocode context around each decompiled match (0-10)"},
        "sample": {"type": "boolean"},
        "sample_max_funcs": {"type": "integer"},
        # Semantic search params — previously stripped by arg filter, making
        # semantic_action, intent, semantic_min_score, include_semantic_alternatives,
        # and constraints unreachable through MCP (defaults always applied).
        "semantic_action": {"type": "string", "description": "Semantic action alias for action normalization"},
        "intent": {"type": "string", "description": "Natural language intent (alias for pattern)"},
        "semantic_min_score": {"type": "number", "description": "Minimum semantic score threshold (default 0.0)"},
        "include_semantic_alternatives": {"type": "boolean", "description": "Include alternative semantic matches"},
        "constraints": {"type": "object", "description": "Schema constraints for structured search"},
        "kind": {"type": "string", "enum": ["all", "names", "strings", "imports", "comments", "instructions", "refs"], "description": "Restrict action='find' to one category. kind='strings' is a dedicated string-literal search; kind='names' a symbol-only search. Default 'all'."},
        # Combinator / NL kwargs (must be admitted — host rejects unknown keys)
        "mode": {"type": "string", "description": "nl mode: quick|expand (default expand)"},
        "rerank": {"type": "boolean", "description": "Re-score recalled candidates with the cross-encoder reranker (auto in expand mode, off in quick; no-op when no rerank model is installed)."},

        "target": {"type": "string", "description": "Alias for pattern/addr for ref searches"},
        "ea": {"type": "string", "description": "Address alias for pattern/addr"},
        "scope": {"type": "string", "description": "analyze scope: neighborhood|outlier|similar|vulnerable|semantic (default auto)"},
        "metric": {"type": "string", "description": "outlier metric: size|complexity|bb_count|orphan|leaf|hub|deep|tiny|huge"},
        "top": {"type": "integer", "description": "outlier top N (default 50)"},
        "top_k": {"type": "integer", "description": "fingerprint top K (default 20)"},
        "radius": {"type": "integer", "description": "neighborhood radius (default 10)"},
        "src": {"type": "string", "description": "path source symbol/addr"},
        "dst": {"type": "string", "description": "path destination symbol/addr"},
        "max_depth": {"type": "integer", "description": "path/reach max BFS depth"},
        "depth": {"type": "integer", "description": "reach/noreach BFS depth"},
        # data_value / query_lang actions
        "value": {"type": "string", "description": "Raw value to locate for data_value (e.g. '0xDEADBEEF' or ASCII string)"},
        "endian": {"type": "string", "enum": ["little", "big"], "description": "Byte order for data_value scan (default: binary endianness)"},
        "size": {"type": "integer", "description": "Byte width for data_value scans (1/2/4/8; default: auto-detect)"},
    },
    "r2": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["r2"]},
        "binary_path": {"type": "string", "description": "Absolute path to the raw binary for r2 sidecar operations (defaults to the current session binary)"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or file offset for disassemble_hypothesis / load_hints"},
        "value": {"type": "string", "description": "Raw value whose pointer-word references to locate (for vxrefs)"},
        "count": {"type": "integer", "description": "Max instructions to disassemble (disassemble_hypothesis)"},
        "limit": {"type": "integer", "description": "Max results to return (vxrefs)"},
    },
    "firmware": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["firmware"]},
        "start": {"type": "string", "description": "Inclusive start address of the carve/triage window (hex)"},
        "end": {"type": "string", "description": "Exclusive end address of the carve/triage window (hex)"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") for region-relative checks"},
        "limit": {"type": "integer", "description": "Max results to return (detect_* / rtos_scan)"},
    },
    "emulate": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["emulate"]},
        "name": {"type": "string", "description": "Register name (get_reg/set_reg) or backend name (backend action)."},
        "names": {"type": "array", "items": {"type": "string"}, "description": "Registers to read in one get_reg call."},
        "value": {"type": "string", "description": "Register value for set_reg (hex string like '0x10' or decimal string)."},
        "address": {"type": "string", "description": "Function name or hexadecimal address for run_to/read_mem/set_mem."},
        "size": {"type": "integer", "description": "Byte count for read_mem (default 16, max 4096)."},
        "data": {"type": "string", "description": "Hex bytes to write for set_mem (e.g. '9090')."},
        "start_addr": {"type": "string", "description": "Optional start address for start."},
        "args": {"type": "string", "description": "Process argv string for start."},
        "input_file": {"type": "string", "description": "Input file path for start."},
        "dir": {"type": "string", "description": "Working directory for start."},
        "count": {"type": "integer", "description": "Step count for step (default 1)."},
        "mode": {"type": "string", "enum": ["into", "over", "ret"], "description": "Step mode (default 'into')."},
        "force": {"type": "boolean", "description": "Reload the backend even if one is loaded (backend action)."},
        "unload": {"type": "boolean", "description": "Unload the backend after stop."},
        "governed": {"type": "boolean", "description": "Run the governance pre-check on mutating actions (default true)."},
        "timeout_ms": {"type": "integer", "description": "Per-action timeout in milliseconds (default 30000)."},
        "idb": {"type": "string", "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."},
    },
    "workflow": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["workflow"]},
        "planned_calls": {
            "type": "array",
            "items": {"type": "object"},
            "description": "For action='prioritize'/'execute_plan'/'audit_plan': optional dry-run call list to reorder, execute, or validate.",
        },
        "priority_mode": {
            "type": "string",
            "enum": ["original", "coverage", "risk_first"],
            "description": "For action='prioritize': sorting strategy for dry-run plan ordering.",
        },
        "continue_on_error": {
            "type": "boolean",
            "description": "For action='execute_plan': continue executing later calls when one call fails.",
        },
        "max_steps": {
            "type": "integer",
            "minimum": 1,
            "maximum": 200,
            "description": "For action='execute_plan': maximum calls to execute from the provided/generated plan.",
        },
        "workflow_actions": {
            "type": ["array", "string"],
            "items": {"type": "string"},
            "description": "For action='compose': list of workflow actions to merge into one dry-run plan.",
        },
        "workflow_action": {
            "type": "string",
            "description": "For action='plan': target workflow action to preview (for example triage_fast or recon_sweep).",
        },
        "addr": {
            "type": "string",
            "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion.",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "description": "Max findings per sub-step.",
        },
        "profile": {
            "type": "string",
            "enum": ["quick", "balanced", "deep"],
            "description": "Depth profile override for underlying pipelines.",
        },
        "dry_run": {
            "type": "boolean",
            "description": "When true, return the planned calls and workflow metadata without executing tool steps.",
        },
        "include_tools": {
            "type": ["array", "string"],
            "items": {"type": "string"},
            "description": "Optional allow-list of tool names to keep in the generated plan.",
        },
        "exclude_tools": {
            "type": ["array", "string"],
            "items": {"type": "string"},
            "description": "Optional deny-list of tool names to remove from the generated plan.",
        },
    },
    "types": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["types"]},
        "name": {"type": "string", "description": "Type name, or variable name for apply"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "decl": {"type": "string", "description": "Type declaration string (or header content)"},
        "query": {"type": "string", "description": "Search query for list/search_structs"},
        "kind": {"type": "string", "description": "Apply kind: function, global, local"},
        "offset": {"type": "integer", "description": "Pagination offset (or member byte offset for struct_member_add; -1 appends)"},
        "count": {"type": "integer", "description": "Maximum items to return"},
        "other_name": {"type": "string", "description": "Second type name (for diff)"},
        "value": {"type": "integer", "description": "Enum value to look up (enum_values) or enum member value (enum_member_*)"},
        "max_depth": {"type": "integer", "description": "Maximum recursion depth for type_graph"},
        "struct_name": {"type": "string", "description": "Struct type name (struct_member_* actions)"},
        "member_name": {"type": "string", "description": "Member/enumerator name (struct_member_*/enum_member_* actions)"},
        "new_name": {"type": "string", "description": "Replacement name (struct_member_rename / enum_member_rename)"},
        "type_str": {"type": "string", "description": "C type string (struct_member_add / struct_member_set_type)"},
        "size": {"type": "integer", "description": "Member size in bytes (struct_member_add when type_str omitted)"},
        "enum_name": {"type": "string", "description": "Enum type name (enum_member_* actions)"},
        "enum_value": {"type": "integer", "description": "Enum member value (enum_member_add / enum_member_revalue)"},
        "path": {"type": "string", "description": "TIL file path (til_export / til_import)"},
        "til_filter": {"type": "string", "description": "Type-name filter for til_export (default '*')"},
        "seed_addr": {"type": "string", "description": "Alias for addr (type inference seed)"},
        "type_name": {"type": "string", "description": "Alias for name"},
    },
    "segments": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["segments"]},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "name": {"type": "string"},
        "sclass": {"type": "string"},
        "attr": {"type": "string"},
        "value": {"type": ["string", "integer"]},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        # `name2` is the second-segment name for compare/merge. Without
        # admission, name-based compare was unreachable (only address-based
        # via `end` worked). The address/name aliases are admitted for
        # parity with the handler's alias normalization block.
        "name2": {"type": "string"},
        "address": {"type": "string"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "ea": {"type": "string"},
        "segment": {"type": "string"},
        "address2": {"type": "string"},
        "addr2": {"type": "string"},
        "ea2": {"type": "string"},
        "segment2": {"type": "string"},
        "segment_name": {"type": "string"},
        "segment_name2": {"type": "string"},
        # sreg_get/sreg_set/sreg_list actions
        "reg": {"type": "string", "description": "Segment register name for sreg_get/sreg_set/sreg_list (e.g. 'cs', 'ds', 'ss', 'es', 'fs', 'gs')"},
    },

    "intelligence": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["intelligence"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
        "max_items": {"type": "integer"},
        "threshold": {"type": "number"},
        "top_k": {"type": "integer"},
        "block": {"type": "boolean"},
        "probe": {"type": "boolean"},
        "deep_hash": {"type": "boolean"},
        "limit": {"type": "integer"},
        "index_limit": {"type": "integer", "description": "Maximum functions to index in this resumable pass."},
        "mode": {"type": "string", "enum": ["fast", "full"]},
        "start_after": {"type": "string", "description": "Resume indexing after this hexadecimal function address."},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "ranges": {"type": "array", "items": {"type": "object"}},
        "radius": {"type": "integer"},
        "min_size": {"type": "integer"},
        "max_size": {"type": "integer"},
        "constraints": {"type": "object", "description": "Structured query constraints"},
        "offset": {"type": "integer", "description": "Skip first N results"},
        "order_by": {"type": "string", "description": "Column to order by (e.g., 'entropy DESC')"},
        "include_apis": {"type": "boolean", "description": "Include API list in results"},
        "include_strings": {"type": "boolean", "description": "Include string refs in results"},
        "include_resolved": {"type": "boolean"},
        "similar_top_k": {"type": "integer"},
        "min_similarity": {"type": "number", "description": "Cosine threshold for 'lookalike' (default 0.85)."},
        "mark_examined": {"type": "boolean", "description": "Record every family member as examined in one call (default false)."},
        "verdict": {"type": "string", "description": "Verdict used when mark_examined is true (default boring)."},
    },

    "idb": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["idb"]},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        # `state` reads `audit_tail` (number of recent audit records to show).
        # Previously stripped, so state always returned the default 5.
        "audit_tail": {"type": "integer"},
        # events / registers actions
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "limit": {"type": "integer", "description": "Max events to return for events action"},
        "tail": {"type": "integer", "description": "Return only the N most recent events"},
    },
    "code": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["code"]},
        "addrs": {"type": ["array", "string"], "items": {"type": "string"}, "description": "Hex address string(s) (e.g. \"0x356f8\") or function name(s). Pass verbatim from search results — no mental math, no decimal conversion."},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "max_items": {"type": "integer"},
        "max_depth": {"type": "integer"},
        "format": {"type": "string"},
        "disasm_style": {"type": "string", "enum": ["csmini", "classic", "annotated"]},
        "include_bytes": {"type": "boolean"},
        "end": {"type": "string"},
        "limit": {"type": "integer"},
        "field_name": {"type": "string"},
        "target": {"type": "string"},
        "query": {"type": "string", "description": "decompile_all: budget/clamp query text or a filter expression to narrow the decompile set."},
        "details": {"type": "boolean", "description": "decompile: include verbose enrichment (var_rename_hints, annotated_code, complexity, dataflow top_hubs). Default false."},
        "window": {"type": "integer", "description": "disasm: ±N instructions around the start address."},
        "structured": {"type": "boolean", "description": "disasm: return per-instruction JSON instead of text."},
        "include_comments": {"type": "boolean"},
        "annotate_branches": {"type": "boolean"},
        # detect (custom per-session detector engine) — previously the action
        # was advertised but every one of its params was rejected.
        "rule_type": {"type": "string", "description": "detect rule: api_chain|string_ref|type_match|xor_threshold|caller_of|callee_of|list|delete"},
        "threshold": {"type": "integer", "description": "detect xor_threshold: minimum XOR ops (default 4)"},
        "apis": {"type": ["array", "string"], "items": {"type": "string"}, "description": "detect api_chain: API names in sequence"},
        "chain": {"type": ["array", "string"], "items": {"type": "string"}, "description": "detect api_chain alias for apis"},
        "strict_order": {"type": "boolean", "description": "detect api_chain: enforce call order (default true)"},
        "pattern": {"type": "string", "description": "detect string_ref: string content pattern"},
        "string": {"type": "string", "description": "detect string_ref alias for pattern"},
        "type_pattern": {"type": "string", "description": "detect type_match: parameter type pattern (e.g. 'SOCKET')"},
        "type": {"type": "string", "description": "detect type_match alias for type_pattern"},
        "name": {"type": "string", "description": "detect: registered rule name"},
        "rule_name": {"type": "string", "description": "detect alias for name"},
        "register": {"type": "boolean", "description": "detect: persist the rule for the session"},
        "rule": {"type": "object", "description": "detect: rule dict when registering"},
        "list_detectors": {"type": "boolean", "description": "detect: list registered detectors"},
        "delete_detector": {"type": "boolean", "description": "detect: delete a registered detector"},
        "function": {"type": "string", "description": "detect caller_of/callee_of alias for target"},
        "arg_index": {"type": "integer", "description": "trace_argument_origin: 1-based index of the argument to trace (default 1)"},
        "max_callers_per_level": {"type": "integer", "description": "trace_argument_origin: cap on callers followed per recursion level"},
        "offset": {"type": "integer", "description": "decompile_all: number of matched functions to skip before returning the page (pagination)."},
        "mode": {"type": "string", "enum": ["full", "listing"], "description": "decompile_all: 'full' decompiles each function (default); 'listing' returns a fast disasm-only table (addr/name/size/prototype) without Hex-Rays."},
    },
    "ctree": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["ctree"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
    },
    "gadgets": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["gadgets"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
        "raw": {"type": "boolean", "description": "Force a byte-level linear sweep: raw-decode from every offset in the exec region even when IDA has disassembled heads (auto-enabled when the region has no defined instruction heads)."},
        "auto_blackboard": {"type": "boolean", "description": "Store mitigation/exploit findings in the blackboard (opt-in; default keeps read actions pure)."},
        "limit": {"type": "integer"},
        "max_insns": {"type": "integer"},
        "source_actions": {"type": ["array", "string"], "items": {"type": "string"}},
        "source_limit": {"type": "integer"},
        "rebuild_index": {"type": "boolean"},
        "min_score": {"type": "integer"},
        "offset": {"type": "integer"},
    },
    "wiki": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["wiki"]},
        "topic": {"type": "string"},
        "query": {"type": "string"},
        "section": {"type": "string"},
        "lines": {
            "type": "string",
            "description": "Line selector such as '10-40', '25', '10-', or '-40'.",
        },
        "line_start": {"type": "integer"},
        "line_end": {"type": "integer"},
        "offset": {"type": "integer"},
        "limit": {"type": "integer"},
        "max_results": {"type": "integer"},
        "category": {"type": ["string", "array"], "items": {"type": "string"}},
        "fuzzy": {"type": "boolean"},
        "strict_topic": {"type": "boolean"},
        "include_related": {"type": "boolean"},
        "include_snippets": {"type": "boolean"},
        "context_lines": {"type": "integer"},
        "verbose": {
            "type": "boolean",
            "description": "Include full structural metadata in wiki responses.",
        },
    },
    "background": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["background"]},
        "task_id": {"type": "string", "description": "Batch task identifier returned by submit"},
        "script": {"type": "string", "description": "IDAPython script source to run in background"},
        "tool_call": {
            "type": "object",
            "description": "Tool call to execute: {'tool': 'session', 'action': 'status', 'args': {...}}",
            "properties": {
                "tool": {"type": "string"},
                "action": {"type": "string"},
                "args": {"type": "object"},
            },
        },
        "state": {"type": "string", "description": "Filter tasks by state (pending/running/done/failed/cancelled)"},
        "session_id": {"type": "string", "description": "IDA session ID to run tool calls within. Task persists with this session."},
        "timeout": {"type": "number", "description": "Max seconds to wait for task completion"},
    },
    "batch": {
        "calls": {
            "type": "array",
            "items": {
                "type": ["object", "string"],
                "description": "Each item can be 'tool:action', {name, arguments}, or {name, action, ...args}.",
            },
        },
        "script": {"type": "string", "description": "Macro DSL script. Alternative to 'calls'."},
        "stop_on_error": {"type": "boolean"},
        "dry_run": {"type": "boolean"},
        "template": {"type": "string", "description": "Predefined template name"},
        "template_vars": {"type": "object", "description": "Variables for template expansion"},
        "bindings": {"type": "object", "description": "Static {param: value} map for output→input chaining; later call arguments may reference it via $param. Step results chain via step{i}_{key} / step{i}.result{path} / <output_key> refs. Precedence: literal > bindings > step refs."},
    },
    "blackboard": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["blackboard"]},
        "entry_id": {"type": "string", "description": "Entry ID for read/update/delete"},
        "title": {"type": "string", "description": "Title for write/update"},
        "content": {"type": "string", "description": "Content/body text"},
        "category": {"type": "string", "description": "Category (default: general)"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string", "description": "Semantic/behavior query for search and related_by_behavior"},
        "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"},
        "confidence": {"type": "number", "description": "Confidence score 0-1"},
        "priority": {"type": "number", "description": "Investigation priority 0-1"},
        "kind": {"type": "string", "description": "finding, hypothesis, question, task, decision, or examined"},
        "status": {"type": "string", "description": "proposed, open, confirmed, resolved, or rejected"},
        "reason": {"type": "string", "description": "Lifecycle transition reason"},
        "evidence": {"type": "array", "items": {"type": "object"}, "description": "Structured supporting observations"},
        "tag": {"type": "string", "description": "Filter by single tag"},
        "min_confidence": {"type": "number", "description": "Minimum confidence filter"},
        "limit": {"type": "integer", "description": "Max entries to return"},
        "top_k": {"type": "integer", "description": "Top-K results for semantic retrieval"},
        "threshold": {"type": "number", "description": "Similarity threshold for semantic retrieval"},
        "include_resolved": {"type": "boolean", "description": "Include resolved entries in semantic retrieval"},
        "include_contradicted": {"type": "boolean", "description": "Include contradicted entries in semantic retrieval"},
        "force": {"type": "boolean", "description": "Force re-embedding of matching entries during semantic recall"},
        "offset": {"type": "integer", "description": "Pagination offset"},
        "db_path": {"type": "string", "description": "Override path to blackboard SQLite DB"},
    },
    "governance": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["governance"]},
        "operation_type": {"type": "string", "description": "Operation type for check: patch, comment, rename, type_change, execution, annotation"},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "proposed_value": {"type": "string", "description": "The proposed value to check or redact"},
        "context": {"type": "object", "description": "Optional context dict for governance check"},
        "metadata": {"type": "object", "description": "Optional metadata dict for governance check"},
    },
    "knowledge": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["knowledge"]},
        "query": {"type": "string", "description": "Fuzzy text query for symbol lookup"},
        "min_confidence": {"type": "number", "description": "Minimum confidence threshold for symbol import"},
        "limit": {"type": "integer", "description": "Result limit"},
        "db_path": {"type": "string", "description": "Override path to symbol knowledge SQLite DB"},
        "chip_family": {"type": "string", "description": "Optional chip family tag for export_session"},
        "session_id": {"type": "string", "description": "Optional source session identifier for export_session"},
    },
}
