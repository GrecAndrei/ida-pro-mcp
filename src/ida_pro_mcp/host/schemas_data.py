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
    "schemaboot": "intelligence",
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
    # Unified query/edit hubs (delegating to sub-tools)
    "query",
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
    "bulk",
    # Utilities
    "misc",
    "calc",
    "nav",
    # Debugging and tracing
    "debug",
    "coverage",
    "trace_analysis",
    # Project and file management
    "project",
    # Advanced analysis
    "agent",
    "microcode",
    "graph",
    "xref_analysis",
    "ctree",
    "entropy",
    # Structure and type recovery
    "imports_deep",
    "patterns",
    "symbols",
    # Differential and comparison
    "lumina",
    # Export and annotation
    "export",
    "history",
    "colorize",
    "data_ops",
    "firmware_view",
    # Instrumentation
    "hooks",
    # Documentation and YARA
    "wiki",
    "yara_hunt",
    # Intelligence subsystem (extracted from agent)
    "intelligence",
    # --- New LLM-optimized tools ---
    # Security & vulnerability analysis
    "threat_hunt",
    "predictor",
    "workflow",
    "gadgets",
    "taint",
    # Deobfuscation & crypto
    "deobfuscate",
    "crypto_id",
    # ABI & calling conventions
    "abi",
    # Summarization & classification
    "summarize",
    "classify",
    # Function comparison
    "compare",
    # Stack analysis
    "stack_analysis",
    # Protocol analysis
    "protocol",
    # Intelligent annotation
    "annotation",
    # String operations
    "string_ops",
    # CFG analysis
    "cfg_analysis",
    # Binary info
    "binary_info",
    # LLM helpers
    "llm_helpers",
    # Other components
    "bridge_search",
    # --- New infrastructure tools ---
    "blackboard",
    "filter",
    # --- Governance ---
    "governance",
    # --- Cross-session firmware KB ---
    "knowledge",
    # --- Relocation/fixup management (specialized; not advertised) ---
    # --- Packer / protector / anti-cheat detection ---
    "packer",
    # --- New: struct recovery, emulation, binary diffing, multi-session ---
    "struct_recover",
    "emulate",
    "bindiff",
    "multi_session",
    "fixups",
]

ADVERTISED_TOOLS = [
    "session",
    "truncation",
    "bookmarks",
    "batch",
    "wiki",
    "analysis",
    "query",
    "idb",
    "code",
    "data",
    "search",
    "imports_deep",
    "symbols",
    "patterns",
    "types",
    "memory",
    "modify",
    "funcs",
    "segments",
    "bulk",
    "misc",
    "calc",
    "nav",
    "project",
    "debug",
    "graph",
    "ctree",
    "export",
    "history",
    "annotation",
    "binary_info",
    "threat_hunt",
    "predictor",
    "workflow",
    "compare",
    "firmware_view",
    "blackboard",
    "knowledge",
    # RE-useful tools (previously hidden)
    "abi",
    "agent",
    "bridge_search",
    "cfg_analysis",
    "classify",
    "coverage",
    "crypto_id",
    "intelligence",
    "data_ops",
    "deobfuscate",
    "entropy",
    "filter",
    "gadgets",
    "governance",
    "hooks",
    "llm_helpers",
    "lumina",
    "microcode",
    "protocol",
    "stack_analysis",
    "string_ops",
    "summarize",
    "taint",
    "trace_analysis",
    "yara_hunt",
    "packer",
    "struct_recover",
    "emulate",
    "bindiff",
    "multi_session",
    "fixups",
]

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
    "firmware": "firmware_view",
    "firmware_ops": "firmware_view",
    "firmware_view_tool": "firmware_view",
    "firmware_bootstrap": "firmware_view",
    "decomp": "code",
    "diag": "misc",
    "disasm": "code",
    "disassembly": "code",
    "fn": "funcs",
    "func": "funcs",
    "function": "funcs",
    "functions": "funcs",
    "graphs": "graph",
    "helper": "llm_helpers",
    "helpers": "llm_helpers",
    "hexrays": "code",
    "i_db": "idb",
    "ida": "idb",
    "imports": "imports_deep",
    "lookup": "data",
    "notes": "bookmarks",
    "plugins_tool": "misc",
    "python": "misc",
    "queries": "query",
    "vuln": "threat_hunt",
    "vulnerability": "threat_hunt",
    "vulnerabilities": "threat_hunt",
    "threat": "threat_hunt",
    "threat_hunt_tool": "threat_hunt",
    "malware": "threat_hunt",
    "security": "threat_hunt",
    "trace": "threat_hunt",
    "tracing": "threat_hunt",
    # NOTE: do NOT alias "coverage" here — it collides with the canonical
    # `coverage` tool. The collision is silently dropped by _build_tool_aliases
    # but the entry confuses readers. See Phase 1.5 of dedupe plan.
    "c2": "threat_hunt",
    "c2_detect": "string_ops",
    "deobfuscation": "threat_hunt",
    "crypto": "threat_hunt",
    "yara": "threat_hunt",
    "hunt": "threat_hunt",
    "automated_findings": "threat_hunt",
    "recommend": "predictor",
    "predict": "predictor",
    "next_tool": "predictor",
    "workflow_predictor": "predictor",
    # Legacy/compat aliases kept for older clients and scripts.
    "comments_ai": "annotation",
    "annotations_ai": "annotation",
    "strings_xref": "graph",
    # "emulate" alias removed — now a real tool in TOOLS
    "searches": "search",
    "segment": "segments",
    "session_tool": "session",
    "strings": "string_ops",
    "symbols_tool": "symbols",
    "trace_analyze": "trace_analysis",
    "xref": "graph",
    "xrefs": "graph",
    "govern": "governance",
    "rules": "governance",
    "policy": "governance",
}

# Canonical legacy threat-route contract used by host dispatchers.
THREAT_LEGACY_REDIRECT_TOOLS = {
    "c2_detect": "string_ops",
}

THREAT_LEGACY_TRACING_TOOLS = {
    "trace",
    "trace_analysis",
    "coverage",
    "taint",
}

THREAT_LEGACY_VULN_TOOLS = {
    "gadgets",
    "search",
}

THREAT_LEGACY_MALWARE_PASSTHROUGH_TOOLS = {
    "deobfuscate",
    "crypto_id",
    "yara_hunt",
    "string_ops",
}

# Tool->optional action allowlist for legacy passthrough flows.
# `None` means any action is accepted.
THREAT_LEGACY_CONDITIONAL_PASSTHROUGH = {
    "classify": None,
    "protocol": None,
    "summarize": {
        "security_posture",
        "statistics",
        "binary",
        "function",
    },
    "agent": {
        "search_all",
        "find_references",
    },
}

TOOL_DESCRIPTIONS = {
    "abi": "Analyzes calling conventions and ABI details of functions. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.",
    "agent": "High-level AI-assisted analysis combining search, context packing, multi-hop discovery, and CFG similarity. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar, bridge_query, reflect, cluster, fingerprint, cfg_encode, cfg_similar, cfg_stats. NOTE: similar and cluster overlap functionally with intelligence.similar_functions (embedding-based nearest neighbors); for embedding-indexed similarity prefer intelligence.*, for the older 'structured context pack' workflow use agent.*. cfg_encode/cfg_similar/cfg_stats are agent-specific structural CFG features not present in graph.*.",
    "analysis": "Controls IDA analysis engine settings and triggers reanalysis, and runs IDA plugins. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, run, analyze, wait. Note: analysis(action='plugin_run', name='...') is a host-level alias that forwards to misc(action='plugin_run').",
    "annotation": "Automatically generates and manages comments, labels, and documentation across functions. Actions: auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate, get_context, set_structured, bulk_set, export_md, import_md, summary.",
    "background": "Background batch execution for long-running analysis tasks and IDAPython scripts. Submit scripts or tool calls to run in background threads without interrupting IDA. Actions: submit, status, cancel, result, list, wait.",
    "batch": "Executes multiple tool calls in a single request to reduce round trips. Pass a calls array of tool invocations.",
    "binary_info": "Retrieves binary metadata including PE/ELF headers, sections, and build info. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.",
    "blackboard": "Persistent RE knowledge base: findings, hypotheses, IOCs, decisions, and knowledge graph. write/read/list/search/update/delete: CRUD for findings. frontier: ranked unvisited functions — read this when choosing what to analyze next. next_target: priority queue by confidence×recency×xrefs. decision_card: record a verified claim with evidence citations (required before write-surface tools in prove phase). contradict/resolve/add_evidence/calibrate: evidence lifecycle. Actions: write, read, list, search, update, delete, clear, stats, frontier, next_target, decision_card, working_set, state_health, contradict, resolve, add_evidence, calibrate, campaign_summary, propagate_labels, start_crawler, stop_crawler, phase_set, phase_status, policy_set, policy_check.",
    "bookmarks": "Manages named address bookmarks for quick navigation and milestone tracking. Actions: add, list, delete, update, clear, find, export.",
    "bridge_search": "Multi-hop bridge-conditioned search for discovering indirect relationships between entities. Actions: search, bridges.",
    "bulk": "Applies batch edits (renames, comments, types) to multiple addresses in one call. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.",
    "calc": "Safe address arithmetic and pointer resolution—use instead of mental math. Includes bitwise helper operations. Actions: eval, offset, convert, resolve, deref, chain, align, bitops.",
    "cfg_analysis": "Analyzes control flow graph structure including loops, dominators, and complexity. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.",
    "classify": "Classify functions and binaries by purpose. function: single function — embedding-driven BehaviorClassifier (bge-code-v1). binary: overall binary type. all_functions: classify all functions — unnamed functions use BehaviorClassifier. library_code/wrappers/callbacks/initializers/error_handlers: structural classification. hot_functions: most-called functions. orphans: no-caller functions (entry points / dead code). induce_schema: SchemaBoot attribute-value schema for structured retrieval. anchor_coverage: report per-anchor coverage over current IDB. NOTE: the binary and function actions share names with summarize.binary / summarize.function but produce DIFFERENT output — classify returns categories/behavior tags, summarize returns counts/structure. Pick the one that matches the question.",
    "code": "Decompilation, disassembly, and code analysis (≈ IDA View menu / F5/Tab). smart_decompile: best first call — pseudocode + behavior tags + callers/callees + crypto hints + suggested next actions. decompile: pseudocode only. disasm: assembly listing. decompile_chain: function + compact caller/callee context. semantic_decompile: pseudocode + CFG semantics + variable dependency graph. diff_functions: unified diff of two functions. Actions: smart_decompile, decompile, disasm, decompile_chain, semantic_decompile, diff_functions, xrefs_to, xrefs_from, callees, callers, blocks, callgraph, find_paths, strings_in_func, decomp_dataflow, export.",
    "colorize": "Sets and queries color highlighting on functions, ranges, and instructions. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.",
    "compare": "Diff two IDB databases or functions across binaries. Actions: functions, blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.",
    "coverage": "Import and analyze code coverage data to identify hit/missed paths. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter, function_coverage, gaps, compare, merge.",
    "crypto_id": "Detect cryptographic algorithms, constants, and encoding routines in the binary. Actions: identify, constants, encoding, checksums, entropy_analysis, aes_ni.",
    "ctree": "Query and traverse the Hex-Rays decompiler ctree AST for a function. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph.",
    "data": "Retrieve core IDB data. functions: list all functions — always includes xref count (capped 999). globals: global variables. strings: string literals — always includes xref count. imports: imported modules and functions. exports: exported entry points. lookup: resolve name↔address. bulk_query: multiple queries in one call. capability_matrix: binary capability matrix from imports + function classifications. string_xrefs: ranked string-to-function xref map with module clustering.",
    "data_ops": "Change data representation at addresses (≈ IDA Edit menu / D/A/O/U keys). cycle_data: step byte→word→dword→qword at addr (≡ pressing D in IDA). make_data: force a specific size. make_array: define an array. make_string: define a string literal (≡ A in IDA). undefine: undefine bytes (≡ U in IDA). make_code: convert to code (≡ C in IDA). set_repr: change display radix (hex/dec/bin/char/offset). make_ptr: mark as pointer. Actions: make_data, make_array, make_string, undefine, make_code, cycle_data, set_repr, make_ptr.",
    "debug": "Control the debugger: run, step, breakpoints, registers, memory, threads. Actions: status, start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, add_hw_bp, add_watch, regs, set_reg, reg_diff, snapshot_regs, threads, modules, callstack, read_mem, write_mem, search_mem, stack_dump, mem_map, bp_context, trace_start, trace_stop, trace_read, mem_diff.",
    "deobfuscate": "Detect and decode obfuscation: stack strings, API hashing, dead code, anti-disasm. Actions: detect, detect_encoding, stack_strings, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt.",
    "entropy": "Compute entropy over regions to detect packing, encryption, or compressed data. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.",
    "packer": "Detect packers / protectors (UPX, MPRESS, VMProtect, Themida, ASPack, custom) and game anti-cheat references in the current IDB. Returns indicators, classification, recommendation, and a structured workflow with concrete tool calls (static_steps) and external user actions (external_steps). Actions: detect, profile, guide, status, script. script runs Python in the packer's namespace for custom heuristics.",
    "export": "Export IDB content in various formats for external tooling. Actions: listing, html, idc, json, sarif, binexport, headers, redact.",
    "filter": "JQ-like deterministic filtering for tool outputs — prevents context overflow. Supports field extraction (.key), slicing ([0:10]), predicate filter ([?size > 100]), sort, unique, pluck, group_by, count, and first(N). Run any large list result through filter before returning to the LLM. Actions: filter.",
    "firmware_view": "Firmware triage: region scanning, pointer sweeps, table carving, deterministic detection logic, multi-region campaigns, and bootstrap orchestration. Actions: scan_region, auto_retype, pointer_sweep, recommend, table_candidates, smart_carve, rollback_last, review_contradictions, region_profile, pointer_clusters, carve_plan, campaign, segment_sweep, multi_region_campaign, detect_load_address, detect_vector_table, detect_mmio, rtos_scan, triage_snapshot, bootstrap.",
    "fixups": "Manage relocations/fixups (relocation table entries) in the IDB. Actions: list, get, add, delete.",
    "funcs": "Function boundary management (≈ IDA P/Delete keys). create: define a function at addr (≡ pressing P in IDA). delete: remove function definition. info: full function metadata — pass include_xrefs/include_prototype/include_stack for richer output. metrics: size/complexity/call counts. find_similar: structural similarity search. suggest_names: name candidates from heuristics. list: paginated function listing (like data(functions)) with structured output. Note: regex-based filters live in search, while renames and comments live on modify. Actions: create, delete, set_flags, info, metrics, find_similar, suggest_names, list.",
    "gadgets": "Find ROP/JOP/COP gadgets, stack pivots, and classify exploit chains. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, classify_chain.",
    "governance": "Pre-flight validation for edits: detect contradictions, PII, dangerous patches. Actions: check, redact, list_rules, stats.",
    "graph": "Generate call graphs, CFGs, and xref graphs for visualization. Actions: callgraph, cfg, dominators, xref_graph.",
    "xref_analysis": "Cross-reference and callgraph analysis: call chains, common callers/callees, hub/leaf functions, recursion detection, dominator analysis, influence reachability, dependency graphs, dead function detection. Actions: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions.",
    "history": "Undo/redo IDB changes, create snapshots, restore, and diff states. Actions: undo, redo, list, snapshot, restore, diff.",
    "hooks": "Generate dynamic instrumentation hooks (Frida, Detours) for target functions. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.",
    "idb": "Query top-level IDB metadata: binary info, segments, entrypoints, bookmarks, and architecture profile guidance for raw binaries. Actions: meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile.",
    "imports_deep": "Deep import analysis: thunks, delay-loads, forwarded, ordinal, and API set resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.",
     "intelligence": "Intelligence subsystem: embedding-based classification, blackboard-driven indexing, and similarity search. Actions: intelligence_status, embedder_status, anchor_status, refresh_anchors, classify_text, classify_function, index_function, index_batch, similar_functions, semantic_search, blackboard_search, export_index_summary, evidence_card, structural_extract, structural_extract_single, structural_query, structural_get, structural_refresh, structural_stats, structural_delete, structural_ingest. Corpus is blackboard entries (curated hypotheses/IOCs/vulns), not raw decompiled functions — indexing never blocks IDA on full-binary pseudocode embedding. index_function needs a blackboard note at the address (write one first via blackboard(action='write')); index_batch pulls every blackboard entry (filtered by category, capped by max_items, gated by IDA_MCP_EMBED_CORPUS_GATE); similar_functions builds a query doc from the address's blackboard context and runs k-NN over the entry index. semantic_search and blackboard_search use the same vector index; the first is text→vector, the second is text→related_by_behavior on the blackboard store. structural_* actions manage the structural index (extract/get/query/refresh/stats/delete/ingest).",
    "knowledge": "Cross-session firmware knowledge base: chip family identification, persistent symbol memory, and symbol transfer across binaries. Actions: chip_identify, symbol_lookup, import_symbols, export_session, chip_families.",
    "llm_helpers": "Context-optimized helpers for LLM agents. bootstrap: first-turn call list. context_window/function_digest/binary_digest/explain_address: compact analysis helpers. suggest_next/progress_report/focus_area: navigation and planning. behavioral_signature_search: find functions by behavior tag. function_role_classifier: entry_point/callback/dispatcher/wrapper. dangerous_pattern_explainer: exploitation path + mitigation for an address. api_contract_extractor: infer preconditions/postconditions. global_state_influence_mapper: globals a function reads/writes. interprocedural_data_lineage_graph: trace data flow across functions. semantic_diff_explainer: diff two functions by embedding+behavior. path_constrained_search: BFS from addr filtered by behavior tag. cross_artifact_correlation_search: correlate strings/names/blackboard.",
    "lumina": "Interface to Hex-Rays Lumina server for collaborative function metadata sharing. Actions: pull, push, status, history, search, get_metadata.",
    "memory": "Read, write, and inspect raw memory/bytes in the binary or debuggee, plus host filesystem read/write helpers. Actions: read, write, hexdump, search, compare, pointers, find_pointers, entropy, strings, struct_walk, histogram, read_file, write_file.",
    "microcode": "Access Hex-Rays microcode IR for a function at various maturity levels. Actions: get, blocks, instructions, def_use_graph.",
    "misc": "Utility grab-bag: run scripts (python/idc), load signatures, inspect cache stats, and read/write files on the host filesystem. Actions: python, idc, load_sig, cache_stats, plugin_list, plugin_run, read_file, write_file, health. (analysis(action='plugin_run') and memory read/write live alongside here.)",
    "modify": "Apply edits to the IDB: rename symbols, add comments (regular/repeatable/anterior/posterior), set types, and patch assembly (multi-line instructions separated by semicolons). Actions: rename, comment, set_type, patch_asm.",
    "nav": "Navigate the IDA cursor to addresses or semantically interesting locations. Actions: goto, cursor, interesting, semantic_goto.",
    "patterns": "Generate, match, and manage FLIRT/byte pattern signatures for function identification. Actions: generate, match, list_sigs, apply_sig, create_sig, matched, yara_from_func, flirt_generate, match_yara.",
    "predictor": "Deterministic prediction of next useful tool, focus address, or stuck-state detection. recommend_bundle returns a bundled next-step pack (tools + focus + addresses + stall risk). Actions: suggest_next_tool, detect_stuck, suggest_focus, suggest_next_address, risk_of_stall, recommend_bundle.",
    "project": "Project I/O and evidence management. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, evidence_graph, knowledge_merge, confidence_model, replay_pipeline, hypothesis_tracker, temporal_reasoning, semantic_artifact_diff, ai_governance, knowledge_debt, casefile_export.",
    "protocol": "Detect and analyze network protocol structures, parsers, endpoints, state machines, and reconstruct full protocol specs from dispatch tables. Actions: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine, reconstruct, trace_handler, export_spec.",
    "query": "Unified query interface combining data, search, code, types, symbols, and natural-language queries. Actions: data, search, idb, code, types, imports_deep, symbols, patterns, nl, nl_batch. NOTE: query.nl and search.nl both expose natural-language search. query.nl routes through the unified query dispatcher (multi-domain NL over the indexed IDB), search.nl uses the bge-code-v1 embedding ranker directly. Use search.nl for behaviorally-precise RE queries; use query.nl when you want the unified dispatcher to pick a target domain.",
    "search": "Pattern, reference, and semantic search. nl: NL search via bge-code-v1 embeddings (best for RE queries). find: unified search over names/strings/imports/instructions. api: all call sites of an import. decompiled: grep pseudocode across all functions. vulnerable: scan for dangerous API patterns. outlier: structurally anomalous functions (size/complexity/orphan/hub). hunt: named recipes (backdoor/c2/crypto/anti_debug — pass recipe='list'). path: shortest call-graph path between two symbols. reach/noreach: reachability from a root. Actions: nl, behavior, find, semantic, smart_bundle, api, decompiled, structured, vulnerable, constants, callers, callees, bytes, string, immediate, name, insns, mnemonic, comment, regex, func_by_sig, bool, hunt, neighborhood, outlier, fingerprint, path, reach, noreach.",
    "segments": "List, create, modify, and analyze binary segments and their permissions/attributes. Actions: list, add, delete, set_attr, set_perms, move, info, analyze, find_code, find_data, compare, merge. For relocations/fixups use the dedicated `fixups` tool.",
     "session": "Full session lifecycle with runtime tracking, analysis notebook, hypothesis tracking. state: full analysis state snapshot (binary, coverage, blackboard summary, engine status, next actions) — call this at the start of every turn instead of reading the ida://state resource. logs: tail IDA stdout/stderr log files directly without an IDA RPC — use this when IDA is busy (e.g. during auto-analysis) and other tool calls time out; accepts lines= param (default 60). Actions: create/switch/close/list/status/state/logs, snapshot/restore, rate_skill/suggest_strategy/suggest_triage/suggest_analogy/apply_analogy, notebook_append/read, track_hypothesis/confirm/refute, get_phase/advance_phase, recent_workset, macro_set/run, dashboard, health, idle_purge. cleanup_stale: remove sessions older than max_age_days (default 30); with prune_orphans=True (default) also deletes sessions whose binary+idb paths are both gone. idle_purge: tear down live IDA runtimes idle longer than idle_seconds (does NOT touch the database; use cleanup_stale for DB rows). health: server, runtime, IDA, session, wiki diagnostics. Plus ~30 more actions (tag, merge, export_session, etc.) — use tools/list for the full enum.",
    "stack_analysis": "Analyze stack frames: buffer sizes, canaries, alignment, spills, variables, and uninitialized regions. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.",
    "string_ops": "Advanced string analysis and IOC extraction. score_c2/indicators: C2 risk report — BehaviorClassifier on strings + API triads + family guess. ioc_extract: extract all IOCs (URLs, IPs, registry keys, C2 endpoints). persistence/evasion: persistence mechanisms and evasion techniques. find_urls/find_ips/find_paths/find_registry/find_emails/find_commands: pattern extraction. find_c2/find_configs/find_api_keys/find_databases/find_crypto_addrs: semantic extraction. find_stack_strings/find_base64: obfuscated string recovery. entropy_rank: rank strings by Shannon entropy. suspicious/encoding_stats/multilingual/decode_all: analysis utilities.",
    "summarize": "Structured summaries of binary components. binary: overall binary summary. function: single function summary. segment: segment summary. imports_by_category: imports grouped by API category. strings_by_category: strings grouped by type. complexity: function complexity metrics. call_hierarchy: call tree from entry point. data_flow: data flow summary. security_posture: dangerous APIs + mitigations + risk level. statistics: binary-wide stats. report: FULL REPORT — binary + security_posture + live taint scan + blackboard findings + statistics. NOTE: the binary and function actions share names with classify.binary / classify.function but produce DIFFERENT output — summarize returns counts/structure, classify returns categories/behavior tags. Pick the one that matches the question.",
    "symbols": "Loads and manages debug symbols (PDB/DWARF) for the current binary. Actions: load_pdb, load_dwarf, status, apply, export.",
    "taint": "Data flow taint analysis from user-controlled sources to dangerous sinks. Actions: sources (list all taint sources: recv/read/fgets/getenv imports + blackboard IOCs), sinks (dangerous sinks reachable from a source), trace (trace forward from addr/source, write vuln entries to blackboard), paths (full call-graph paths source→sink with dataflow description), report (all sources → all reachable sinks). Example: taint(action='trace', source='recv') finds all paths from recv to memcpy/strcpy/system.",
    "struct_recover": "Automatic struct/type recovery from field access patterns — walks instructions for [base+offset] accesses, clusters by register, infers field types, generates C structs. Actions: recover, recover_all, propagate, preview, apply.",
    "emulate": "Unicorn-backed emulation sandbox — execute functions/slices from the IDB without a debugger (x86/x64, ARM/AArch64, MIPS). Maps IDB segments, sets up stack and calling convention. Actions: run, slice, call, decrypt, trace. NOTE: requires `pip install unicorn`.",
    "bindiff": "Cross-version binary diffing via serialized snapshots — fingerprint all functions, compare against a saved baseline, find patches and security-relevant changes. Unlike compare (same-IDB), bindiff works across IDB versions. Actions: snapshot, diff, patch_analysis, function_match, summary.",
    "multi_session": "Multi-binary session groups — link IDA sessions for cross-binary import/export resolution, cross-session decompilation, and cross-binary xref queries. Actions: group_create, group_list, group_link, group_remove, cross_resolve, cross_decompile, cross_xrefs, status.",
    "threat_hunt": "Runs automated threat-hunting passes to detect malware patterns, vulnerabilities, and suspicious behaviors. Actions: run, malware, vuln, tracing, findings, quick, deep, legacy.",
    "trace_analysis": "Analyzes imported execution traces for coverage, loops, API sequences, and anti-analysis detection. Also provides runtime execution-trace access (get/clear/set_options), static control-flow tracing (static_trace, decrypt_strings, eval_expr, prefetch_context), and emulation-driven deobfuscation (deobfuscate_emulate). Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, execution_timeline_graph, cross_run_diff, coverage_debug_plan, anti_analysis_detect, trace_entropy, api_sequence, loop_analysis, get, clear, set_options, static_trace, decrypt_strings, eval_expr, deobfuscate_emulate, prefetch_context.",
    "truncation": "Continues a previously truncated tool response to retrieve remaining output. Actions: continue.",
    "types": "Manages IDA type system: structs, enums, prototypes, type propagation, and header imports. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header, diff, visualize, propagate, enum_values, type_graph.",
    "wiki": "Accesses built-in documentation and tool usage guides within MCP context. Actions: list_topics, read, search, semantic_search, index, sections, suggest.",
    "workflow": "Executes predefined multi-step analysis workflows for common RE tasks. audit_plan validates and scores a plan before execution. execute_plan runs a planned call list (or generated plan) through batch execution with execution metadata. prioritize reorders a dry-run plan by strategy (original/coverage/risk_first). compose merges multiple workflow plans into one deduplicated dry-run execution plan. estimate returns dry-run complexity/risk/category projections. explain returns a dry-run plan plus per-step rationale. plan previews another workflow action without executing it. catalog returns available workflows and required inputs. triage_fast auto-checks idb overview and, for firmware-like binaries, injects firmware_view(action='triage_snapshot') plus guided analysis. recon_sweep runs broader orientation + structured retrieval + protocol + security posture in one pass. Supports dry_run plan preview and include/exclude tool filtering for controlled orchestration. Actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review.",
    "yara_hunt": "Scans the binary with YARA rules and provides match context and xref correlation. Actions: scan, compile, list_rules, match_context, extract_strings, xref_matches.",
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
        "query": {
            "type": "string",
            "description": "Filter sessions by name/path (supports regex, glob, substring)",
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
            "description": "Name for macro_* actions or rename action.",
        },
        "macro": {
            "type": "string",
            "description": "Alias for macro name in macro_* actions.",
        },
        "data": {"type": "object", "description": "Macro payload for macro_set."},
        "macro_data": {
            "type": "object",
            "description": "Alias for macro payload in macro_set.",
        },
        "run_action": {
            "type": "string",
            "description": "Session action to execute for macro_run (default from macro or create).",
        },
        "n": {
            "type": "integer",
            "description": "Count for recent/oldest/recent_workset actions.",
        },
        "include_bookmarks": {
            "type": "boolean",
            "description": "Include bookmark entries in recent_workset.",
        },
        "include_items": {
            "type": "boolean",
            "description": "Include structured items in recent_workset response.",
        },
        "verbose": {
            "type": "boolean",
            "description": "Include per-runtime details for health action.",
        },
        "context": {
            "type": "string",
            "description": "Optional context search/intent string to compute novelty against.",
        },
        "library_idbs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional list of absolute historical library IDB paths to match against.",
        },
        "threshold_cosine": {
            "type": "number",
            "description": "Minimum cosine similarity threshold (default: 0.85).",
        },
        "threshold_structural": {
            "type": "number",
            "description": "Minimum structural ratio similarity threshold (default: 0.70).",
        },
        "mappings": {
            "type": "array",
            "items": {"type": "object"},
            "description": "List of mapping objects to apply, where each object contains addr, name (optional), and comment (optional).",
        },
    },
    "truncation": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
        "token": {"type": "string"},
        "field": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
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
        "comment": {"type": "string"},
        "repeatable": {"type": "boolean"},
        "query": {"type": "string"},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        "named_only": {"type": "boolean"},
        "include_prototype": {"type": "boolean"},
        "include_stack": {"type": "boolean"},
        "include_items": {"type": "boolean"},
        "include_xrefs": {"type": "boolean"},
        # find_similar / suggest_names tuning knobs. Previously NOT admitted, so
        # the dispatch arg-filter silently stripped them: find_similar and
        # suggest_names were unreachable in their tuned form (defaults always
        # applied). Address aliases (ea/start/function/target for addr,
        # end_ea/stop for end) are admitted for parity with the handler.
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
        "data": {"type": "string"},
        "path": {"type": "string", "description": "File path for read_file/write_file"},
        "content": {"type": "string", "description": "Content to write for write_file"},
        "encoding": {
            "type": "string",
            "description": "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data.",
        },
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
    },
    "misc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["misc"]},
        "expr": {
            "type": "string",
            "description": "Python expression or IDC script to evaluate",
        },
        "code": {"type": "string", "description": "Multi-line Python code to execute"},
        "name": {"type": "string", "description": "Signature name for load_sig"},
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
        "timeout": {"type": "number"},
        "max_wait": {"type": "number"},
        # Blocking / observe knobs for run+wait. Previously NOT admitted by the
        # schema, so the dispatch arg-filter silently stripped them: callers
        # passing blocking=true/pump=true got silent non-blocking behavior with
        # no error. The in-IDA handler bounds the bare-call default to 10s
        # (under IDA_MCP_RPC_TIMEOUT) so these are safe to expose.
        "blocking": {"type": "boolean"},
        "wait": {"type": "boolean"},
        "pump": {"type": "boolean"},
        "poll_timeout": {"type": "number"},
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
        "sample": {"type": "boolean"},
        "sample_max_funcs": {"type": "integer"},
        # Combinator actions (bool, hunt, neighborhood, outlier, fingerprint, path, reach, noreach)
        "metric": {"type": "string", "description": "outlier metric: size|complexity|bb_count|orphan|leaf|hub|deep|tiny|huge"},
        "top": {"type": "integer", "description": "outlier top N (default 50)"},
        "top_k": {"type": "integer", "description": "fingerprint top K (default 20)"},
        "radius": {"type": "integer", "description": "neighborhood radius (default 10)"},
        "src": {"type": "string", "description": "path source symbol/addr"},
        "dst": {"type": "string", "description": "path destination symbol/addr"},
        "max_depth": {"type": "integer", "description": "path/reach max BFS depth"},
        "depth": {"type": "integer", "description": "reach/noreach BFS depth"},
    },
    "threat_hunt": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["threat_hunt"]},
        "legacy_tool": {
            "type": "string",
            "description": "Legacy tool name to emulate (for action='legacy').",
        },
        "legacy_action": {
            "type": "string",
            "description": "Legacy action to inherit/route (for action='legacy').",
        },
        "profile": {
            "type": "string",
            "enum": ["quick", "balanced", "deep"],
            "description": "Pipeline depth profile.",
        },
        "query": {
            "type": "string",
            "description": "Optional focus query for post-filtering and relevance scoring.",
        },
        "addr": {
            "type": "string",
            "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion.",
        },
        "include_tracing": {
            "type": "boolean",
            "description": "Include trace/coverage analysis steps.",
        },
        "include_malware": {
            "type": "boolean",
            "description": "Include malware-behavior analysis steps.",
        },
        "include_vuln": {
            "type": "boolean",
            "description": "Include vulnerability analysis steps.",
        },
        "include_evidence": {
            "type": "boolean",
            "description": "Include compact raw per-step payloads for auditability.",
        },
        "limit": {
            "type": "integer",
            "description": "Global max findings to return after dedupe/ranking.",
        },
        "max_steps": {
            "type": "integer",
            "description": "Safety cap for total orchestrated tool calls.",
        },
        "scan_profile": {
            "type": "string",
            "enum": ["quick", "balanced", "deep"],
            "description": "Forwarded depth profile to threat_hunt.",
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Optional severity filter for vulnerability findings.",
        },
        "legacy_passthrough": {
            "type": "boolean",
            "description": "For action='legacy', execute exact mapped legacy action in consolidated flow and include mapping metadata.",
        },
    },
    "predictor": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["predictor"]},
        "session_id": {
            "type": "string",
            "description": "Optional session ID. If omitted, active session is used.",
        },
        "context": {
            "type": "string",
            "description": "Optional context text to bias suggestions.",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 20,
            "description": "Maximum suggestions to return.",
        },
        "recent_n": {
            "type": "integer",
            "minimum": 5,
            "maximum": 200,
            "description": "Recent activity window for sequence modeling.",
        },
        "target_tool": {
            "type": "string",
            "description": "Target tool for explain_decision action.",
        },
        "target_action": {
            "type": "string",
            "description": "Target action for explain_decision action.",
        },
        "tool": {
            "type": "string",
            "description": "Tool name for predictor feedback action.",
        },
        "outcome": {
            "type": "string",
            "enum": ["helpful", "not_helpful"],
            "description": "Feedback outcome for predictor(action='feedback').",
        },
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
    },
    "agent": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["agent"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
        "include_pseudocode": {"type": "boolean"},
        "max_items": {"type": "integer"},
        "use_cache": {"type": "boolean"},
        # Knobs for rename_suggestions / cluster / reflect / fingerprint /
        # cfg_similar. Previously stripped, so these actions ran with fixed
        # defaults and their tuning/persistence flags were unreachable.
        "top_k": {"type": "integer"},
        "limit": {"type": "integer"},
        "threshold": {"type": "number"},
        "k": {"type": "integer"},
        "func_limit": {"type": "integer"},
        "include_evidence": {"type": "boolean"},
        "persist_blackboard": {"type": "boolean"},
        "persist_capsule": {"type": "boolean"},
        "items": {"type": "array", "items": {"type": "object"}},
        "db_path": {"type": "string"},
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
        "constraints": {"type": "object", "description": "Structured query constraints"},
        "offset": {"type": "integer", "description": "Skip first N results"},
        "order_by": {"type": "string", "description": "Column to order by (e.g., 'entropy DESC')"},
        "include_apis": {"type": "boolean", "description": "Include API list in results"},
        "include_strings": {"type": "boolean", "description": "Include string refs in results"},
        # blackboard_search reads `include_resolved`; evidence_card reads
        # `similar_top_k`. Previously stripped, so both flags were unreachable
        # through MCP. (`tool`/`payload` are intentionally NOT admitted: they
        # belong to the internal suggest_next_steps helper, not an action.)
        "include_resolved": {"type": "boolean"},
        "similar_top_k": {"type": "integer"},
    },
    "query": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["query"]},
        "subaction": {"type": "string"},
        "args": {"type": "object"},
    },
    "idb": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["idb"]},
        "offset": {"type": "integer"},
        "count": {"type": "integer"},
        # `state` reads `audit_tail` (number of recent audit records to show).
        # Previously stripped, so state always returned the default 5.
        "audit_tail": {"type": "integer"},
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
    },
    "ctree": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["ctree"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
    },
    "entropy": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["entropy"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "size": {"type": "integer"},
        "threshold": {"type": "number"},
        "end_addr": {"type": "string"},
        "window": {"type": "integer"},
        "step": {"type": "integer"},
        "limit": {"type": "integer"},
    },
    "gadgets": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["gadgets"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "query": {"type": "string"},
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
    "bulk": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bulk"]},
        "items": {"type": "array", "items": {"type": "object"}},
        "path": {"type": "string"},
        "continue_on_error": {"type": "boolean"},
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
    },
    "bridge_search": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bridge_search"]},
        "query_constraints": {"type": "object", "description": "SchemaBoot-style constraints for seed selection"},
        "func_ea": {"type": "string", "description": "Hex address of seed function (for action='bridges')"},
        "func_name": {"type": "string", "description": "Name of seed function (for action='bridges')"},
        "bridge_types": {"type": "array", "items": {"type": "string"}, "description": "Bridge types: ['apis'], ['strings'], or ['apis', 'strings']"},
        "top_k": {"type": "integer", "description": "Max candidates to return"},
        "hops": {"type": "integer", "description": "Number of hops (2=standard, >2=extended)"},
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
        "tag": {"type": "string", "description": "Filter by single tag"},
        "min_confidence": {"type": "number", "description": "Minimum confidence filter"},
        "limit": {"type": "integer", "description": "Max entries to return"},
        "top_k": {"type": "integer", "description": "Top-K results for semantic retrieval"},
        "threshold": {"type": "number", "description": "Similarity threshold for semantic retrieval"},
        "include_resolved": {"type": "boolean", "description": "Include resolved entries in semantic retrieval"},
        "include_contradicted": {"type": "boolean", "description": "Include contradicted entries in semantic retrieval"},
        "force": {"type": "boolean", "description": "Force semantic_rebuild to re-embed all matching entries"},
        "offset": {"type": "integer", "description": "Pagination offset"},
        "db_path": {"type": "string", "description": "Override path to blackboard SQLite DB"},
        # Knowledge-graph builder fields for add_system / add_struct / add_gap /
        # fill_gap / add_state_machine / add_peripheral / add_attack_surface /
        # kg_gaps. Previously stripped, so the KG-builder actions could only
        # set title/content/confidence/tags — the structuring fields (members,
        # gap_type, size_bytes, drivers, reachable_from, ...) were silently
        # dropped, making these actions non-functional through MCP.
        "members": {"type": "array", "items": {"type": "string"}},
        "entry_points": {"type": "array", "items": {"type": "string"}},
        "exit_points": {"type": "array", "items": {"type": "string"}},
        "size_bytes": {"type": "integer"},
        "hints": {"type": "array", "items": {"type": "string"}},
        "gap_type": {"type": "string"},
        "binary_type": {"type": "string"},
        "gap_id": {"type": "string"},
        "filled_by": {"type": "string"},
        "state_var": {"type": "string"},
        "states": {"type": "array", "items": {"type": "object"}},
        "periph_type": {"type": "string"},
        "drivers": {"type": "array", "items": {"type": "string"}},
        "reachable_from": {"type": "array", "items": {"type": "string"}},
        "input_type": {"type": "string"},
        "call_stack": {"type": "array", "items": {"type": "string"}},
        "resolved": {"type": "boolean"},
    },
    "filter": {
        "data": {"type": "object", "description": "Tool output dict to filter"},
        "query": {"type": "string", "description": "JQ-like filter expression (e.g. '.functions[?size > 100] | first(10)')"},
    },
    "fixups": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["fixups"]},
        "addr": {"type": "string", "description": "Hex address string (e.g. \"0x356f8\") or function name. Pass verbatim from search results — no mental math, no decimal conversion."},
        "target": {"type": "string", "description": "Target address (for add)"},
        "fixup_type": {"type": "integer", "description": "Fixup type id (processor specific)"},
        "start": {"type": "string", "description": "Start address for list range"},
        "end": {"type": "string", "description": "End address for list range"},
        "offset": {"type": "integer", "description": "Pagination offset"},
        "count": {"type": "integer", "description": "Max entries (0=all)"},
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
