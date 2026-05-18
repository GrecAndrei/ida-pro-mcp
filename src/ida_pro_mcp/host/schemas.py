#!/usr/bin/env python3
"""
Tool registry: TOOL_ACTIONS, TOOL_DESCRIPTIONS, TOOL_ARG_SCHEMAS,
schema builders, alias resolution.
"""
import os
import re
import json
import difflib
from typing import Any, Dict, List, Optional, Union

from .config import log_rpc
from .patterns import compile_smart_pattern, smart_match

TOOL_ALIASES = {
    "plugins": "misc",
    "xfer_analysis": "xref_analysis",
}
WRAPPER_ACTIONS = ("grep", "pick", "head", "tail", "next", "stats")
ACTION_PREFIX_RE = re.compile(r"^action[\s\"']*[:=][\s\"']*", re.IGNORECASE)
ACTION_STRIP_CHARS = "\"'"
_WRAPPER_PAIRS = (("[", "]"), ("(", ")"), ("{", "}"), ("<", ">"))

# =============================================================================
# TOOLS REGISTRY
# =============================================================================

TOOLS = [
    # Core session and batch tools (host-side)
    "session",
    "truncation",
    "bookmarks",
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
    "trace",
    "coverage",
    "trace_analysis",
    # Project and file management
    "project",
    # Advanced analysis
    "agent",
    "microcode",
    "graph",
    "ctree",
    "static_trace",
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
    "comment_mgr",
    "colorize",
    "data_ops",
    "firmware_view",
    "fixups",
    # Instrumentation
    "hooks",
    # Documentation and YARA
    "wiki",
    "yara_hunt",
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
    # Deep cross-reference analysis
    "xref_analysis",
    # String operations
    "string_ops",
    # CFG analysis
    "cfg_analysis",
    # Binary info
    "binary_info",
    # LLM helpers
    "llm_helpers",
    # Structured semantic indexing
    "schemaboot",
    # VOERA components
    "turboquant",
    "bridgerag",
    "memrl",
    "mbagcn",
    # --- New infrastructure tools ---
    "blackboard",
    "filter",
    # --- Governance ---
    "governance",
    # --- Cross-session firmware KB ---
    "knowledge",
    "firmware_bootstrap",
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
    "governance",
    "firmware_view",
    "blackboard",
    "knowledge",
]

# Keep tools/list compact for LLM context windows while preserving backward-compatible calls.
HIDDEN_TOOLS_IN_LIST = {t for t in TOOLS if t not in ADVERTISED_TOOLS}

_EXTRA_TOOL_ALIASES = {
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
    "coverage": "threat_hunt",
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
    "comments_ai": "comment_mgr",
    "annotations_ai": "annotation",
    "strings_xref": "xref_analysis",
    "emulate": "static_trace",
    "searches": "search",
    "segment": "segments",
    "session_tool": "session",
    "strings": "string_ops",
    "symbols_tool": "symbols",
    "trace_analyze": "trace_analysis",
    "xref": "xref_analysis",
    "xrefs": "xref_analysis",
    "govern": "governance",
    "cybercane": "governance",
    "rules": "governance",
    "policy": "governance",
}

def _snake_variants(value: str) -> set[str]:
    base = str(value or "").strip().lower()
    if not base:
        return set()
    out = {
        base,
        base.replace("-", "_"),
        base.replace(" ", "_"),
        base.replace("_", "-"),
        base.replace("_", ""),
        base.replace("_", "."),
        base.replace("_", "/"),
    }
    if base.endswith("s") and len(base) > 3:
        out.add(base[:-1])
    else:
        out.add(f"{base}s")
    out.add(f"{base}_tool")
    out.add(f"{base}_tools")
    out.add(f"tool_{base}")
    out.add(f"tools_{base}")
    return {x for x in out if x}

def _camel_variants(value: str) -> set[str]:
    words = [w for w in str(value or "").replace("-", "_").split("_") if w]
    if len(words) <= 1:
        return set()
    pascal = "".join(w.capitalize() for w in words)
    camel = words[0].lower() + "".join(w.capitalize() for w in words[1:])
    return {camel, pascal}

def _strip_balanced_wrappers(value: str, rounds: int = 3) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for _ in range(rounds):
        changed = False
        text = text.strip().strip(",;")
        stripped_quotes = text.strip(ACTION_STRIP_CHARS + "`")
        if stripped_quotes != text:
            text = stripped_quotes
            changed = True
        for left, right in _WRAPPER_PAIRS:
            if len(text) >= 2 and text.startswith(left) and text.endswith(right):
                text = text[1:-1].strip()
                changed = True
        if not changed:
            break
    return text

def _noisy_alias_variants(value: str) -> set[str]:
    base = str(value or "").strip().lower()
    if not base:
        return set()
    return {
        f"[{base}]",
        f"({base})",
        f"{{{base}}}",
        f"<{base}>",
        f'"{base}"',
        f"'{base}'",
        f"`{base}`",
        f"{base}()",
        f"{base}:",
        f"{base}=",
        f"tool:{base}",
        f"{base}.tool",
    }

def _normalize_alias_lookup_key(value: Any) -> str:
    stripped = _strip_balanced_wrappers(str(value or ""))
    without_prefix = ACTION_PREFIX_RE.sub("", stripped)
    return without_prefix.strip().strip(",;").lower()

def _resolve_tool_alias(name: Any) -> Any:
    if not isinstance(name, str):
        return name
    normalized = _normalize_alias_lookup_key(name)
    if not normalized:
        return name
    resolved = TOOL_ALIASES.get(normalized)
    if resolved:
        return resolved
    if normalized in TOOLS:
        return normalized
    # Fallback for callers that already pass clean aliases/canonical names.
    return TOOL_ALIASES.get(name, name)

def _build_tool_aliases(tools: list[str], explicit: dict[str, str]) -> dict[str, str]:
    candidates: Dict[str, set[str]] = {}
    for tool in tools:
        variants = _snake_variants(tool).union(_camel_variants(tool))
        for alias in list(variants):
            variants.update(_noisy_alias_variants(alias))
        for alias in variants:
            key = _normalize_alias_lookup_key(alias)
            if key:
                candidates.setdefault(key, set()).add(tool)
    for alias, target in (explicit or {}).items():
        key = _normalize_alias_lookup_key(alias)
        target_key = _normalize_alias_lookup_key(target)
        if key and target_key:
            candidates.setdefault(key, set()).add(target_key)
    resolved: dict[str, str] = {}
    for alias, targets in candidates.items():
        if len(targets) == 1:
            target = next(iter(targets))
            if alias != target:
                resolved[alias] = target
    return resolved

TOOL_ALIASES = _build_tool_aliases(TOOLS, {**TOOL_ALIASES, **_EXTRA_TOOL_ALIASES})

TOOL_DESCRIPTIONS = {
    "abi": "Analyzes calling conventions and ABI details of functions. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.",
    "agent": "High-level AI-assisted analysis combining search, context packing, and multi-hop discovery. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar, bridge_query, reflect, cluster, fingerprint.",
    "analysis": "Controls IDA analysis engine settings and triggers reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.",
    "annotation": "Automatically generates and manages comments, labels, and documentation across functions. Actions: auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate.",
    "batch": "Executes multiple tool calls in a single request to reduce round trips. Pass a calls array of tool invocations.",
    "binary_info": "Retrieves binary metadata including PE/ELF headers, sections, and build info. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.",
    "blackboard": "Firmware RE knowledge base: findings, hypotheses, IOCs, vulns, regions, and knowledge graph. write/read/list/search/update/delete/clear/prune/stats/merge: CRUD. frontier: ranked unvisited functions by embedding proximity + xref + entropy (read when choosing what to analyze next). coverage: analyzed vs unvisited per embedding cluster (read to understand progress). propagate_labels: spread LLM labels to embedding-similar neighbors via FrontierEngine. next_target: priority queue (confidence × time_decay × xref_boost). contradict/resolve/add_evidence/calibrate: evidence lifecycle. campaign_summary/auto_tag_propagate: batch operations. start_crawler/stop_crawler/crawler_status/accept/reject: background xref crawler. KG actions: kg_add_system/kg_add_struct/kg_add_gap/kg_add_state_machine/kg_add_attack_surface/kg_add_peripheral + read variants.",
    "bookmarks": "Manages named address bookmarks for quick navigation and milestone tracking. Actions: add, list, delete, update, clear, find, export.",
    "bridgerag": "Multi-hop bridge-conditioned search for discovering indirect relationships between entities. Actions: search, bridges.",
    "bulk": "Applies batch edits (renames, comments, types) to multiple addresses in one call. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.",
    "calc": "Safe address arithmetic and pointer resolution—use instead of mental math. Includes bitwise helper operations. Actions: eval, offset, convert, resolve, deref, chain, align, bitops.",
    "cfg_analysis": "Analyzes control flow graph structure including loops, dominators, and complexity. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.",
    "classify": "Classify functions and binaries by purpose. function: single function — embedding-driven BehaviorClassifier (bge-code-v1). binary: overall binary type. all_functions: classify all functions — unnamed functions use BehaviorClassifier. library_code/wrappers/callbacks/initializers/error_handlers: structural classification. hot_functions: most-called functions. orphans: no-caller functions (entry points / dead code). induce_schema: VOERA SchemaBoot attribute-value schema for structured retrieval.",
    "code": "Decompilation, disassembly, and code analysis. smart_decompile: best single call — pseudocode + behavior_tags + api_calls + crypto_hints + dangerous_patterns + var_rename_hints + callers + callees + strings + blackboard_context + suggested_next_actions. decompile: pseudocode with inline api_calls/crypto_hints/complexity. disasm: assembly listing. analyze: comprehensive (decompile+callers+callees+strings+stack). decompile_chain: function with compact caller/callee context (first 8 lines each). semantic_decompile: pseudocode + CFG semantics + variable dependency graph. diff_functions: unified diff of two functions. annotate: add comment to function/address. xrefs_to/from, callees, callers, blocks, callgraph, find_paths, strings_in_func, decomp_dataflow, export.",
    "colorize": "Sets and queries color highlighting on functions, ranges, and instructions. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.",
    "comment_mgr": "Structured comment management with context-aware get/set and markdown import/export. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.",
    "compare": "Diff two IDB databases or functions across binaries. Actions: functions, blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.",
    "coverage": "Import and analyze code coverage data to identify hit/missed paths. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter, function_coverage, gaps, compare, merge.",
    "crypto_id": "Detect cryptographic algorithms, constants, and encoding routines in the binary. Actions: identify, constants, encoding, checksums, entropy_analysis, aes_ni.",
    "ctree": "Query and traverse the Hex-Rays decompiler ctree AST for a function. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph.",
    "data": "Retrieve core IDB data. functions: list all functions — always includes xref count (capped 999). globals: global variables. strings: string literals — always includes xref count. imports: imported modules and functions. exports: exported entry points. lookup: resolve name↔address. bulk_query: multiple queries in one call. capability_matrix: binary capability matrix from imports + function classifications. string_xrefs: ranked string-to-function xref map with module clustering.",
    "data_ops": "Change data representation at addresses: define types, arrays, strings, pointers. Actions: make_data, make_array, make_string, undefine, make_code, cycle_data, set_repr, make_ptr, hex, dec, bin, char, offset.",
    "debug": "Control the debugger: run, step, breakpoints, registers, memory, threads. Actions: status, start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem, bp_context.",
    "deobfuscate": "Detect and decode obfuscation: stack strings, API hashing, dead code, anti-disasm. Actions: detect, detect_encoding, stack_strings, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt.",
    "entropy": "Compute entropy over regions to detect packing, encryption, or compressed data. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.",
    "export": "Export IDB content in various formats for external tooling. Actions: listing, html, idc, json, sarif, binexport, headers, redact.",
    "filter": "Apply structured predicate filters to tool result sets for focused output. Actions: filter.",
    "firmware_view": "Firmware triage: region scanning, pointer sweeps, table carving, deterministic detection logic, multi-region campaigns, and bootstrap orchestration. Actions: scan_region, auto_retype, pointer_sweep, recommend, table_candidates, smart_carve, rollback_last, review_contradictions, region_profile, pointer_clusters, carve_plan, campaign, segment_sweep, multi_region_campaign, campaign_checkpoint, campaign_resume, campaign_feedback, fingerprint_index_sync, fingerprint_index_query, detect_load_address, detect_vector_table, detect_mmio, rtos_scan, triage_snapshot, bootstrap.",
    "firmware_bootstrap": "Chip-aware post-load bootstrap pipeline for firmware binaries. Defines vector-table functions (Reset_Handler and IRQ handlers), annotates known MMIO peripherals, runs auto-analysis, and returns a bootstrap report.",
    "fixups": "Manage relocation fixup entries in the IDB. Actions: list, get, add, delete.",
    "funcs": "Function boundary management with regex/glob/substring filtering. Actions: create, delete, set_flags, set_name/rename, add_comment, list, info, metrics, find_similar, suggest_names.",
    "gadgets": "Find ROP/JOP/COP gadgets, stack pivots, and classify exploit chains. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, classify_chain.",
    "governance": "Pre-flight validation for edits: detect contradictions, PII, dangerous patches. Actions: check, redact, list_rules, stats.",
    "knowledge": "Cross-session firmware knowledge base: chip family identification, persistent symbol memory, and symbol transfer across binaries. Actions: chip_identify, symbol_lookup, import_symbols, export_session, chip_families.",
    "graph": "Generate call graphs, CFGs, and xref graphs in JSON/DOT/Mermaid formats. Actions: callgraph, cfg, dominators, xref_graph, down, up, both, json, dot, mermaid.",
    "history": "Undo/redo IDB changes, create snapshots, restore, and diff states. Actions: undo, redo, list, snapshot, restore, diff.",
    "hooks": "Generate dynamic instrumentation hooks (Frida, Detours) for target functions. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.",
    "idb": "Query top-level IDB metadata: binary info, segments, entrypoints, bookmarks, and architecture profile guidance for raw binaries. Actions: meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile.",
    "imports_deep": "Deep import analysis: thunks, delay-loads, forwarded, ordinal, and API set resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.",
    "llm_helpers": "Context-optimized helpers for LLM agents. START HERE: bootstrap gives a concrete first-turn playbook; cheatsheet returns full tool reference with concrete examples. context_window/function_digest/binary_digest/explain_address: compact analysis helpers. suggest_next/progress_report/focus_area: navigation and planning. behavioral_signature_search: find functions by behavior tag using BehaviorClassifier. function_role_classifier: entry_point/callback/dispatcher/wrapper via structural+embedding signals. dangerous_pattern_explainer: why a pattern is dangerous + exploitation path + mitigation. api_contract_extractor: infer preconditions/postconditions from call sites. global_state_influence_mapper: which globals a function reads/writes. interprocedural_data_lineage_graph: trace data flow across function boundaries. semantic_diff_explainer: embedding+BehaviorClassifier diff between two functions. decompile_disasm_consistency_search: find decompiler/disasm disagreements. argument_semantics_search: find functions by argument role. path_constrained_search: BFS from addr filtered by behavior tag. cross_artifact_correlation_search: correlate strings/names/blackboard by query.",
    "lumina": "Interface to IDA Lumina server for collaborative function metadata sharing. Actions: pull, push, status, history, search, get_metadata.",
    "mbagcn": "Mamba-based GCN encoder for CFG similarity search across functions. Actions: encode, similar, stats.",
    "memory": "Read, write, and inspect raw memory/bytes in the binary or debuggee. Actions: read, write, hexdump, search, compare, pointers, find_pointers, entropy, strings, struct_walk, histogram.",
    "memrl": "Q-value reinforcement learning for skill ranking, strategy suggestion, and usage feedback tracking. Actions: record, update, rank, stats, top, get_q, suggest, feedback.",
    "microcode": "Access Hex-Rays microcode IR for a function at various maturity levels. Actions: get, blocks, instructions, def_use_graph.",
    "misc": "Utility grab-bag: run scripts, manage plugins, read/write files, check health. Actions: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health.",
    "modify": "Apply edits to the IDB: rename symbols, add comments (regular/repeatable/anterior/posterior), set types, and patch assembly (multi-line instructions separated by semicolons). Actions: rename, comment, set_type, patch_asm.",
    "nav": "Navigate the IDA cursor to addresses or semantically interesting locations. Actions: goto, cursor, interesting, semantic_goto.",
    "patterns": "Generate, match, and manage FLIRT/byte pattern signatures for function identification. Actions: generate, match, list_sigs, apply_sig, create_sig, matched, yara_from_func, flirt_generate, match_yara.",
    "predictor": "Deterministic prediction of next useful tool, focus address, or stuck-state detection. recommend_bundle returns a bundled next-step pack (tools + focus + addresses + stall risk). Actions: suggest_next_tool, detect_stuck, suggest_focus, suggest_next_address, risk_of_stall, recommend_bundle.",
    "project": "Project I/O and file operations. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists.",
    "protocol": "Detect and analyze network protocol structures, parsers, endpoints, and state machines in a binary. Actions: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine.",
    "query": "Unified query interface combining data, search, code, types, symbols, and natural-language queries. Actions: data, search, idb, code, types, imports_deep, symbols, patterns, nl.",
    "schemaboot": "Structured semantic indexing with induced attribute-value schemas for function-level retrieval. Actions: ingest, query, refresh, stats, delete, get.",
    "search": "Pattern, reference, and semantic search across the binary. nl: natural language search using bge-code-v1 embeddings (most accurate for RE queries). behavior: find all functions matching a behavior tag (crypto_symmetric, network_http, etc.) via BehaviorClassifier. find: smart unified search (names/strings/imports/instructions, auto-ranked). semantic: NL search with embedding-aware ranking. smart_bundle: fused find+semantic with deduplicated structured items. api: find all usages of an imported API. decompiled: search pseudocode across all functions (auto-writes blackboard entries for matches). structured: schema-based pre-filtered search with behavior_tags constraints. vulnerable: scan for dangerous API patterns. constants: find crypto/magic constants. callers/callees, bytes/string/immediate/name/insns/mnemonic/instruction/text/operand/comment/data_ref/code_ref/regex/func_by_sig/type/export/summary/query_lang.",
    "segments": "List, create, modify, and analyze binary segments and their permissions/attributes. Actions: list, add, delete, set_attr, set_perms, move, info, analyze, find_code, find_data, compare, merge.",
    "session": "Full session lifecycle with runtime tracking, analysis notebook, hypothesis tracking, and skill crystallization. Actions: create/switch/close/list/status, snapshot/restore, crystallize_skill/rate_skill/suggest_strategy, notebook_append/read, track_hypothesis/confirm/refute, get_phase/advance_phase, recent_workset, macro_set/run, dashboard. cleanup_stale: remove sessions older than max_age_days (default 30) — run this when sessions accumulate.",
    "stack_analysis": "Analyze stack frames: buffer sizes, canaries, alignment, spills, variables, and uninitialized regions. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.",
    "static_trace": "Statically trace data/control flow, evaluate expressions, and decrypt obfuscated strings. Actions: static_trace, decrypt_strings, eval_expr.",
    "string_ops": "Advanced string analysis and IOC extraction. score_c2/indicators: C2 risk report — BehaviorClassifier on strings + API triads + family guess. ioc_extract: extract all IOCs (URLs, IPs, registry keys, C2 endpoints). persistence/evasion: persistence mechanisms and evasion techniques. find_urls/find_ips/find_paths/find_registry/find_emails/find_commands: pattern extraction. find_c2/find_configs/find_api_keys/find_databases/find_crypto_addrs: semantic extraction. find_stack_strings/find_base64: obfuscated string recovery. entropy_rank: rank strings by Shannon entropy. suspicious/encoding_stats/multilingual/decode_all: analysis utilities.",
    "summarize": "Structured summaries of binary components. binary: overall binary summary. function: single function summary. segment: segment summary. imports_by_category: imports grouped by API category. strings_by_category: strings grouped by type. complexity: function complexity metrics. call_hierarchy: call tree from entry point. data_flow: data flow summary. security_posture: dangerous APIs + mitigations + risk level. statistics: binary-wide stats. report: FULL REPORT — binary + security_posture + live taint scan + blackboard findings + statistics.",
    "symbols": "Loads and manages debug symbols (PDB/DWARF) for the current binary. Actions: load_pdb, load_dwarf, status, apply, export.",
    "taint": "Data flow taint analysis from user-controlled sources to dangerous sinks. Actions: sources (list all taint sources: recv/read/fgets/getenv imports + blackboard IOCs), sinks (dangerous sinks reachable from a source), trace (trace forward from addr/source, write vuln entries to blackboard), paths (full call-graph paths source→sink with dataflow description), report (all sources → all reachable sinks). Example: taint(action='trace', source='recv') finds all paths from recv to memcpy/strcpy/system.",
    "threat_hunt": "Runs automated threat-hunting passes to detect malware patterns, vulnerabilities, and suspicious behaviors. Actions: run, malware, vuln, tracing, findings, quick, deep, legacy.",
    "trace": "Manages execution trace data for the current debug session. Actions: get, clear, set_options.",
    "trace_analysis": "Analyzes imported execution traces for coverage, loops, API sequences, and anti-analysis detection. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, execution_timeline_graph, cross_run_diff, coverage_debug_plan, anti_analysis_detect, trace_entropy, api_sequence, loop_analysis.",
    "truncation": "Continues a previously truncated tool response to retrieve remaining output. Actions: continue.",
    "turboquant": "4-bit quantized embedding store for fast semantic similarity queries over binary artifacts. Actions: ingest, query, stats, delete.",
    "types": "Manages IDA type system: structs, enums, prototypes, type propagation, and header imports. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header, diff, visualize, propagate, enum_values, type_graph.",
    "wiki": "Accesses built-in documentation and tool usage guides within MCP context. Actions: list_topics, read, search, semantic_search, index, sections, suggest.",
    "workflow": "Executes predefined multi-step analysis workflows for common RE tasks. audit_plan validates and scores a plan before execution. execute_plan runs a planned call list (or generated plan) through batch execution with execution metadata. prioritize reorders a dry-run plan by strategy (original/coverage/risk_first). compose merges multiple workflow plans into one deduplicated dry-run execution plan. estimate returns dry-run complexity/risk/category projections. explain returns a dry-run plan plus per-step rationale. plan previews another workflow action without executing it. catalog returns available workflows and required inputs. triage_fast auto-checks idb overview and, for firmware-like binaries, injects firmware_view(action='triage_snapshot') plus guided analysis. recon_sweep runs broader orientation + structured retrieval + protocol + security posture in one pass. Supports dry_run plan preview and include/exclude tool filtering for controlled orchestration. Actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review.",
    "xref_analysis": "Performs cross-reference graph analysis: call chains, dominators, hubs, dead code, and dependency graphs. Actions: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions, forward, backward, both.",
    "yara_hunt": "Scans the binary with YARA rules and provides match context and xref correlation. Actions: scan, compile, list_rules, match_context, extract_strings, xref_matches.",
}

TOOL_ACTIONS = {
    "abi": [
        "detect",
        "stack_args",
        "reg_args",
        "return_type",
        "varargs",
        "struct_return",
        "tail_calls",
        "prologue",
        "epilogue",
        "abi_violations",
    ],
    "agent": [
        "analyze_function",
        "explore_address",
        "find_references",
        "search_all",
        "search_structs",
        "context_pack",
        "quick",
        "rename_suggestions",
        "batch_context",
        "similar",
        "bridge_query",
        "reflect",
        "cluster",
        "fingerprint",
    ],
    "analysis": [
        "get_options",
        "set_options",
        "set_processor",
        "set_loader_options",
        "set_architecture",
        "reanalyze",
    ],
    "annotation": [
        "auto_comment",
        "auto_comment_function",
        "label_loops",
        "label_branches",
        "mark_dangerous",
        "annotate_constants",
        "tag_functions",
        "document_args",
        "mark_error_paths",
        "propagate_names",
        "cleanup",
        "validate",
    ],
    "batch": [
        "(pass calls array)",
    ],
    "binary_info": [
        "headers",
        "sections",
        "relocations",
        "resources",
        "debug_info",
        "compiler",
        "linker",
        "timestamps",
        "checksums",
        "overlay",
    ],
    "blackboard": [
        "write",
        "read",
        "list",
        "search",
        "update",
        "delete",
        "clear",
        "stats",
        "prune",
        "merge",
        "contradict",
        "resolve",
        "next_target",
        "frontier",
        "coverage",
        "propagate_labels",
        "start_crawler",
        "stop_crawler",
        "crawler_status",
        "accept",
        "reject",
        "add_evidence",
        "calibrate",
        "campaign_summary",
        "auto_tag_propagate",
        "accept_proposal",
        "reject_proposal",
        "add_system",
        "add_struct",
        "add_gap",
        "fill_gap",
        "add_state_machine",
        "add_peripheral",
        "add_attack_surface",
        "kg_summary",
        "kg_systems",
        "kg_gaps",
        "kg_structs",
        "kg_state_machines",
        "kg_attack_surface",
        "kg_peripherals",
        "export_symbols",
        "import_symbols",
    ],
    "bookmarks": [
        "add",
        "list",
        "delete",
        "update",
        "clear",
        "find",
        "export",
    ],
    "bridgerag": [
        "search",
        "bridges",
    ],
    "bulk": [
        "rename",
        "comment",
        "apply_type",
        "rename_stack",
        "import_annotations",
        "export_annotations",
    ],
    "calc": [
        "eval",
        "offset",
        "convert",
        "resolve",
        "deref",
        "chain",
        "align",
        "bitops",
    ],
    "cfg_analysis": [
        "complexity",
        "loops",
        "branches",
        "paths",
        "dominators",
        "post_dominators",
        "back_edges",
        "natural_loops",
        "irreducible",
        "flatten_detect",
    ],
    "classify": [
        "function",
        "binary",
        "all_functions",
        "library_code",
        "wrappers",
        "callbacks",
        "initializers",
        "error_handlers",
        "hot_functions",
        "orphans",
        "induce_schema",
    ],
    "code": [
        "decompile",
        "disasm",
        "xrefs_to",
        "xrefs_from",
        "xrefs_to_field",
        "callees",
        "callers",
        "blocks",
        "analyze",
        "callgraph",
        "export",
        "find_paths",
        "strings_in_func",
        "diff_functions",
        "semantic_decompile",
        "decomp_dataflow",
        "decompile_chain",
        "smart_decompile",
        "annotate",
        "explain",
        "json",
        "c_header",
        "prototypes",
        "csmini",
        "classic",
        "annotated",
    ],
    "colorize": [
        "set_func",
        "set_range",
        "set_insn",
        "get",
        "clear",
        "palette",
        "highlight_pattern",
    ],
    "comment_mgr": [
        "get_context",
        "set_structured",
        "bulk_set",
        "export_md",
        "import_md",
        "summary",
    ],
    "compare": [
        "functions",
        "blocks",
        "apis",
        "strings",
        "constants",
        "structure",
        "semantics",
        "batch_compare",
        "find_clones",
        "changelog",
    ],
    "coverage": [
        "import_drcov",
        "import_lighthouse",
        "highlight",
        "report",
        "uncovered",
        "filter",
        "function_coverage",
        "gaps",
        "compare",
        "merge",
    ],
    "crypto_id": [
        "identify",
        "constants",
        "encoding",
        "checksums",
        "entropy_analysis",
        "aes_ni",
    ],
    "ctree": [
        "get",
        "traverse",
        "find_calls",
        "find_vars",
        "find_strings",
        "find_conditions",
        "get_logic_flow",
        "dominance_map",
        "var_dependency_graph",
    ],
    "data": [
        "functions",
        "globals",
        "strings",
        "imports",
        "exports",
        "lookup",
        "bulk_query",
        "capability_matrix",
        "string_xrefs",
    ],
    "data_ops": [
        "make_data",
        "make_array",
        "make_string",
        "undefine",
        "make_code",
        "cycle_data",
        "set_repr",
        "make_ptr",
        "hex",
        "dec",
        "bin",
        "char",
        "offset",
    ],
    "debug": [
        "status",
        "start",
        "stop",
        "continue",
        "step_into",
        "step_over",
        "run_to",
        "run_until",
        "breakpoints",
        "add_bp",
        "del_bp",
        "enable_bp",
        "add_hw_bp",
        "add_watch",
        "regs",
        "set_reg",
        "reg_diff",
        "snapshot_regs",
        "threads",
        "modules",
        "callstack",
        "read_mem",
        "write_mem",
        "search_mem",
        "stack_dump",
        "mem_map",
        "bp_context",
        "read",
        "write",
        "rw",
        "execute",
    ],
    "deobfuscate": [
        "detect",
        "detect_encoding",
        "stack_strings",
        "dead_code",
        "api_hashing",
        "dynamic_dispatch",
        "anti_disasm",
        "decode_attempt",
    ],
    "entropy": [
        "section",
        "region",
        "packed_detect",
        "crypto_detect",
        "compare",
        "window",
        "summary",
    ],
    "export": [
        "listing",
        "html",
        "idc",
        "json",
        "sarif",
        "binexport",
        "headers",
        "redact",
    ],
    "filter": [
        "filter",
    ],
    "firmware_view": [
        "scan_region",
        "auto_retype",
        "pointer_sweep",
        "recommend",
        "table_candidates",
        "smart_carve",
        "rollback_last",
        "review_contradictions",
        "region_profile",
        "pointer_clusters",
        "carve_plan",
        "campaign",
        "segment_sweep",
        "multi_region_campaign",
        "campaign_checkpoint",
        "campaign_resume",
        "campaign_feedback",
        "fingerprint_index_sync",
        "fingerprint_index_query",
        "detect_load_address",
        "detect_vector_table",
        "detect_mmio",
        "rtos_scan",
        "triage_snapshot",
        "bootstrap",
    ],
    "firmware_bootstrap": [
        "(call with chip_family/load_base/memory_map/peripheral_addresses)",
    ],
    "fixups": [
        "list",
        "get",
        "add",
        "delete",
    ],
    "funcs": [
        "create",
        "delete",
        "set_flags",
        "set_name",
        "rename",
        "add_comment",
        "list",
        "info",
        "metrics",
        "find_similar",
        "suggest_names",
    ],
    "gadgets": [
        "rop",
        "jop",
        "cop",
        "syscall",
        "write_what_where",
        "stack_pivot",
        "shellcode_space",
        "mitigations",
        "seh_handlers",
        "pivot_chains",
        "classify_chain",
    ],
    "governance": [
        "check",
        "redact",
        "list_rules",
        "stats",
    ],
    "knowledge": [
        "chip_identify",
        "symbol_lookup",
        "import_symbols",
        "export_session",
        "chip_families",
    ],
    "graph": [
        "callgraph",
        "cfg",
        "dominators",
        "xref_graph",
        "down",
        "up",
        "both",
        "json",
        "dot",
        "mermaid",
    ],
    "history": [
        "undo",
        "redo",
        "list",
        "snapshot",
        "restore",
        "diff",
    ],
    "hooks": [
        "suggest",
        "generate_frida",
        "generate_detours",
        "find_targets",
        "inline_hooks",
    ],
    "idb": [
        "meta",
        "summary",
        "segments",
        "entrypoints",
        "bookmarks",
        "overview",
        "architecture_profile",
    ],
    "imports_deep": [
        "thunks",
        "delay",
        "forwarded",
        "ordinal",
        "api_sets",
        "resolve",
    ],
    "llm_helpers": [
        "bootstrap",
        "context_window",
        "function_digest",
        "binary_digest",
        "explain_address",
        "suggest_next",
        "progress_report",
        "focus_area",
        "question_answer",
        "guided_analysis",
        "cheatsheet",
        "compact",
        "enrich",
        "intent_tool_compiler",
        "adaptive_query_planner",
        "token_aware_context_optimizer",
        "cross_call_variable_resolver",
        "evidence_weighted_response_assembler",
        "uncertainty_propagation_engine",
        "multi_granularity_retrieval_layer",
        "semantic_chunking_for_decompiled_code",
        "question_type_router",
        "interactive_clarification_protocol",
        "behavioral_signature_search",
        "cross_artifact_correlation_search",
        "temporal_search_replay",
        "search_hypothesis_sandbox",
        "path_constrained_search",
        "argument_semantics_search",
        "decompile_disasm_consistency_search",
        "near_miss_search_ranking",
        "persistent_search_collections",
        "auto_expansion_search_chains",
        "function_role_classifier",
        "protocol_format_reconstruction_assistant",
        "global_state_influence_mapper",
        "api_contract_extractor",
        "interprocedural_data_lineage_graph",
        "semantic_diff_explainer",
        "dangerous_pattern_explainer",
        "binary_capability_matrix_builder",
        "execution_hypothesis_generator",
        "patch_impact_forecaster",
        "safe_idapython_orchestration_runtime",
        "script_template_marketplace_layer",
        "auto_script_synthesis_from_intent",
        "script_output_schema_enforcer",
        "long_running_job_manager",
        "cross_session_script_memory",
        "privilege_scope_guardrails_for_scripts",
        "script_to_tool_promotion_pipeline",
        "experiment_harness_for_script_variants",
        "idapython_provenance_recorder",
        "investigation_playbook_engine",
        "next_best_action_recommender",
        "analysis_dead_end_detector",
        "workset_intelligence_capsules",
        "contradiction_tracker",
        "review_queue_for_ai_edits",
        "case_narrative_composer",
        "cost_latency_optimizer",
        "trust_verification_layer",
        "learning_feedback_loop",
    ],
    "lumina": [
        "pull",
        "push",
        "status",
        "history",
        "search",
        "get_metadata",
    ],
    "mbagcn": [
        "encode",
        "similar",
        "stats",
    ],
    "memory": [
        "read",
        "write",
        "hexdump",
        "search",
        "compare",
        "pointers",
        "find_pointers",
        "entropy",
        "strings",
        "struct_walk",
        "histogram",
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
    "memrl": [
        "record",
        "update",
        "rank",
        "stats",
        "top",
        "get_q",
        "suggest",
        "feedback",
        "ingest",
        "list_suggestions",
        "get_suggestion",
    ],
    "microcode": [
        "get",
        "blocks",
        "instructions",
        "def_use_graph",
    ],
    "misc": [
        "python",
        "idc",
        "load_sig",
        "cache_stats",
        "read_file",
        "write_file",
        "plugin_list",
        "plugin_run",
        "health",
    ],
    "modify": [
        "rename",
        "comment",
        "set_type",
        "patch_asm",
    ],
    "nav": [
        "goto",
        "cursor",
        "interesting",
        "semantic_goto",
    ],
    "patterns": [
        "generate",
        "match",
        "list_sigs",
        "apply_sig",
        "create_sig",
        "matched",
        "yara_from_func",
        "flirt_generate",
        "match_yara",
    ],
    "predictor": [
        "suggest_next_tool",
        "detect_stuck",
        "suggest_focus",
        "suggest_next_address",
        "risk_of_stall",
        "recommend_bundle",
        "explain_decision",
        "feedback",
    ],
    "project": [
        "save",
        "close",
        "open",
        "load_binary",
        "list_recent",
        "get_cwd",
        "set_cwd",
        "list_dir",
        "exists",
        "evidence_graph",
        "knowledge_merge",
        "confidence_model",
        "replay_pipeline",
        "hypothesis_tracker",
        "temporal_reasoning",
        "semantic_artifact_diff",
        "ai_governance",
        "knowledge_debt",
        "casefile_export",
    ],
    "protocol": [
        "detect",
        "parsers",
        "serializers",
        "handlers",
        "endpoints",
        "tls_config",
        "socket_flow",
        "packet_struct",
        "magic_numbers",
        "state_machine",
    ],
    "query": [
        "data",
        "search",
        "idb",
        "code",
        "types",
        "imports_deep",
        "symbols",
        "patterns",
    ],
    "schemaboot": [
        "ingest",
        "query",
        "refresh",
        "stats",
        "delete",
        "get",
    ],
    "search": [
        "text",
        "bytes",
        "regex",
        "immediate",
        "code_pattern",
        "next",
        "all",
        "structured",
        "string",
        "name",
        "comment",
        "mnemonic",
        "operand",
        "insns",
        "instruction",
        "decompiled",
        "constants",
        "semantic",
        "smart_bundle",
        "func_by_sig",
        "vulnerable",
        "api",
        "callees",
        "callers",
        "code_ref",
        "data_ref",
        "export",
        "find",
        "nl",
        "behavior",
        "query_lang",
        "summary",
        "type",
    ],
    "segments": [
        "list",
        "add",
        "delete",
        "set_attr",
        "set_perms",
        "move",
        "info",
        "analyze",
        "find_code",
        "find_data",
        "compare",
        "merge",
    ],
    "session": [
        "discover",
        "create",
        "get",
        "list",
        "switch",
        "close",
        "status",
        "rebuild",
        "update",
        "rename",
        "duplicate",
        "export_session",
        "import_session",
        "archive",
        "unarchive",
        "tag",
        "untag",
        "find_by_tag",
        "add_note",
        "clear_notes",
        "cleanup_stale",
        "stats",
        "validate",
        "bulk_delete",
        "bulk_tag",
        "search_notes",
        "recent",
        "oldest",
        "snapshot",
        "restore_snapshot",
        "merge",
        "macro_set",
        "macro_get",
        "macro_list",
        "macro_delete",
        "macro_run",
        "recent_workset",
        "crystallize_skill",
        "rate_skill",
        "list_skills",
        "suggest_strategy",
        "log_activity",
        "get_activity_log",
        "notebook_append",
        "notebook_read",
        "notebook_section",
        "track_hypothesis",
        "confirm_hypothesis",
        "refute_hypothesis",
        "list_hypotheses",
        "get_phase",
        "advance_phase",
        "dashboard",
        "link",
        "cross_reference",
        "list_snapshots",
    ],
    "stack_analysis": [
        "frame",
        "buffers",
        "canary",
        "alignment",
        "spills",
        "usage",
        "variables",
        "arrays",
        "uninitialized",
        "summary",
    ],
    "static_trace": [
        "static_trace",
        "decrypt_strings",
        "eval_expr",
    ],
    "string_ops": [
        "decode_all",
        "find_urls",
        "find_paths",
        "find_registry",
        "find_ips",
        "find_emails",
        "find_commands",
        "encoding_stats",
        "multilingual",
        "suspicious",
        "find_xrefs",
        "find_stack_strings",
        "find_base64",
        "find_api_keys",
        "find_configs",
        "find_c2",
        "find_databases",
        "find_crypto_addrs",
        "entropy_rank",
        "score_c2",
        "indicators",
        "persistence",
        "evasion",
        "ioc_extract",
    ],
    "summarize": [
        "binary",
        "function",
        "segment",
        "imports_by_category",
        "strings_by_category",
        "complexity",
        "call_hierarchy",
        "data_flow",
        "security_posture",
        "statistics",
        "report",
    ],
    "symbols": [
        "load_pdb",
        "load_dwarf",
        "status",
        "apply",
        "export",
    ],
    "taint": [
        "sources",
        "sinks",
        "trace",
        "report",
        "paths",
    ],
    "threat_hunt": [
        "run",
        "malware",
        "vuln",
        "tracing",
        "findings",
        "quick",
        "deep",
        "legacy",
    ],
    "trace": [
        "get",
        "clear",
        "set_options",
    ],
    "trace_analysis": [
        "import_trace",
        "analyze_coverage",
        "find_loops",
        "extract_api_calls",
        "basic_blocks_hit",
        "execution_timeline_graph",
        "cross_run_diff",
        "coverage_debug_plan",
        "anti_analysis_detect",
        "trace_entropy",
        "api_sequence",
        "loop_analysis",
    ],
    "truncation": [
        "continue",
    ],
    "turboquant": [
        "ingest",
        "query",
        "stats",
        "delete",
    ],
    "types": [
        "list",
        "get",
        "set_prototype",
        "parse_decl",
        "declare",
        "apply",
        "search_structs",
        "infer",
        "read_struct",
        "import_header",
        "diff",
        "visualize",
        "propagate",
        "enum_values",
        "type_graph",
    ],
    "wiki": [
        "list_topics",
        "read",
        "search",
        "semantic_search",
        "index",
        "sections",
        "suggest",
    ],
    "workflow": [
        "audit_plan",
        "execute_plan",
        "prioritize",
        "compose",
        "estimate",
        "explain",
        "plan",
        "catalog",
        "triage_fast",
        "malware_deep",
        "vuln_audit",
        "recon_sweep",
        "patch_review",
    ],
    "xref_analysis": [
        "call_chain",
        "common_callers",
        "common_callees",
        "hub_functions",
        "leaf_functions",
        "recursive",
        "dominator",
        "influence",
        "dependency_graph",
        "dead_functions",
        "forward",
        "backward",
        "both",
    ],
    "yara_hunt": [
        "scan",
        "compile",
        "list_rules",
        "match_context",
        "extract_strings",
        "xref_matches",
    ],
}

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
        "addr": {"type": "string"},
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
        "addr": {"type": "string"},
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
    },
    "calc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["calc"]},
        "expr": {"type": "string"},
        "addr": {"type": "string"},
        "target": {"type": "string"},
        "value": {"type": ["string", "integer"]},
        "bit_op": {"type": "string"},
        "type": {"type": "string"},
        "size": {"type": "integer"},
        "offsets": {"type": ["array", "string"], "items": {"type": "string"}},
    },
    "memory": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["memory"]},
        "addr": {"type": "string"},
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
    },
    "misc": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["misc"]},
        "expr": {
            "type": "string",
            "description": "Python expression or IDC script to evaluate",
        },
        "code": {"type": "string", "description": "Multi-line Python code to execute"},
        "name": {"type": "string", "description": "Signature name for load_sig"},
        "arg": {"type": "integer", "description": "Plugin argument for plugin_run"},
        "path": {"type": "string", "description": "File path for read_file/write_file"},
        "content": {"type": "string", "description": "Content to write for write_file"},
        "encoding": {
            "type": "string",
            "description": "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data.",
        },
        "verbose": {
            "type": "boolean",
            "description": "Include per-runtime details for health action.",
        },
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
    },
    "search": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["search"]},
        "pattern": {"type": "string"},
        "query": {"type": "string"},
        "addr": {"type": "string"},
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
            "description": "Optional address focus for underlying scanners where supported.",
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
            "description": "Forwarded depth profile to vuln_scan.",
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
            "description": "Optional address focus for the workflow.",
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
    },
    "agent": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["agent"]},
        "addr": {"type": "string"},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
        "include_pseudocode": {"type": "boolean"},
        "max_items": {"type": "integer"},
        "use_cache": {"type": "boolean"},
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
    },
    "code": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["code"]},
        "addrs": {"type": ["array", "string"], "items": {"type": "string"}},
        "addr": {"type": "string"},
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
        "addr": {"type": "string"},
        "query": {"type": "string"},
        "depth": {"type": "integer"},
    },
    "mbagcn": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["mbagcn"]},
        "addr": {"type": "string"},
        "top_k": {"type": "integer"},
        "db_path": {"type": "string"},
    },
    "entropy": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["entropy"]},
        "addr": {"type": "string"},
        "size": {"type": "integer"},
        "threshold": {"type": "number"},
        "end_addr": {"type": "string"},
        "window": {"type": "integer"},
        "step": {"type": "integer"},
        "limit": {"type": "integer"},
    },
    "static_trace": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["static_trace"]},
        "addr": {"type": "string"},
        "max_steps": {"type": "integer"},
        "follow_calls": {"type": "boolean"},
        "max_depth": {"type": "integer"},
        "include_blocks": {"type": "boolean"},
        "expr": {"type": "string"},
    },
    "gadgets": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["gadgets"]},
        "addr": {"type": "string"},
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
    "schemaboot": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["schemaboot"]},
        "constraints": {"type": "object", "description": "Structured query constraints"},
        "addr": {"type": "string", "description": "Function address for get/refresh"},
        "limit": {"type": "integer", "description": "Max results"},
        "offset": {"type": "integer", "description": "Skip first N results"},
        "order_by": {"type": "string", "description": "Column to order by (e.g., 'entropy DESC')"},
        "include_apis": {"type": "boolean", "description": "Include API list in results"},
        "include_strings": {"type": "boolean", "description": "Include string refs in results"},
    },
    "turboquant": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["turboquant"]},
        "query_key": {"type": "string", "description": "Function address or name to query"},
        "top_k": {"type": "integer", "description": "Number of similar functions to return"},
        "db_path": {"type": "string", "description": "Override path to TurboQuant bank file"},
    },
    "bridgerag": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["bridgerag"]},
        "query_constraints": {"type": "object", "description": "SchemaBoot-style constraints for seed selection"},
        "func_ea": {"type": "string", "description": "Hex address of seed function (for action='bridges')"},
        "func_name": {"type": "string", "description": "Name of seed function (for action='bridges')"},
        "bridge_types": {"type": "array", "items": {"type": "string"}, "description": "Bridge types: ['apis'], ['strings'], or ['apis', 'strings']"},
        "top_k": {"type": "integer", "description": "Max candidates to return"},
        "hops": {"type": "integer", "description": "Number of hops (2=standard, >2=extended)"},
    },
    "memrl": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["memrl"]},
        "intent_key": {"type": "string", "description": "Identifier for the query/analyst intent"},
        "experience_key": {"type": "string", "description": "Identifier for the retrieved candidate"},
        "reward": {"type": "number", "description": "Environmental feedback (+1 accept, +0.5 partial, 0 skip, -0.5 reject, -1 dangerous)"},
        "alpha": {"type": "number", "description": "Learning rate for TD updates (default 0.15)"},
        "candidate_pool": {"type": "array", "items": {"type": "object"}, "description": "Candidates from Phase A for Phase B re-ranking"},
        "top_k": {"type": "integer", "description": "Number of results to return"},
        "lambda_explore": {"type": "number", "description": "Weight for Q-value vs similarity (0=pure similarity, 1=pure Q)"},
        "similarity_key": {"type": "string", "description": "Dict key to read similarity score from candidate_pool items"},
        "suggestion_id": {"type": "string", "description": "Suggestion ID for feedback/get_suggestion actions"},
        "source_tool": {"type": "string", "description": "Tool that created the suggestion (modify, annotation, etc.)"},
        "source_action": {"type": "string", "description": "Action that created the suggestion (rename, comment, etc.)"},
        "context_addr": {"type": "string", "description": "Address context for the suggestion"},
        "initial_q": {"type": "number", "description": "Initial Q-value for ingest (default 0.5)"},
        "experience_meta": {"type": "object", "description": "Metadata dict for the experience"},
        "epsilon": {"type": "number", "description": "Epsilon-greedy exploration probability (default 0.0)"},
        "query_embedding": {"type": "array", "items": {"type": "number"}, "description": "Query embedding for semantic search"},
        "feedback_type": {"type": "string", "description": "Feedback type: accept, reject, partial, undo, skip"},
        "limit": {"type": "integer", "description": "Max items to return for list_suggestions"},
        "offset": {"type": "integer", "description": "Pagination offset for list_suggestions"},
        "db_path": {"type": "string", "description": "Override path to MemRL SQLite DB"},
    },
    "blackboard": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["blackboard"]},
        "entry_id": {"type": "string", "description": "Entry ID for read/update/delete"},
        "title": {"type": "string", "description": "Title for write/update"},
        "content": {"type": "string", "description": "Content/body text"},
        "category": {"type": "string", "description": "Category (default: general)"},
        "addr": {"type": "string", "description": "Associated address"},
        "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"},
        "confidence": {"type": "number", "description": "Confidence score 0-1"},
        "tag": {"type": "string", "description": "Filter by single tag"},
        "min_confidence": {"type": "number", "description": "Minimum confidence filter"},
        "limit": {"type": "integer", "description": "Max entries to return"},
        "offset": {"type": "integer", "description": "Pagination offset"},
        "db_path": {"type": "string", "description": "Override path to blackboard SQLite DB"},
    },
    "filter": {
        "data": {"type": "object", "description": "Tool output dict to filter"},
        "query": {"type": "string", "description": "JQ-like filter expression (e.g. '.functions[?size > 100] | first(10)')"},
    },
    "governance": {
        "action": {"type": "string", "enum": TOOL_ACTIONS["governance"]},
        "operation_type": {"type": "string", "description": "Operation type for check: patch, comment, rename, type_change, execution, annotation"},
        "addr": {"type": "string", "description": "Target address for the operation"},
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
    "firmware_bootstrap": {
        "chip_family": {"type": "string"},
        "load_base": {"type": ["integer", "string"]},
        "memory_map": {"type": "array", "items": {"type": "object"}},
        "peripheral_addresses": {"type": "array", "items": {"type": "object"}},
        "post_load_actions": {"type": "array", "items": {"type": "string"}},
    },
}

_ACTION_ALIAS_HINTS = {
    "add": {"append", "insert", "create"},
    "analyze": {"analyse", "inspect"},
    "bookmarks": {"marks"},
    "callers": {"incoming_calls", "who_calls"},
    "callees": {"outgoing_calls", "calls"},
    "comment": {"set_comment", "annotate"},
    "create": {"new", "make"},
    "decompile": {"pseudo", "pseudocode"},
    "decompile_func": {"decompile", "pseudo"},
    "delete": {"remove", "rm", "del"},
    "disasm": {"asm", "assembly", "disassemble", "listing"},
    "entrypoints": {"entries"},
    "export": {"dump"},
    "find": {"search", "query", "lookup"},
    "functions": {"funcs", "function_list"},
    "get": {"show", "view", "read", "info"},
    "health": {"diagnostics", "diag"},
    "imports": {"imports_list"},
    "info": {"details", "describe"},
    "list": {"ls", "enumerate", "all"},
    "lookup": {"resolve", "find_addr", "find_address"},
    "meta": {"metadata"},
    "name": {"symbol"},
    "plugin_list": {"plugins", "list_plugins"},
    "plugin_run": {"run_plugin", "exec_plugin"},
    "read": {"load"},
    "recent": {"latest"},
    "regex": {"regexp"},
    "rename": {"set_name"},
    "run": {"execute", "exec"},
    "scan_all": {"scan", "full_scan"},
    "search": {"find", "query", "lookup"},
    "set_attr": {"set_attribute"},
    "set_flags": {"flags"},
    "set_name": {"rename"},
    "set_options": {"configure"},
    "set_perms": {"permissions", "set_permissions"},
    "status": {"state"},
    "strings": {"strs"},
    "summary": {"overview"},
    "switch": {"use"},
    "write": {"save"},
    "xrefs_from": {"refs_from", "xrefs_out"},
    "xrefs_to": {"refs_to", "xrefs_in"},
}

_COMMON_ARG_ALIAS_HINTS = {
    "action": {"cmd", "command", "op", "operation", "tool_action"},
    "addr": {"address", "ea", "va", "offset"},
    "addrs": {"addr", "address", "addresses", "ea", "eas", "vas"},
    "args": {"arguments", "params", "parameters"},
    "binary_path": {"binary", "file", "path", "target"},
    "calls": {"steps", "requests"},
    "count": {"limit", "max", "max_items", "n"},
    "data": {"payload", "value"},
    "end": {"end_addr", "stop", "to"},
    "idb": {"database"},
    "idb_path": {"idb", "database", "database_path"},
    "limit": {"count", "max", "max_items", "n"},
    "max_items": {"limit", "count", "max", "n"},
    "name": {"func_name", "symbol", "label"},
    "notes": {"description"},
    "offset": {"skip"},
    "pattern": {"query", "needle", "match"},
    "query": {"q", "search", "pattern"},
    "session_id": {"sid", "session"},
    "source_action": {"on", "target_action", "subaction", "source"},
    "start": {"from", "start_addr"},
    "target": {"to"},
    "topic": {"doc", "page"},
}

_TOOL_SPECIFIC_ARG_ALIASES = {
    "code": {
        "addrs": {"addr", "address", "addresses", "ea", "eas"},
        "max_items": {"count", "max"},
    },
    "query": {
        "subaction": {"sub_action", "sub-action", "sub", "action_name"},
    },
    "compare": {
        "addr": {"addr_a", "address_a", "a", "lhs"},
        "addr2": {"addr_b", "address_b", "b", "rhs"},
    },
    "data": {
        "query": {"name", "symbol", "lookup"},
    },
    "search": {
        "pattern": {"query", "needle"},
    },
}

# Broad malformed/variant aliases accepted for high-noise LLM tool calls.
_TOOL_ACTION_EXTRA_ALIASES = {
    "threat_hunt": {
        "run": {
            "default",
            "all",
            "full",
            "hunt",
            "triage",
            "investigate",
            "orchestrate",
            "pipeline",
            "execute_all",
            "end_to_end",
            "go",
        },
        "legacy": {
            "compat",
            "compatibility",
            "legacy_route",
            "legacy_mode",
            "bridge",
            "fallback",
            "inherit",
        },
        "vuln": {
            "vulnerability",
            "vulnerabilities",
            "security",
            "security_scan",
            "vulnscan",
            "cve",
        },
        "malware": {
            "mal",
            "mal_scan",
            "malware_scan",
            "malware_hunt",
            "ioc",
            "iocs",
            "threats",
        },
        "tracing": {
            "trace",
            "trace_analysis",
            "runtime",
            "coverage",
            "flow",
            "behavior",
        },
        "findings": {
            "finds",
            "results",
            "report",
            "summary",
            "alerts",
        },
        "quick": {"fast", "lite", "quick_scan", "quickly"},
        "deep": {"thorough", "intensive", "deep_scan", "full_depth"},
    },
    "predictor": {
        "suggest_next_tool": {"next_tool", "recommend_tool", "tool_suggest", "predict_next"},
        "detect_stuck": {"stuck", "dead_end", "loop_detect", "stalled"},
        "suggest_focus": {"next_focus", "focus", "suggest_address", "interesting"},
    },
    "agent": {
        "context_pack": {"context", "pack", "summarize_context", "analysis_context"},
        "explore_address": {"explore", "inspect_address", "addr_overview"},
        "find_references": {"references", "xrefs", "find_xrefs"},
        "search_all": {"search", "global_search", "multi_search"},
    },
    "llm_helpers": {
        "bootstrap": {
            "start",
            "start_here",
            "onboard",
            "onboarding",
            "quickstart",
            "first_steps",
            "where_to_start",
            "guide",
            "playbook",
            "help",
        },
        "enrich": {"augment", "post_process", "enhance_output"},
        "compact": {"compress", "minify", "shrink"},
        "function_digest": {"func_digest", "summarize_function", "function_summary"},
        "binary_digest": {"bin_digest", "summarize_binary", "binary_summary"},
    },
    "trace_analysis": {
        "analyze_coverage": {"coverage", "coverage_report", "analyze_trace"},
        "extract_api_calls": {"api_calls", "apis", "extract_apis"},
    },
    "comment_mgr": {
        "get_context": {"context", "comments_context", "comment_context"},
        "set_structured": {"set_comment", "annotate", "comment"},
        "bulk_set": {"bulk_comment", "set_many", "annotate_many"},
    },
    "annotation": {
        "auto_comment": {"comment", "annotate", "auto_annotate"},
        "cleanup": {"clean", "sanitize", "normalize"},
    },
    "search": {
        "bytes": {"byte", "opcode_bytes", "hex_bytes"},
        "string": {"strings", "str", "text_string"},
        "immediate": {"imm", "immediates", "literal", "number"},
        "name": {"symbol", "symbol_name", "func_name", "named"},
        "insns": {"insn", "instruction_seq", "instruction_sequence", "asm_seq"},
        "mnemonic": {"mnemonics", "mnem", "opcode", "opcodes"},
        "instruction": {"instruction", "instructions", "instructions_text", "insn_text", "instruction_text", "asm_text", "semantic_instruction"},
        "text": {"full_text", "plaintext"},
        "operand": {"operands", "opnd", "arg_text"},
        "comment": {"comments", "cmt", "annotation", "notes"},
        "data_ref": {"data_refs", "dref", "drefs"},
        "code_ref": {"code_refs", "cref", "crefs", "xref"},
        "regex": {"regexp", "re", "pattern_regex"},
        "func_by_sig": {"signature", "sig", "func_signature", "signature_search"},
        "find": {"search", "lookup", "query", "locate", "discover"},
        "semantic": {"semantic_find", "nl", "natural_language", "intent_search"},
        "callers": {"incoming", "inbound_calls", "who_calls"},
        "callees": {"outgoing", "outbound_calls", "calls_from"},
        "api": {"apis", "import_api", "api_calls"},
        "vulnerable": {"vuln", "vulnerabilities", "risky"},
        "constants": {"const", "literals", "magic"},
        "decompiled": {"decompile", "pseudo", "pseudocode", "hl"},
    },
    "session": {
        "discover": {"scan", "discover_sessions", "find_sessions"},
        "create": {"new", "open", "start", "init", "spawn"},
        "get": {"show", "read", "info", "details"},
        "list": {"ls", "all", "enumerate"},
        "switch": {"use", "activate", "focus"},
        "close": {"delete", "remove", "terminate", "stop"},
        "status": {"state", "current", "active"},
        "rebuild": {"refresh", "recreate", "reanalyze"},
        "update": {"set"},
        "rename": {"set_name", "retitle"},
        "duplicate": {"clone", "copy"},
        "export_session": {"export", "dump"},
        "import_session": {"import", "load"},
        "archive": {"stash"},
        "unarchive": {"unstash"},
        "tag": {"add_tag", "label"},
        "untag": {"remove_tag", "del_tag"},
        "find_by_tag": {"search_tag", "tag_search"},
        "add_note": {"note", "append_note"},
        "clear_notes": {"wipe_notes", "reset_notes"},
        "cleanup_stale": {"cleanup", "gc", "prune"},
        "stats": {"statistics", "metrics"},
        "validate": {"check", "verify"},
        "bulk_delete": {"delete_many", "mass_delete"},
        "bulk_tag": {"tag_many", "mass_tag"},
        "search_notes": {"find_notes", "notes_search"},
        "recent": {"latest", "newest"},
        "oldest": {"old"},
        "snapshot": {"savepoint", "checkpoint"},
        "restore_snapshot": {"rollback", "restore"},
        "merge": {"combine", "join"},
        "macro_set": {"save_macro", "macro_save"},
        "macro_get": {"load_macro", "macro_read"},
        "macro_list": {"list_macros", "macros"},
        "macro_delete": {"remove_macro", "delete_macro"},
        "macro_run": {"run_macro", "execute_macro"},
        "recent_workset": {"workset", "active_workset"},
    },
    "code": {
        "decompile": {"decompiled", "pseudo", "pseudocode", "hl"},
        "semantic_decompile": {"deep_decompile", "semantic_ir", "decomp_semantics", "rich_decompile"},
        "decomp_dataflow": {"decompiler_dataflow", "decomp_slice", "var_flow"},
        "disasm": {"disassemble", "asm", "assembly", "listing"},
        "xrefs_to": {"xref_to", "refs_to", "incoming_refs"},
        "xrefs_from": {"xref_from", "refs_from", "outgoing_refs"},
        "xrefs_to_field": {"field_xrefs", "xrefs_field"},
        "callees": {"calls", "called_functions", "outgoing_calls"},
        "callers": {"who_calls", "incoming_calls"},
        "blocks": {"basic_blocks", "bb"},
        "analyze": {"analysis", "inspect"},
        "callgraph": {"cg", "graph_calls"},
        "export": {"dump", "save"},
        "find_paths": {"paths", "path_search", "reachability"},
        "strings_in_func": {"func_strings", "strings"},
    },
    "ctree": {
        "dominance_map": {"dom_map", "condition_dominance", "control_dominance"},
        "var_dependency_graph": {"var_graph", "dependency_graph", "ssa_like_graph"},
    },
    "microcode": {
        "def_use_graph": {"du_graph", "defuse", "ir_dataflow"},
    },
    "governance": {
        "check": {"evaluate", "inspect", "validate", "review"},
        "redact": {"sanitize", "scrub", "cleanse", "strip_pii"},
        "list_rules": {"rules", "show_rules", "get_rules"},
        "stats": {"statistics", "metrics", "counters"},
    },
}

_TOOL_ARG_EXTRA_ALIASES = {
    "threat_hunt": {
        "legacy_tool": {"source_tool", "tool_name", "legacyTool", "tool"},
        "legacy_action": {"source_action", "action_name", "legacyAction", "on"},
        "profile": {"mode", "depth", "scan_mode"},
        "query": {"q", "needle", "search"},
        "addr": {"address", "ea", "va"},
        "include_tracing": {"tracing", "with_tracing", "trace"},
        "include_malware": {"malware", "with_malware"},
        "include_vuln": {"vuln", "with_vuln", "security"},
        "include_evidence": {"evidence", "with_evidence", "proof"},
        "limit": {"max", "max_items", "count", "n"},
        "max_steps": {"steps", "max_calls", "pipeline_steps"},
        "scan_profile": {"vuln_profile", "scanner_profile"},
        "severity": {"risk", "level"},
        "legacy_passthrough": {"passthrough", "exact_legacy", "strict_legacy"},
    },
    "search": {
        "pattern": {"needle", "text", "query_text"},
        "query": {"q", "search", "find"},
        "addr": {"address", "ea"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "start": {"from", "start_addr"},
        "end": {"to", "end_addr"},
        "case_sensitive": {"case", "match_case"},
        "include_context": {"context", "with_context"},
        "include_items": {"items", "with_items"},
        "include_breakdown": {"breakdown", "stats"},
        "timeout_ms": {"timeout", "timeout_millis"},
        "max_functions": {"max_funcs", "function_cap"},
        "sample": {"sample_mode", "sampling"},
        "sample_max_funcs": {"sample_limit", "sample_cap"},
    },
    "session": {
        "binary_path": {"binary", "path", "target", "input"},
        "session_id": {"sid", "session", "id"},
        "force_new": {"new", "create_new", "fresh"},
        "analysis_options": {"analysis", "options"},
        "ida_args": {"idat_args", "args"},
        "tags": {"labels", "tag_list"},
        "notes": {"description"},
        "query": {"q", "search"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "name": {"title", "session_name"},
        "data": {"payload"},
        "session_ids": {"sids", "sessions"},
        "tag": {"label"},
        "snapshot_id": {"snapshot", "snap_id"},
        "source_id": {"from_sid", "source"},
        "target_id": {"to_sid", "target"},
        "run_action": {"macro_action", "action_to_run"},
    },
    "code": {
        "addrs": {"addr", "address", "ea", "vas", "targets"},
        "addr": {"address", "ea", "va"},
        "max_items": {"max", "count", "n"},
        "max_depth": {"depth", "levels"},
        "format": {"fmt"},
        "disasm_style": {"style", "disasmStyle"},
        "include_bytes": {"bytes", "with_bytes"},
        "end": {"end_addr", "to"},
        "limit": {"max", "count"},
        "field_name": {"field", "member"},
        "target": {"to", "destination"},
    },
    "schemaboot": {
        "constraints": {"filters", "where", "criteria"},
        "addr": {"address", "ea", "va"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "order_by": {"sort", "order"},
        "include_apis": {"apis", "with_apis"},
        "include_strings": {"strings", "with_strings"},
    },
    "governance": {
        "operation_type": {"op_type", "type", "op"},
        "proposed_value": {"value", "text", "content", "input"},
        "addr": {"address", "ea", "va"},
    },
}

def _build_action_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name, actions in TOOL_ACTIONS.items():
        alias_map: dict[str, str] = {}
        for action in actions:
            candidates = _snake_variants(action).union(_camel_variants(action))
            candidates.update(_ACTION_ALIAS_HINTS.get(action, set()))
            candidates.update(
                _TOOL_ACTION_EXTRA_ALIASES.get(tool_name, {}).get(action, set())
            )
            if action.startswith("get_"):
                candidates.add(action.replace("get_", "show_", 1))
            if action.startswith("set_"):
                candidates.add(action.replace("set_", "update_", 1))
            if action.startswith("find_"):
                candidates.add(action.replace("find_", "search_", 1))
            if action.startswith("list_"):
                candidates.add(action.replace("list_", "get_", 1))
            for alias in list(candidates):
                candidates.update(_noisy_alias_variants(alias))
            for alias in candidates:
                key = _normalize_alias_lookup_key(alias)
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != action:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = action
        for action in actions:
            alias_map.pop(action.lower(), None)
        out[tool_name] = alias_map
    return out

def _build_tool_arg_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name in TOOLS:
        canonical_keys = set(TOOL_ARG_SCHEMAS.get(tool_name, {}).keys())
        canonical_keys.add("action")
        canonical_keys.update(_TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).keys())
        alias_map: dict[str, str] = {}
        # Sort for deterministic alias conflict resolution across processes/runs.
        for canonical in sorted(canonical_keys):
            candidates = _snake_variants(canonical).union(_camel_variants(canonical))
            # Keep argument aliasing conservative: avoid automatic singular/plural flips,
            # because some tools intentionally use both (e.g. tag vs tags, note vs notes).
            if canonical.endswith("s") and len(canonical) > 3:
                candidates.discard(canonical[:-1])
            else:
                candidates.discard(f"{canonical}s")
            candidates.update(_COMMON_ARG_ALIAS_HINTS.get(canonical, set()))
            candidates.update(
                _TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).get(canonical, set())
            )
            candidates.update(
                _TOOL_ARG_EXTRA_ALIASES.get(tool_name, {}).get(canonical, set())
            )
            for alias in list(candidates):
                candidates.update(_noisy_alias_variants(alias))
            for alias in candidates:
                key = _normalize_alias_lookup_key(alias)
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != canonical:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = canonical
        for canonical, explicit_aliases in _TOOL_SPECIFIC_ARG_ALIASES.get(
            tool_name, {}
        ).items():
            for alias in explicit_aliases:
                alias_key = _normalize_alias_lookup_key(alias)
                if alias_key and alias_key != canonical.lower():
                    alias_map[alias_key] = canonical
        for canonical in canonical_keys:
            alias_map.pop(canonical.lower(), None)
        out[tool_name] = alias_map
    return out

ACTION_ALIASES_BY_TOOL = _build_action_aliases()
ARG_ALIASES_BY_TOOL = _build_tool_arg_aliases()

GLOBAL_RESPONSE_CONTROLS = {
    "_response_mode": {
        "type": "string",
        "enum": ["compact", "full"],
        "description": "Output mode. compact is default and reduces token usage.",
    },
    "_compact": {
        "type": "boolean",
        "description": "Shortcut for compact/full mode toggle.",
    },
    "_response_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field projection (comma-separated string or list).",
    },
    "_response_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field omission list.",
    },
    "_response_max_items": {
        "type": "integer",
        "description": "Max list items retained in compact mode.",
    },
    "_response_max_string": {
        "type": "integer",
        "description": "Max string length retained in compact mode.",
    },
    "_response_char_budget": {
        "type": "integer",
        "description": "Approximate max output chars before truncation middleware applies.",
    },
    "_response_table": {
        "type": "boolean",
        "description": "Convert repetitive list-of-object payloads into {columns,rows}.",
    },
    "_response_batch_compact": {
        "type": "boolean",
        "description": "Compact batch envelopes in compact mode.",
    },
    "_error_details": {
        "type": "string",
        "enum": ["none", "basic", "full"],
        "description": "Controls verbosity of error details.",
    },
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL profile shortcut for response compaction presets.",
    },
}

GLOBAL_WRAPPER_ACTION_CONTROLS = {
    "source_action": {
        "type": "string",
        "description": "For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).",
    },
    "target_action": {"type": "string"},
    "on": {"type": "string"},
    "subaction": {"type": "string"},
    "grep": {
        "type": "string",
        "description": "Grep pattern (substring by default; regex if grep_regex=true).",
    },
    "grep_pattern": {"type": "string"},
    "grep_regex": {"type": "boolean"},
    "grep_case_sensitive": {"type": "boolean"},
    "grep_invert": {"type": "boolean"},
    "grep_field": {
        "type": "string",
        "description": "Optional top-level source field to grep (e.g. matches, functions, content).",
    },
    "grep_limit": {"type": "integer"},
    "grep_offset": {"type": "integer"},
    "pick_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to include.",
    },
    "pick_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to omit after pick_fields.",
    },
    "head_n": {"type": "integer"},
    "tail_n": {"type": "integer"},
    "next_token": {"type": "string"},
    "token": {"type": "string"},
    "cursor": {"type": "string"},
    "stats_include_payload": {"type": "boolean"},
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL response profile preset.",
    },
    "qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
    },
}

def _action_enum_with_grep(tool_name: str) -> list[str]:
    actions = list(TOOL_ACTIONS.get(tool_name, []) or [])
    for wrapper_action in WRAPPER_ACTIONS:
        if wrapper_action not in actions:
            actions.append(wrapper_action)
    return actions

def build_input_schema(tool_name: str) -> dict:
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        props.update(TOOL_ARG_SCHEMAS[tool_name])
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    for key, schema in GLOBAL_RESPONSE_CONTROLS.items():
        props.setdefault(key, schema)
    # idb parameter is now completely optional - uses current_session automatically
    # Only include it in schema for documentation, never required
    if (
        tool_name not in ("session", "bookmarks", "wiki", "batch")
        and "idb" not in props
    ):
        props["idb"] = {
            "type": "string",
            "description": "Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.",
        }
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, schema)
        required.append("action")
    return {"type": "object", "properties": props, "required": required}

def _lean_prop_schema(prop_name: str, schema: Any) -> dict:
    """
    Produce an ultra-lean per-parameter schema for tools/list.
    Keep action enum, but collapse other fields to just a basic type.
    """
    if not isinstance(schema, dict):
        return {"type": "string"}

    out: dict[str, Any] = {}
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        out["type"] = raw_type
    elif isinstance(raw_type, list):
        # Prefer a concrete scalar-ish type to avoid noisy anyOf-style payloads.
        preferred = None
        for t in ("string", "integer", "number", "boolean", "array", "object"):
            if t in raw_type:
                preferred = t
                break
        out["type"] = preferred or "string"
    elif prop_name == "action":
        out["type"] = "string"
    else:
        out["type"] = "string"

    if prop_name == "action":
        enum_vals = schema.get("enum")
        if isinstance(enum_vals, list):
            out["enum"] = enum_vals
    return out

def build_input_schema_lean(tool_name: str) -> dict:
    """
    Build a minimal input schema for tools/list to reduce prompt/context overhead.
    Preserves essential per-tool argument fields while stripping verbose text.
    """
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        for k, v in TOOL_ARG_SCHEMAS[tool_name].items():
            props[k] = _lean_prop_schema(k, v)
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    if tool_name not in ("session", "bookmarks", "wiki", "batch"):
        props["idb"] = {"type": "string"}
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, _lean_prop_schema(key, schema))
        required.append("action")
    return {"type": "object", "properties": props, "required": required}

def build_input_schema_ultra(tool_name: str) -> dict:
    """
    Build a very small schema for tools/list to minimize startup context.
    Keeps only the essential invocation shape (action enum + optional idb).
    """
    if tool_name == "batch":
        return {
            "type": "object",
            "properties": {
                "calls": {"type": "array", "items": {"type": ["object", "string"]}},
                "continue_on_error": {"type": "boolean"},
            },
            "required": ["calls"],
        }
    if tool_name == "truncation":
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
                "token": {"type": "string"},
            },
            "required": ["action"],
        }

    props: Dict[str, Any] = {}
    required: List[str] = []
    action_enum = TOOL_ACTIONS.get(tool_name)
    if action_enum:
        props["action"] = {"type": "string", "enum": _action_enum_with_grep(tool_name)}
        required.append("action")
    if tool_name not in ("session", "bookmarks", "wiki", "batch", "truncation"):
        props["idb"] = {
            "type": "string",
            "description": "Optional. session_id, SID_* id, binary path, or full IDB path.",
        }
    return {"type": "object", "properties": props, "required": required}

def build_tool_description_ultra(tool_name: str) -> str:
    """Return a tiny wiki-first routing hint for ultra tools/list mode."""
    if tool_name == "wiki":
        return "Wiki index + docs. Start with wiki(action='index')."
    if tool_name == "session":
        return "Session hub. IDB is optional after create/switch."
    if tool_name == "batch":
        return "Batch hub. Use calls as 'tool:action' or {name,action,...}."
    return f"Use wiki(topic='tools/{tool_name}') for usage."

def build_tool_description_lean(tool_name: str) -> str:
    """Return a short description without embedded action lists."""
    full = str(TOOL_DESCRIPTIONS.get(tool_name, "") or "").strip()
    if not full:
        return ""
    if "Actions:" in full:
        full = full.split("Actions:", 1)[0].strip()
    full = re.sub(r"\s+", " ", full).strip(" .")
    if not full:
        return ""
    if len(full) > 140:
        full = full[:137].rstrip() + "..."
    return full + "."

_TOOL_CATEGORY_CORE = {"session", "truncation", "bookmarks", "batch", "wiki"}
_TOOL_CATEGORY_ANALYSIS = {
    "analysis",
    "query",
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    "modify",
    "funcs",
    "segments",
    "bulk",
    "calc",
    "nav",
}
_TOOL_CATEGORY_DEBUG = {"debug", "trace", "coverage", "trace_analysis"}
_TOOL_CATEGORY_PROJECT = {"project", "misc"}
_TOOL_CATEGORY_ADVANCED = {
    "agent",
    "microcode",
    "graph",
    "ctree",
    "mbagcn",
    "static_trace",
    "entropy",
    "imports_deep",
    "patterns",
    "symbols",
    "lumina",
    "export",
    "history",
    "comment_mgr",
    "colorize",
    "data_ops",
    "fixups",
    "hooks",
}
_TOOL_CATEGORY_SECURITY = {
    "threat_hunt",
    "deobfuscate",
    "crypto_id",
    "protocol",
    "gadgets",
    "annotation",
    "xref_analysis",
    "string_ops",
    "cfg_analysis",
    "binary_info",
    "abi",
    "stack_analysis",
    "compare",
    "classify",
    "summarize",
}
_TOOL_CATEGORY_COMPAT = set()

def classify_tool_category(tool_name: str) -> str:
    if tool_name in _TOOL_CATEGORY_CORE:
        return "core"
    if tool_name in _TOOL_CATEGORY_ANALYSIS:
        return "analysis"
    if tool_name in _TOOL_CATEGORY_DEBUG:
        return "debug"
    if tool_name in _TOOL_CATEGORY_PROJECT:
        return "project"
    if tool_name in _TOOL_CATEGORY_ADVANCED:
        return "advanced"
    if tool_name in _TOOL_CATEGORY_SECURITY:
        return "security"
    if tool_name in _TOOL_CATEGORY_COMPAT:
        return "compat"
    return "other"

def sanitize_schema_for_vertex(schema: Any) -> Any:
    """
    Translates a schema into a Vertex AI/Gemini-compatible format by removing
    unsupported structures such as arrays of types, empty required arrays, and
    empty properties dictionaries.
    """
    if not isinstance(schema, dict):
        return schema

    out = {}
    for k, v in schema.items():
        if k == "type" and isinstance(v, list):
            # Prefer a scalar type, fallback to string if none found
            preferred = None
            for t in ("string", "integer", "number", "boolean", "array", "object"):
                if t in v:
                    preferred = t
                    break
            out[k] = preferred or "string"
        elif k == "required" and isinstance(v, list) and len(v) == 0:
            continue
        elif k == "properties" and isinstance(v, dict) and len(v) == 0:
            continue
        elif isinstance(v, dict):
            out[k] = sanitize_schema_for_vertex(v)
        elif isinstance(v, list):
            out[k] = [sanitize_schema_for_vertex(item) for item in v]
        else:
            out[k] = v

    if out.get("type") == "array" and "items" not in out:
        out["items"] = {"type": "string"}
    elif out.get("type") != "array" and "items" in out:
        del out["items"]

    return out
