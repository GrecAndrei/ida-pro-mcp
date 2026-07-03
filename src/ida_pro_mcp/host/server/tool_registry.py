"""
Single source of truth for per-tool action lists, argument schemas, and aliases.

Each tool module in ``ida_mcp/tools/`` exports its action list as ``TOOL_ACTIONS``.
This module aggregates them into the dicts that ``schemas_data.py`` and the
dispatchers consume.  For host-side-only tools (session, blackboard, workflow)
the action lists are defined here directly.

Long-term goal: every tool's ``TOOL_ACTIONS`` lives in its own file so that
``schemas_data.py`` can be reduced to tool descriptions only.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Tool -> [action names]
# ---------------------------------------------------------------------------
# These are the canonical action lists that drive argument validation and
# tool listing.  Every action name here MUST have a corresponding handler
# in the tool's dispatch table or if/elif ladder.
#
# Tools whose action list lives in the tool file itself are marked below.
_TOOL_ACTIONS: dict[str, list[str]] = {
    "abi": [
        "detect", "stack_args", "reg_args", "return_type",
        "varargs", "struct_return", "tail_calls",
        "prologue", "epilogue", "abi_violations",
    ],
    "agent": [
        "analyze_function", "explore_address", "find_references",
        "search_all", "search_structs", "context_pack", "quick",
        "rename_suggestions", "batch_context", "similar",
        "bridge_query", "reflect", "cluster", "fingerprint",
        "cfg_encode", "cfg_similar", "cfg_stats",
    ],
    "analysis": [
        "get_options", "set_options", "set_processor",
        "set_loader_options", "set_architecture", "reanalyze",
        "run", "analyze", "wait",
    ],
    "annotation": [
        "auto_comment", "auto_comment_function", "label_loops",
        "label_branches", "mark_dangerous", "annotate_constants",
        "tag_functions", "document_args", "mark_error_paths",
        "propagate_names", "cleanup", "validate", "get_context",
        "set_structured", "bulk_set", "export_md", "import_md", "summary",
    ],
    "background": ["submit", "status", "cancel", "result", "list", "wait"],
    "batch": ["(pass calls array)"],
    "binary_info": [
        "headers", "sections", "relocations", "resources",
        "debug_info", "compiler", "linker", "timestamps",
        "checksums", "overlay",
    ],
    "blackboard": [
        "policy_set", "policy_status", "policy_check", "phase_status",
        "phase_set", "phase_tick", "quest_board", "quest_complete",
        "memory_compile", "phase_finalize", "trace_ingest", "trace_run",
        "trace_status", "proposal_create", "proposal_list",
        "proposal_accept", "proposal_reject", "decision_card",
        "working_set", "state_health", "notes_export", "notes_import",
        "write", "read", "list", "search", "update", "delete", "clear",
        "stats", "prune", "merge", "contradict", "resolve",
        "next_target", "frontier", "coverage", "propagate_labels",
        "start_crawler", "stop_crawler", "crawler_status",
        "accept", "reject", "add_evidence", "calibrate",
        "campaign_summary", "auto_tag_propagate",
        "accept_proposal", "reject_proposal",
        "add_system", "add_struct", "add_gap", "fill_gap",
        "add_state_machine", "add_peripheral", "add_attack_surface",
        "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
        "kg_state_machines", "kg_attack_surface", "kg_peripherals",
        "export_symbols", "import_symbols",
        "semantic_index", "semantic_rebuild", "related_by_behavior",
        "deref", "chain",
    ],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    "bridge_search": ["bridges", "search"],
    "bulk": ["rename", "comment", "apply_type", "rename_stack", "import_annotations", "export_annotations"],
    "calc": ["eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops"],
    "cfg_analysis": ["complexity", "loops", "branches", "paths", "dominators", "post_dominators", "back_edges", "natural_loops", "irreducible", "flatten_detect"],
    "classify": ["function", "binary", "all_functions", "library_code", "wrappers", "callbacks", "initializers", "error_handlers", "hot_functions", "orphans", "induce_schema", "anchor_coverage"],
    "code": ["smart_decompile", "decompile", "disasm", "decompile_chain", "semantic_decompile", "diff_functions", "xrefs_to", "xrefs_from", "xrefs_to_field", "callees", "callers", "blocks", "callgraph", "find_paths", "strings_in_func", "decomp_dataflow", "export", "explain"],
    "colorize": ["set_func", "set_range", "set_insn", "get", "clear", "palette", "highlight_pattern"],
    "compare": ["functions", "blocks", "apis", "strings", "constants", "structure", "semantics", "batch_compare", "find_clones", "changelog"],
    "coverage": ["import_drcov", "import_lighthouse", "highlight", "report", "uncovered", "filter", "function_coverage", "gaps", "compare", "merge"],
    "crypto_id": ["identify", "constants", "encoding", "checksums", "entropy_analysis", "aes_ni"],
    "ctree": ["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow", "dominance_map", "var_dependency_graph"],
    "data": ["functions", "globals", "strings", "imports", "exports", "lookup", "bulk_query", "capability_matrix", "string_xrefs"],
    "data_ops": ["make_data", "make_array", "make_string", "undefine", "make_code", "cycle_data", "set_repr", "make_ptr"],
    "debug": ["status", "start", "stop", "continue", "step_into", "step_over", "run_to", "run_until", "breakpoints", "add_bp", "del_bp", "enable_bp", "add_hw_bp", "add_watch", "regs", "set_reg", "reg_diff", "snapshot_regs", "threads", "modules", "callstack", "read_mem", "write_mem", "search_mem", "stack_dump", "mem_map", "bp_context", "trace_start", "trace_stop", "trace_read", "mem_diff"],
    "deobfuscate": ["detect", "detect_encoding", "stack_strings", "dead_code", "api_hashing", "dynamic_dispatch", "anti_disasm", "decode_attempt"],
    "entropy": ["section", "region", "packed_detect", "crypto_detect", "compare", "window", "summary"],
    "export": ["listing", "html", "idc", "json", "sarif", "binexport", "headers", "redact"],
    "filter": ["filter"],
    "firmware_view": ["scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates", "smart_carve", "rollback_last", "review_contradictions", "region_profile", "pointer_clusters", "carve_plan", "campaign", "segment_sweep", "multi_region_campaign", "detect_load_address", "detect_vector_table", "detect_mmio", "rtos_scan", "triage_snapshot", "bootstrap"],
    "fixups": ["list", "get", "add", "delete"],
    "funcs": ["create", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names", "list"],
    "gadgets": ["rop", "jop", "cop", "syscall", "write_what_where", "stack_pivot", "shellcode_space", "mitigations", "seh_handlers", "pivot_chains", "classify_chain"],
    "governance": ["check", "redact", "list_rules", "stats"],
    "graph": ["callgraph", "cfg", "dominators", "xref_graph"],
    "history": ["undo", "redo", "list", "snapshot", "restore", "diff"],
    "hooks": ["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"],
    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks", "overview", "architecture_profile", "state"],
    "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
    "intelligence": [
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card", "structural_extract", "structural_extract_single",
        "structural_query", "structural_get", "structural_refresh",
        "structural_stats", "structural_delete", "structural_ingest",
    ],
    "knowledge": ["chip_identify", "symbol_lookup", "import_symbols", "export_session", "chip_families"],
    "llm_helpers": [
        "bootstrap", "context_window", "function_digest", "binary_digest",
        "explain_address", "suggest_next", "progress_report", "focus_area",
        "question_answer", "guided_analysis", "cheatsheet", "compact", "enrich",
        "intent_tool_compiler", "adaptive_query_planner",
        "question_type_router",
        "behavioral_signature_search", "cross_artifact_correlation_search",
        "path_constrained_search", "argument_semantics_search",
        "decompile_disasm_consistency_search",
        "function_role_classifier", "global_state_influence_mapper",
        "api_contract_extractor", "interprocedural_data_lineage_graph",
        "semantic_diff_explainer", "dangerous_pattern_explainer",
    ],
    "lumina": ["pull", "push", "status", "history", "search", "get_metadata"],
    "memory": ["read", "write", "hexdump", "search", "compare", "pointers", "find_pointers", "entropy", "strings", "struct_walk", "histogram"],
    "microcode": ["get", "blocks", "instructions", "def_use_graph"],
    "misc": ["python", "idc", "load_sig", "cache_stats", "plugin_list", "plugin_run", "read_file", "write_file", "health"],
    "modify": ["rename", "comment", "set_type", "patch_asm"],
    "nav": ["goto", "cursor", "interesting", "semantic_goto"],
    "patterns": ["generate", "match", "list_sigs", "apply_sig", "create_sig", "matched", "yara_from_func", "flirt_generate", "match_yara"],
    "packer": ["detect", "profile", "guide", "status", "script"],
    "predictor": ["suggest_next_tool", "detect_stuck", "suggest_focus", "suggest_next_address", "risk_of_stall", "recommend_bundle"],
    "project": ["save", "close", "open", "load_binary", "list_recent", "get_cwd", "set_cwd", "list_dir", "exists", "evidence_graph", "knowledge_merge", "confidence_model", "replay_pipeline", "hypothesis_tracker", "temporal_reasoning", "semantic_artifact_diff", "ai_governance", "knowledge_debt", "casefile_export"],
    "protocol": ["detect", "parsers", "serializers", "handlers", "endpoints", "tls_config", "socket_flow", "packet_struct", "magic_numbers", "state_machine", "reconstruct", "trace_handler", "export_spec"],
    "query": ["data", "search", "idb", "code", "types", "imports_deep", "symbols", "patterns", "nl", "nl_batch"],
    "search": [
        "nl", "behavior", "find", "semantic", "smart_bundle", "api",
        "decompiled", "structured", "vulnerable", "constants",
        "callers", "callees", "bytes", "string", "immediate", "name",
        "insns", "mnemonic", "instruction", "text", "operand", "comment",
        "data_ref", "code_ref", "regex", "func_by_sig", "type", "export",
        "summary", "query_lang", "bool", "hunt", "neighborhood", "outlier",
        "fingerprint", "path", "reach", "noreach",
    ],
    "segments": ["list", "add", "delete", "set_attr", "set_perms", "move", "info", "analyze", "find_code", "find_data", "compare", "merge"],
    "session": [
        "health", "create", "discover", "get", "list", "switch", "close",
        "status", "rebuild", "update", "rename", "duplicate",
        "export_session", "import_session", "archive", "unarchive",
        "tag", "untag", "find_by_tag", "add_note", "clear_notes",
        "cleanup_stale", "stats", "validate", "bulk_delete", "bulk_tag",
        "search_notes", "recent", "oldest", "snapshot", "restore_snapshot",
        "merge",
        "rate_skill", "list_skills", "suggest_strategy", "suggest_triage",
        "suggest_analogy", "apply_analogy", "log_activity",
        "get_activity_log", "notebook_append", "notebook_read",
        "notebook_section", "track_hypothesis", "confirm_hypothesis",
        "refute_hypothesis", "list_hypotheses", "dashboard", "get_phase",
        "advance_phase", "link_session", "cross_reference_sessions",
        "list_snapshots", "macro_set", "macro_get", "macro_list",
        "macro_delete", "macro_run", "recent_workset", "kill",
        "state",
    ],
    "stack_analysis": ["frame", "buffers", "canary", "alignment", "spills", "usage", "variables", "arrays", "uninitialized", "summary"],
    "string_ops": ["score_c2", "indicators", "ioc_extract", "persistence", "evasion", "find_urls", "find_ips", "find_paths", "find_registry", "find_emails", "find_commands", "find_c2", "find_configs", "find_api_keys", "find_databases", "find_crypto_addrs", "find_stack_strings", "find_base64", "find_xrefs", "entropy_rank", "suspicious", "encoding_stats", "multilingual", "decode_all"],
    "summarize": ["binary", "function", "segment", "imports_by_category", "strings_by_category", "complexity", "call_hierarchy", "data_flow", "security_posture", "statistics", "report"],
    "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],
    "taint": ["sources", "sinks", "trace", "paths", "report"],
    "struct_recover": ["recover", "recover_all", "propagate", "preview", "apply"],
    "emulate": ["run", "slice", "call", "decrypt", "trace"],
    "bindiff": ["snapshot", "diff", "patch_analysis", "function_match", "summary"],
    "multi_session": ["group_create", "group_list", "group_link", "group_remove", "cross_resolve", "cross_decompile", "cross_xrefs", "status"],
    "threat_hunt": ["run", "malware", "vuln", "tracing", "findings", "quick", "deep", "legacy"],
    "trace_analysis": [
        "import_trace", "analyze_coverage", "find_loops",
        "extract_api_calls", "basic_blocks_hit",
        "execution_timeline_graph", "cross_run_diff",
        "coverage_debug_plan", "anti_analysis_detect",
        "trace_entropy", "api_sequence", "loop_analysis",
        "get", "clear", "set_options", "static_trace",
        "decrypt_strings", "eval_expr", "deobfuscate_emulate",
        "prefetch_context",
    ],
    "truncation": ["continue"],
    "types": ["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct", "import_header", "diff", "visualize", "propagate", "enum_values", "type_graph"],
    "wiki": ["list_topics", "read", "search", "semantic_search", "index", "sections", "suggest"],
    "workflow": [
        "audit_plan", "execute_plan", "prioritize", "compose",
        "estimate", "explain", "plan", "catalog", "triage_fast",
        "malware_deep", "vuln_audit", "recon_sweep", "patch_review",
    ],
    "xref_analysis": ["call_chain", "common_callers", "common_callees", "hub_functions", "leaf_functions", "recursive", "dominator", "influence", "dependency_graph", "dead_functions"],
    "yara_hunt": ["scan", "compile", "list_rules", "match_context", "extract_strings", "xref_matches"],
}


# ---------------------------------------------------------------------------
# Argument schemas  (tool -> action -> {param_name: {type, description, ...}})
# ---------------------------------------------------------------------------
# Derived from TOOL_ARG_SCHEMAS in schemas_data.py.  Stub — full migration
# underway in Phase 2B.
ARG_SCHEMAS: dict[str, dict[str, dict[str, Any]]] = {}

# ---------------------------------------------------------------------------
# Argument aliases  (tool -> action -> {alias: canonical_param})
# ---------------------------------------------------------------------------
ARG_ALIASES: dict[str, dict[str, dict[str, str]]] = {}

# ---------------------------------------------------------------------------
# Action aliases  (tool -> {alias_action: canonical_action})
# ---------------------------------------------------------------------------
ACTION_ALIASES: dict[str, dict[str, str]] = {}


# === Public API ===========================================================

def advertised_tools() -> list[str]:
    """Return the advertised (user-facing) tool names."""
    from ..schemas_data import ADVERTISED_TOOLS

    return [t for t in ADVERTISED_TOOLS if t in _TOOL_ACTIONS]


def tool_actions() -> dict[str, list[str]]:
    return _TOOL_ACTIONS



def register_tool_actions(tool: str, actions: list[str]) -> None:
    """Register or override a tool's action list at runtime.

    Used by tool modules that define their action lists in the tool file itself
    (e.g., session, intelligence).  Any tool not explicitly registered here
    falls back to the ``_TOOL_ACTIONS`` literal above.
    """
    _TOOL_ACTIONS[tool] = actions
