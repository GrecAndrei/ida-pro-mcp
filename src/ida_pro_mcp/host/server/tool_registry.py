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

    "analysis": [
        "get_options", "set_options", "set_processor",
        "set_loader_options", "set_architecture", "reanalyze",
        "run", "analyze", "state",
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
    "blackboard": [
        "policy_set", "policy_status", "policy_check", "phase_status",
        "phase_set", "phase_tick", "quest_board", "quest_complete",
        "memory_compile", "phase_finalize", "trace_ingest", "trace_run",
        "trace_status", "proposal_create", "proposal_list",
        "proposal_accept", "proposal_reject", "decision_card",
        "working_set", "state_health", "notes_import",
        "export",
        "write", "read", "list", "search", "update", "delete", "clear",
        "stats", "prune", "merge", "contradict", "resolve",
        "next_target", "frontier", "coverage", "propagate_labels",
        "start_crawler", "stop_crawler", "crawler_status",
        "accept", "reject", "add_evidence", "calibrate", "decay",
        "campaign_summary", "workspace_brief",
        "mark_examined", "recall", "conflicts", "stale",
        "publish_findings", "import_annotations",
        "add_system", "add_struct", "add_gap", "fill_gap",
        "add_state_machine", "add_peripheral", "add_attack_surface",
        "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
        "kg_state_machines", "kg_attack_surface", "kg_peripherals",
        "export_symbols", "import_symbols",
        "semantic_index", "semantic_rebuild", "related_by_behavior",
        "deref", "chain",
    ],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    "calc": ["eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops"],
    "code": ["smart_decompile", "decompile", "decompile_all", "disasm", "detect", "decompile_chain", "semantic_decompile", "diff_functions", "xrefs_to", "xrefs_from", "xrefs_to_field", "callees", "callers", "blocks", "callgraph", "find_paths", "strings_in_func", "decomp_dataflow", "export", "explain"],

    "ctree": ["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow", "dominance_map", "var_dependency_graph"],
    "data": ["functions", "annotations", "globals", "strings", "imports", "exports", "lookup", "bulk_query", "capability_matrix", "string_xrefs", "read_bytes"],


    "firmware_view": ["scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates", "smart_carve", "rollback_last", "review_contradictions", "region_profile", "pointer_clusters", "carve_plan", "campaign", "segment_sweep", "multi_region_campaign", "detect_load_address", "detect_vector_table", "detect_mmio", "rtos_scan", "triage_snapshot", "bootstrap"],
    "funcs": ["create", "change", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names", "list"],
    "gadgets": ["rop", "jop", "cop", "syscall", "write_what_where", "stack_pivot", "shellcode_space", "mitigations", "seh_handlers", "pivot_chains", "classify_chain"],
    "governance": ["check", "redact", "list_rules", "stats"],
    "graph": ["callgraph", "cfg", "dominators", "xref_graph"],


    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks", "overview", "architecture_profile", "state"],
    "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
    "intelligence": [
        "intelligence_status", "embedder_status", "reranker_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "index_fast", "index_range", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary", "function_families",
    ],
    "knowledge": ["chip_identify", "symbol_lookup", "import_symbols", "export_session", "chip_families"],

    "memory": ["read", "write", "hexdump", "search", "compare", "pointers", "entropy", "strings", "struct_walk", "histogram", "read_file", "write_file"],
    "misc": ["python", "idc", "load_sig", "list_sigs", "cache_stats", "plugin_list", "plugin_run", "read_file", "write_file", "health", "reload"],
    "modify": ["rename", "comment", "set_type", "patch_asm"],






    "search": [
        "nl", "behavior", "find", "api",
        "decompiled", "structured", "vulnerable", "constants",
        "callers", "callees", "bytes", "string", "immediate", "name",
        "insns", "mnemonic", "instruction", "text", "operand", "comment",
        "data_ref", "code_ref", "regex", "func_by_sig", "type", "export",
        "summary", "query_lang", "bool", "analyze",
        "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
        "symbol", "symbol_info", "demangle", "xrefs_to_string",
    ],
    "segments": ["list", "add", "delete", "set_attr", "set_perms", "move", "info", "analyze", "find_code", "find_data", "compare", "merge"],
    "session": [
        "health", "create", "create_background", "get", "list", "switch", "close",
        "status", "rebuild", "update", "rename", "duplicate",
        "archive", "unarchive",
        "tag", "untag", "add_note", "clear_notes",
        "search_notes", "snapshot", "restore_snapshot",
        "kill", "state", "logs",
        "sso_activate", "agent_login", "agent_logout",
    ],
    "stack_analysis": ["frame", "buffers", "canary", "alignment", "spills", "usage", "variables", "arrays", "uninitialized", "summary"],
    "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],


    "multi_session": ["group_create", "group_list", "group_link", "group_remove", "cross_resolve", "cross_decompile", "cross_xrefs", "status"],
    "truncation": ["continue", "peek", "search", "summary"],
    "types": ["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct", "import_header", "diff", "visualize", "propagate", "enum_values", "type_graph", "vtable"],
    "wiki": ["list_topics", "read", "search", "semantic_search", "index", "sections", "suggest"],
    "workflow": [
        "audit_plan", "execute_plan", "prioritize", "compose",
        "estimate", "explain", "plan", "catalog", "triage_fast",
        "malware_deep", "vuln_audit", "recon_sweep", "patch_review",
    ],

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
