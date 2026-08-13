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
        "run", "analyze", "state", "set_gp",
        "save_idb", "make_code", "undefine", "get_af", "set_af", "force_offset",
        "add_entry", "snapshot", "restore_snapshot", "auto_wait",
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
        "phase_set", "phase_tick",
        "memory_compile", "phase_finalize", "trace_ingest", "trace_run",
        "trace_status", "proposal_create", "proposal_list",
        "proposal_accept", "proposal_reject", "decision_card",
        "working_set", "state_health", "notes_import",
        "export",
        "write", "read", "list", "search", "update", "delete", "clear",
        "stats", "coverage", "prune", "merge", "contradict", "resolve",
        "next_target", "frontier",
        "start_crawler", "stop_crawler", "crawler_status",
        "accept", "reject", "add_evidence", "calibrate", "decay",
        "campaign_summary", "workspace_brief",
        "mark_examined", "recall", "conflicts", "stale",
        "publish_findings", "import_annotations",
    ],
    "bookmarks": ["add", "list", "delete", "update", "clear", "find", "export"],
    "calc": ["eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops"],
    "code": ["smart_decompile", "decompile", "decompile_all", "disasm", "detect", "decompile_chain", "semantic_decompile", "diff_functions", "trace_argument_origin", "xrefs_to", "xrefs_from", "xrefs_to_field", "callees", "callers", "blocks", "callgraph", "find_paths", "strings_in_func", "decomp_dataflow", "export", "explain"],

    "ctree": ["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow", "dominance_map", "var_dependency_graph"],
    "data": ["functions", "annotations", "globals", "strings", "imports", "exports", "lookup", "bulk_query", "capability_matrix", "string_xrefs", "read_bytes"],
    "firmware": [
        "detect_vector_table", "detect_load_base", "detect_mmio",
        "rtos_scan", "carve",
    ],
    "emulate": [
        "info", "backend", "start", "state", "step", "run_to",
        "suspend", "continue", "stop", "get_reg", "set_reg",
        "read_mem", "set_mem",
    ],
    "funcs": ["create", "change", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names", "list"],
    "gadgets": ["rop", "jop", "cop", "syscall", "write_what_where", "stack_pivot", "shellcode_space", "mitigations", "seh_handlers", "pivot_chains", "classify_chain", "semantic_find"],
    "governance": ["check", "redact", "list_rules", "stats"],
    "graph": ["callgraph", "cfg", "dominators", "xref_graph"],


    "idb": ["meta", "summary", "segments", "entrypoints", "bookmarks", "overview", "architecture_profile", "state", "events", "registers"],
    "imports_deep": ["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
    "intelligence": [
        "intelligence_status", "embedder_status", "reranker_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "index_fast", "index_range", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary", "function_families",
    ],
    "knowledge": ["symbol_lookup", "import_symbols", "export_session"],

    "memory": ["read", "write", "hexdump", "search", "compare", "pointers", "entropy", "strings", "struct_walk", "histogram"],
    "misc": ["python", "idc", "load_sig", "list_sigs", "cache_stats", "plugin_list", "plugin_run", "read_file", "write_file", "health", "reload"],
    "modify": [
        "rename", "comment", "set_type", "patch_asm", "patch_bytes", "rename_local",
        "create_data", "create_strlit", "undo_begin", "undo_end",
    ],
    "r2": [
        "status", "bininfo", "load_hints", "disassemble_hypothesis", "vxrefs",
    ],






    "search": [
        "nl", "behavior", "find", "api",
        "decompiled", "structured", "vulnerable", "constants",
        "callers", "callees", "bytes", "string", "immediate", "name",
        "insns", "mnemonic", "instruction", "text", "operand", "comment",
        "data_ref", "code_ref", "regex", "func_by_sig", "type", "export",
        "summary", "query_lang", "bool", "analyze",
        "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
        "symbol", "symbol_info", "demangle", "xrefs_to_string", "data_value",
    ],
    "segments": ["list", "add", "delete", "set_attr", "set_perms", "move", "info", "analyze", "find_code", "find_data", "compare", "merge", "sreg_get", "sreg_set", "sreg_list"],
    "session": [
        "health", "create", "create_background", "get", "list", "switch", "close",
        "status", "rebuild", "update", "rename", "duplicate",
        "archive", "unarchive",
        "tag", "untag", "add_note", "clear_notes",
        "search_notes", "snapshot", "restore_snapshot",
        "kill", "state", "logs",
        "sso_activate", "agent_login", "agent_logout",
        "rate_skill", "list_skills", "suggest_triage",
        "suggest_strategy", "get_phase", "dashboard",
    ],
    "stack_analysis": ["frame", "buffers", "canary", "alignment", "spills", "usage", "variables", "arrays", "uninitialized", "summary"],
    "symbols": ["load_pdb", "load_dwarf", "status", "apply", "export"],


    "multi_session": ["group_create", "group_list", "group_link", "group_remove", "cross_resolve", "cross_decompile", "cross_xrefs", "status"],
    "truncation": ["continue", "peek", "search", "summary"],
    "types": ["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct", "import_header", "diff", "visualize", "propagate", "enum_values", "type_graph", "vtable", "struct_member_add", "struct_member_del", "struct_member_rename", "struct_member_set_type", "enum_member_add", "enum_member_rename", "enum_member_revalue", "til_delete", "til_export", "til_import"],
    "wiki": ["list_topics", "read", "search", "semantic_search", "index", "sections", "suggest"],
    "workflow": [
        "audit_plan", "execute_plan", "prioritize", "compose",
        "estimate", "explain", "plan", "catalog", "triage_fast",
        "malware_deep", "vuln_audit", "recon_sweep", "patch_review",
    ],

}


# ---------------------------------------------------------------------------
# Argument schemas / aliases
# ---------------------------------------------------------------------------
# These live in schemas_data.py (TOOL_ARG_SCHEMAS) and schemas.py
# (ACTION_ALIASES_BY_TOOL / ARG_ALIASES_BY_TOOL / _TOOL_SPECIFIC_ARG_ALIASES).
# No consumer reads module-level ARG_SCHEMAS/ARG_ALIASES/ACTION_ALIASES here,
# so they are intentionally not defined (dead stubs were removed).


# === Public API ===========================================================

def advertised_tools() -> list[str]:
    """Return the advertised (user-facing) tool names."""
    from ..schemas_data import ADVERTISED_TOOLS

    return [t for t in ADVERTISED_TOOLS if t in _TOOL_ACTIONS]


def tool_actions() -> dict[str, list[str]]:
    """Backend action catalog: unpublished lists plus every public op's pair."""
    merged = {tool: list(actions) for tool, actions in _TOOL_ACTIONS.items()}
    try:
        from ..agent_operations import list_agent_operations

        for op in list_agent_operations():
            if not op.backend_tool or not op.backend_action:
                continue
            bucket = merged.setdefault(op.backend_tool, [])
            if op.backend_action not in bucket:
                bucket.append(op.backend_action)
    except Exception:
        pass
    return merged



def register_tool_actions(tool: str, actions: list[str]) -> None:
    """Register or override a tool's action list at runtime.

    Used by tool modules that define their action lists in the tool file itself
    (e.g., session, intelligence).  Any tool not explicitly registered here
    falls back to the ``_TOOL_ACTIONS`` literal above.
    """
    _TOOL_ACTIONS[tool] = actions
