#!/usr/bin/env python3
"""
scripts/generate_schemas.py

Auto-generates TOOL_DESCRIPTIONS and TOOL_ACTIONS in schemas.py by:
1. Scanning all tool files for actual action names (Literal hints + action== patterns)
2. Reading descriptions from a JSON file (descriptions.json) written by subagents
3. Patching schemas.py in-place, preserving everything else

Usage:
    python scripts/generate_schemas.py --scan          # print discovered actions
    python scripts/generate_schemas.py --apply         # patch schemas.py
    python scripts/generate_schemas.py --apply --desc descriptions.json
"""
import argparse
import json
import os
import re
import sys

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "src",
                         "ida_pro_mcp", "ida_mcp", "tools")
SCHEMAS_PATH = os.path.join(os.path.dirname(__file__), "..", "src",
                            "ida_pro_mcp", "host", "schemas_data.py")

# Tools that live in host/ not tools/ — actions extracted manually
HOST_TOOL_ACTIONS = {
    "session": [
        "discover","create","get","list","switch","close","status","rebuild",
        "update","rename","duplicate","export_session","import_session",
        "archive","unarchive","tag","untag","find_by_tag","add_note",
        "clear_notes","cleanup_stale","stats","validate","bulk_delete",
        "bulk_tag","search_notes","recent","oldest","snapshot",
        "restore_snapshot","merge","macro_set","macro_get","macro_list",
        "macro_delete","macro_run","recent_workset",
        "rate_skill","list_skills","suggest_strategy","suggest_triage",
        "suggest_analogy","apply_analogy","log_activity",
        "get_activity_log","notebook_append","notebook_read","notebook_section",
        "track_hypothesis","confirm_hypothesis","refute_hypothesis",
        "list_hypotheses","get_phase","advance_phase","dashboard",
        "link","cross_reference","list_snapshots",
        "health",
    ],
    "batch": ["(pass calls array)"],
    "truncation": ["continue"],
    "bookmarks": ["add","list","delete","update","clear","find","export"],
    "query": ["data","search","idb","code","types","imports_deep","symbols","patterns", "nl", "nl_batch"],
    "wiki": ["list_topics","read","search","semantic_search","index","sections","suggest"],
    "blackboard": [
        "policy_set", "policy_status", "policy_check", "phase_status", "phase_set", "phase_tick",
        "quest_board", "quest_complete", "memory_compile", "phase_finalize", "trace_ingest",
        "trace_run", "trace_status", "proposal_create", "proposal_list", "proposal_accept",
        "proposal_reject", "decision_card", "working_set", "state_health", "notes_export",
        "notes_import", "write","read","list","search","update","delete","clear","stats",
        "prune","merge","contradict","resolve","next_target",
        "frontier", "coverage", "propagate_labels",
        "start_crawler","stop_crawler","crawler_status","accept","reject",
        "add_evidence","calibrate","campaign_summary","auto_tag_propagate",
        # KG write
        "add_system","add_struct","add_gap","fill_gap",
        "add_state_machine","add_peripheral","add_attack_surface",
        # KG read
        "kg_summary","kg_systems","kg_gaps","kg_structs",
        "kg_state_machines","kg_attack_surface","kg_peripherals",
        "export_symbols", "import_symbols", "semantic_index", "semantic_rebuild",
        "related_by_behavior",
    ],
    "modify": ["rename","comment","set_type","patch_asm"],
    "governance": ["check","redact","list_rules","stats"],
    "graph": [
        "callgraph", "cfg", "dominators", "xref_graph", "down", "up", "both", "json", "dot", "mermaid",
        "call_chain", "common_callers", "common_callees", "hub_functions", "leaf_functions",
        "recursive", "dominator", "influence", "dependency_graph", "dead_functions"
    ],
    "predictor": [
        "suggest_next_tool","detect_stuck","suggest_focus",
        "suggest_next_address","risk_of_stall",
        "recommend_bundle", "explain_decision", "feedback",
    ],
    "workflow": [
        "audit_plan", "execute_plan", "prioritize", "compose", "estimate",
        "explain", "plan", "catalog", "recon_sweep",
        "triage_fast","malware_deep","vuln_audit","patch_review"
    ],
    "project": ["save","close","open","load_binary","list_recent","get_cwd","set_cwd","list_dir","exists","evidence_graph","knowledge_merge","confidence_model","replay_pipeline","hypothesis_tracker","temporal_reasoning","semantic_artifact_diff","ai_governance","knowledge_debt","casefile_export"],
    "llm_helpers": [
        "bootstrap", "guided_analysis", "cheatsheet",
        "context_window","function_digest","binary_digest","explain_address",
        "suggest_next","progress_report","focus_area","question_answer",
        "compact","enrich",
        # 50 expansion actions
        "intent_tool_compiler","adaptive_query_planner","token_aware_context_optimizer",
        "cross_call_variable_resolver","evidence_weighted_response_assembler",
        "uncertainty_propagation_engine","multi_granularity_retrieval_layer",
        "semantic_chunking_for_decompiled_code","question_type_router",
        "interactive_clarification_protocol","behavioral_signature_search",
        "cross_artifact_correlation_search","temporal_search_replay",
        "search_hypothesis_sandbox","path_constrained_search",
        "argument_semantics_search","decompile_disasm_consistency_search",
        "near_miss_search_ranking","persistent_search_collections",
        "auto_expansion_search_chains","function_role_classifier",
        "global_state_influence_mapper",
        "api_contract_extractor","interprocedural_data_lineage_graph",
        "semantic_diff_explainer","dangerous_pattern_explainer",
        "binary_capability_matrix_builder","execution_hypothesis_generator",
        "patch_impact_forecaster","safe_idapython_orchestration_runtime",
        "script_template_marketplace_layer","auto_script_synthesis_from_intent",
        "script_output_schema_enforcer","long_running_job_manager",
        "cross_session_script_memory","privilege_scope_guardrails_for_scripts",
        "script_to_tool_promotion_pipeline","experiment_harness_for_script_variants",
        "idapython_provenance_recorder","investigation_playbook_engine",
        "next_best_action_recommender","analysis_dead_end_detector",
        "workset_intelligence_capsules","contradiction_tracker",
        "review_queue_for_ai_edits","case_narrative_composer",
        "cost_latency_optimizer","trust_verification_layer","learning_feedback_loop",
    ],
    "memory": ["read_file", "write_file"],
    "analysis": ["plugin_run"],
}

# Tools in subdirectories (packages) — actions listed manually
HOST_TOOL_ACTIONS["search"] = [
    "text", "bytes", "regex", "immediate", "code_pattern", "next", "all",
    "structured", "string", "name", "comment", "mnemonic", "operand",
    "insns", "instruction", "decompiled", "constants", "semantic",
    "smart_bundle", "func_by_sig", "vulnerable", "api", "callees", "callers",
    "code_ref", "data_ref", "export", "find", "nl", "behavior", "query_lang", "summary", "type",
    "bool", "hunt", "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
]

# Actions to exclude from specific tools (e.g. legacy or moved actions)
EXCLUDED_TOOL_ACTIONS = {
    "misc": {"plugin_run", "health", "read_file", "write_file"},
}

# Tools to skip (internal helpers, not exposed as MCP tools)
SKIP_FILES = {
    "arch_utils","firmware_heuristics","hybrid_search","query_lang",
    "semantic_matching","plugins",  # alias of misc
    "search",  # handled as package above
}


def scan_tool_actions(tool_file: str) -> list[str]:
    """Extract action names from a tool file."""
    try:
        src = open(tool_file).read()
    except Exception:
        return []

    actions = []
    seen = set()

    def add(a: str):
        a = a.strip().strip("\"'")
        if a and a not in seen and not a.startswith("_"):
            seen.add(a)
            actions.append(a)

    # Literal["a","b",...] type hints for action parameter
    for lit in re.findall(r'action\s*:\s*(?:Annotated\s*\[\s*)?Literal\s*\[([^\]]+)\]', src, re.DOTALL):
        for a in re.findall(r'["\']([^"\']+)["\']', lit):
            add(a)

    # action == "name": or action == 'name':
    for a in re.findall(r'action\s*==\s*["\']([^"\']+)["\']', src):
        add(a)

    # elif action in ("a", "b"):
    for group in re.findall(r'action\s+in\s+\(([^)]+)\)', src):
        for a in re.findall(r'["\']([^"\']+)["\']', group):
            add(a)

    return actions


def discover_all() -> dict[str, list[str]]:
    """Discover all tool→actions mappings."""
    result = {}

    # Scan tool files
    for fname in sorted(os.listdir(TOOLS_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        name = fname[:-3]
        if name in SKIP_FILES:
            continue
        actions = scan_tool_actions(os.path.join(TOOLS_DIR, fname))
        if actions:
            result[name] = actions

    # Merge host tools instead of overwriting
    for name, host_actions in HOST_TOOL_ACTIONS.items():
        if name in result:
            seen = set(host_actions)
            merged = list(host_actions)
            for a in result[name]:
                if a not in seen:
                    merged.append(a)
                    seen.add(a)
            result[name] = merged
        else:
            result[name] = list(host_actions)

    # Filter out excluded actions
    for name, excluded in EXCLUDED_TOOL_ACTIONS.items():
        if name in result:
            result[name] = [a for a in result[name] if a not in excluded]

    return result


def patch_schemas(actions_map: dict[str, list[str]],
                  descriptions: dict[str, str]) -> None:
    """Patch TOOL_DESCRIPTIONS and TOOL_ACTIONS in schemas.py."""
    src = open(SCHEMAS_PATH).read()

    # Get canonical TOOLS list from schemas_data.py
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    try:
        from ida_pro_mcp.host.schemas_data import TOOLS as canonical_tools_list
        canonical_tools = set(canonical_tools_list)
    except Exception as e:
        print(f"Warning: could not import TOOLS: {e}", file=sys.stderr)
        tools_match = re.search(r'TOOLS\s*=\s*\[(.*?)\]', src, re.DOTALL)
        canonical_tools = set()
        if tools_match:
            canonical_tools = set(re.findall(r'"([^"]+)"', tools_match.group(1)))

    # Only include tools that are in the canonical TOOLS list
    filtered_actions = {k: v for k, v in actions_map.items()
                        if k in canonical_tools}
    filtered_desc = {k: v for k, v in descriptions.items()
                     if k in canonical_tools}

    # Build new TOOL_DESCRIPTIONS block
    desc_lines = ["TOOL_DESCRIPTIONS = {\n"]
    for name, desc in sorted(filtered_desc.items()):
        escaped = desc.replace("\\", "\\\\").replace('"', '\\"')
        desc_lines.append(f'    "{name}": "{escaped}",\n')
    desc_lines.append("}\n")
    new_desc = "".join(desc_lines)

    # Build new TOOL_ACTIONS block
    act_lines = ["TOOL_ACTIONS = {\n"]
    for name, actions in sorted(filtered_actions.items()):
        act_lines.append(f'    "{name}": [\n')
        for a in actions:
            if not a.startswith("#"):
                act_lines.append(f'        "{a}",\n')
        act_lines.append("    ],\n")
    act_lines.append("}\n")
    new_acts = "".join(act_lines)

    # Replace TOOL_DESCRIPTIONS block
    src = re.sub(
        r'TOOL_DESCRIPTIONS\s*=\s*\{.*?\n\}',
        new_desc.rstrip("\n"),
        src, flags=re.DOTALL
    )

    # Replace TOOL_ACTIONS block
    src = re.sub(
        r'TOOL_ACTIONS\s*=\s*\{.*?\n\}',
        new_acts.rstrip("\n"),
        src, flags=re.DOTALL
    )

    open(SCHEMAS_PATH, "w").write(src)
    print(f"Patched {SCHEMAS_PATH}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", action="store_true", help="Print discovered actions")
    parser.add_argument("--apply", action="store_true", help="Patch schemas.py")
    parser.add_argument("--desc", default="", help="Path to descriptions.json")
    args = parser.parse_args()

    actions_map = discover_all()

    if args.scan:
        for name, actions in sorted(actions_map.items()):
            print(f"{name}: {actions}")
        return

    if args.apply:
        descriptions = {}
        if args.desc and os.path.exists(args.desc):
            descriptions = json.load(open(args.desc))
        else:
            # Use existing descriptions as fallback
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
            try:
                from ida_pro_mcp.host.schemas import TOOL_DESCRIPTIONS
                descriptions = dict(TOOL_DESCRIPTIONS)
            except Exception:
                pass
        patch_schemas(actions_map, descriptions)
        print(f"Done. {len(actions_map)} tools, {len(descriptions)} descriptions.")


if __name__ == "__main__":
    main()
