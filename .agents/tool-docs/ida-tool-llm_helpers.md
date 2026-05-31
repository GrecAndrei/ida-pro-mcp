# IDA MCP Tool Doc: `llm_helpers`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `llm_helpers` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Context-optimized helpers for LLM agents. START HERE: bootstrap gives a concrete first-turn playbook; cheatsheet returns full tool reference with concrete examples. context_window/function_digest/binary_digest/explain_address: compact analysis helpers. suggest_next/progress_report/focus_area: navigation and planning. behavioral_signature_search: find functions by behavior tag using BehaviorClassifier. function_role_classifier: entry_point/callback/dispatcher/wrapper via structural+embedding signals. dangerous_pattern_explainer: why a pattern is dangerous + exploitation path + mitigation. api_contract_extractor: infer preconditions/postconditions from call sites. global_state_influence_mapper: which globals a function reads/writes. interprocedural_data_lineage_graph: trace data flow across function boundaries. semantic_diff_explainer: embedding+BehaviorClassifier diff between two functions. decompile_disasm_consistency_search: find decompiler/disasm disagreements. argument_semantics_search: find functions by argument role. path_constrained_search: BFS from addr filtered by behavior tag. cross_artifact_correlation_search: correlate strings/names/blackboard by query.

## Actions
- `bootstrap` (tool-specific)
- `context_window` (tool-specific)
- `function_digest` (tool-specific)
- `binary_digest` (tool-specific)
- `explain_address` (tool-specific)
- `suggest_next` (tool-specific)
- `progress_report` (tool-specific)
- `focus_area` (tool-specific)
- `question_answer` (tool-specific)
- `guided_analysis` (tool-specific)
- `cheatsheet` (tool-specific)
- `compact` (tool-specific)
- `enrich` (tool-specific)
- `intent_tool_compiler` (tool-specific)
- `adaptive_query_planner` (tool-specific)
- `token_aware_context_optimizer` (tool-specific)
- `cross_call_variable_resolver` (tool-specific)
- `evidence_weighted_response_assembler` (tool-specific)
- `uncertainty_propagation_engine` (tool-specific)
- `multi_granularity_retrieval_layer` (tool-specific)
- `semantic_chunking_for_decompiled_code` (tool-specific)
- `question_type_router` (tool-specific)
- `interactive_clarification_protocol` (tool-specific)
- `behavioral_signature_search` (tool-specific)
- `cross_artifact_correlation_search` (tool-specific)
- `temporal_search_replay` (tool-specific)
- `search_hypothesis_sandbox` (tool-specific)
- `path_constrained_search` (tool-specific)
- `argument_semantics_search` (tool-specific)
- `decompile_disasm_consistency_search` (tool-specific)
- `near_miss_search_ranking` (tool-specific)
- `persistent_search_collections` (tool-specific)
- `auto_expansion_search_chains` (tool-specific)
- `function_role_classifier` (tool-specific)
- `protocol_format_reconstruction_assistant` (tool-specific)
- `global_state_influence_mapper` (tool-specific)
- `api_contract_extractor` (tool-specific)
- `interprocedural_data_lineage_graph` (tool-specific)
- `semantic_diff_explainer` (tool-specific)
- `dangerous_pattern_explainer` (tool-specific)
- `binary_capability_matrix_builder` (tool-specific)
- `execution_hypothesis_generator` (tool-specific)
- `patch_impact_forecaster` (tool-specific)
- `safe_idapython_orchestration_runtime` (tool-specific)
- `script_template_marketplace_layer` (tool-specific)
- `auto_script_synthesis_from_intent` (tool-specific)
- `script_output_schema_enforcer` (tool-specific)
- `long_running_job_manager` (tool-specific)
- `cross_session_script_memory` (tool-specific)
- `privilege_scope_guardrails_for_scripts` (tool-specific)
- `script_to_tool_promotion_pipeline` (tool-specific)
- `experiment_harness_for_script_variants` (tool-specific)
- `idapython_provenance_recorder` (tool-specific)
- `investigation_playbook_engine` (tool-specific)
- `next_best_action_recommender` (tool-specific)
- `analysis_dead_end_detector` (tool-specific)
- `workset_intelligence_capsules` (tool-specific)
- `contradiction_tracker` (tool-specific)
- `review_queue_for_ai_edits` (tool-specific)
- `case_narrative_composer` (tool-specific)
- `cost_latency_optimizer` (tool-specific)
- `trust_verification_layer` (tool-specific)
- `learning_feedback_loop` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/llm_helpers')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "llm_helpers",
  "arguments": {
    "action": "bootstrap"
  }
}
```
```json
{
  "name": "llm_helpers",
  "arguments": {
    "action": "grep",
    "source_action": "bootstrap",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
