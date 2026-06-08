# IDA MCP Tool Doc: `llm_helpers`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `llm_helpers` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Context-optimized helpers for LLM agents. START HERE: bootstrap gives a concrete first-turn playbook; cheatsheet returns full tool reference with concrete examples. context_window/function_digest/binary_digest/explain_address: compact analysis helpers. suggest_next/progress_report/focus_area: navigation and planning. behavioral_signature_search: find functions by behavior tag using BehaviorClassifier. function_role_classifier: entry_point/callback/dispatcher/wrapper via structural+embedding signals. dangerous_pattern_explainer: why a pattern is dangerous + exploitation path + mitigation. api_contract_extractor: infer preconditions/postconditions from call sites. global_state_influence_mapper: which globals a function reads/writes. interprocedural_data_lineage_graph: trace data flow across function boundaries. semantic_diff_explainer: embedding+BehaviorClassifier diff between two functions. decompile_disasm_consistency_search: find decompiler/disasm disagreements. argument_semantics_search: find functions by argument role. path_constrained_search: BFS from addr filtered by behavior tag. cross_artifact_correlation_search: correlate strings/names/blackboard by query.

## Actions
- `bootstrap` (tool-specific)
- `cheatsheet` (tool-specific)
- `context_window` (tool-specific)
- `function_digest` (tool-specific)
- `binary_digest` (tool-specific)
- `explain_address` (tool-specific)
- `suggest_next` (tool-specific)
- `progress_report` (tool-specific)
- `focus_area` (tool-specific)
- `behavioral_signature_search` (tool-specific)
- `function_role_classifier` (tool-specific)
- `dangerous_pattern_explainer` (tool-specific)
- `api_contract_extractor` (tool-specific)
- `global_state_influence_mapper` (tool-specific)
- `interprocedural_data_lineage_graph` (tool-specific)
- `semantic_diff_explainer` (tool-specific)
- `decompile_disasm_consistency_search` (tool-specific)
- `argument_semantics_search` (tool-specific)
- `path_constrained_search` (tool-specific)
- `cross_artifact_correlation_search` (tool-specific)

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
