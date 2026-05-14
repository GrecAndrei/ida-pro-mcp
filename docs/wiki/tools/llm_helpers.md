# llm_helpers

Context-aware utilities that help LLMs work efficiently within token budgets, plan analysis steps, and maintain situational awareness during reverse engineering sessions.

## Core Actions
- `context_window` — show current token usage and remaining budget
- `function_digest` — compact summary of a function; params: `address`
- `binary_digest` — high-level binary overview (sections, imports, entry points)
- `explain_address` — human-readable explanation of what lives at an address; params: `address`
- `suggest_next` — recommend next analysis steps based on current session state
- `progress_report` — summarize what has been analyzed and what remains
- `focus_area` — identify the most promising area to investigate next; params: `goal` (optional)
- `question_answer` — answer a natural-language question about the binary; params: `question`
- `compact` — reduce tool output to fit context window; params: `text` or pipe from prior output
- `enrich` — add confidence scores and suggested next actions to any tool output; params: `text` or pipe from prior output

## Expansion Actions (22 of 50 most important)
- `intent_tool_compiler` — translate natural-language intent into a tool call sequence
- `adaptive_query_planner` — plan multi-step queries adapting to intermediate results
- `token_aware_context_optimizer` — rewrite context to maximize information density
- `behavioral_signature_search` — find functions matching a behavioral description
- `cross_artifact_correlation_search` — correlate findings across strings, imports, xrefs
- `auto_expansion_search_chains` — automatically expand search when initial results are sparse
- `function_role_classifier` — classify function purpose (crypto, network, alloc, etc.)
- `protocol_format_reconstruction_assistant` — reconstruct protocol/message formats from code
- `interprocedural_data_lineage_graph` — trace data flow across function boundaries
- `semantic_diff_explainer` — explain semantic differences between two code versions
- `dangerous_pattern_explainer` — explain why a code pattern is dangerous
- `binary_capability_matrix_builder` — build a capability matrix (network, file, crypto, etc.)
- `execution_hypothesis_generator` — generate hypotheses about runtime behavior
- `patch_impact_forecaster` — predict side effects of a proposed patch
- `safe_idapython_orchestration_runtime` — execute IDAPython snippets with safety guardrails
- `investigation_playbook_engine` — run structured investigation playbooks
- `next_best_action_recommender` — rank possible next actions by expected value
- `analysis_dead_end_detector` — detect when current analysis path is unproductive
- `contradiction_tracker` — track contradictions between findings
- `case_narrative_composer` — compose a coherent narrative from analysis findings
- `cost_latency_optimizer` — optimize tool call sequences for token cost and latency
- `learning_feedback_loop` — record what worked/failed to improve future suggestions

## Examples
```json
{"name": "llm_helpers", "arguments": {"action": "context_window"}}
```
```json
{"name": "llm_helpers", "arguments": {"action": "compact", "text": "<large tool output>"}}
```
```json
{"name": "llm_helpers", "arguments": {"action": "function_digest", "address": "0x401000"}}
```
```json
{"name": "llm_helpers", "arguments": {"action": "suggest_next"}}
```
```json
{"name": "llm_helpers", "arguments": {"action": "enrich", "text": "<tool output to annotate>"}}
```

## Notes
- `compact` is essential when prior tool output exceeds context budget — use it to shrink results before reasoning.
- `enrich` wraps any tool output with confidence scores and recommended follow-up actions.
- The 50 expansion actions are advanced orchestration/planning features for autonomous analysis workflows.
- `context_window` should be checked periodically to avoid context overflow.
- Most expansion actions operate on session state and do not require explicit parameters beyond an optional `goal` or `query`.
