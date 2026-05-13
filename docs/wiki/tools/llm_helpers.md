# llm_helpers

LLM-oriented helper actions: digests, explanations, guided analysis, and content compaction.

## Actions
- `context_window` — report current context usage/budget
- `function_digest` — compact digest of a function; params: `address`
- `binary_digest` — compact digest of the entire binary
- `explain_address` — explain what's at an address; params: `address`
- `suggest_next` — suggest next analysis step
- `progress_report` — summarize analysis progress
- `focus_area` — identify highest-priority area to analyze
- `question_answer` — answer a question about the binary; params: `question`
- `guided_analysis` — step-by-step guided analysis; params: `goal`
- `cheatsheet` — quick reference for common RE tasks
- `compact` — RE-specific content compaction; params: `content`

## Examples
```json
{"name": "llm_helpers", "arguments": {"action": "function_digest", "address": "0x401000"}}
```
```json
{"name": "llm_helpers", "arguments": {"action": "compact", "content": "<raw decompilation output>"}}
```

## Notes
- `compact` strips IDA color tags, compresses hex dumps, and truncates long xref lists.
- `suggest_next` and `focus_area` use blackboard + session state for recommendations.
- These actions are designed to minimize context window usage.
