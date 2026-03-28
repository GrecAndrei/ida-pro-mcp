# IDA MCP Tool Doc: `llm_helpers`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `llm_helpers` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
LLM workflow helpers. Actions: context_window (token-budgeted context), function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet.

## Actions
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
    "action": "context_window"
  }
}
```
```json
{
  "name": "llm_helpers",
  "arguments": {
    "action": "grep",
    "source_action": "context_window",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
