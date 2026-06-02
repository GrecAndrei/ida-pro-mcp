# IDA MCP Tool Doc: `summarize`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `summarize` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Structured summaries of binary components. binary: overall binary summary. function: single function summary. segment: segment summary. imports_by_category: imports grouped by API category. strings_by_category: strings grouped by type. complexity: function complexity metrics. call_hierarchy: call tree from entry point. data_flow: data flow summary. security_posture: dangerous APIs + mitigations + risk level. statistics: binary-wide stats. report: FULL REPORT — binary + security_posture + live taint scan + blackboard findings + statistics. NOTE: the binary and function actions share names with classify.binary / classify.function but produce DIFFERENT output — summarize returns counts/structure, classify returns categories/behavior tags. Pick the one that matches the question.

## Actions
- `binary` (tool-specific)
- `function` (tool-specific)
- `segment` (tool-specific)
- `imports_by_category` (tool-specific)
- `strings_by_category` (tool-specific)
- `complexity` (tool-specific)
- `call_hierarchy` (tool-specific)
- `data_flow` (tool-specific)
- `security_posture` (tool-specific)
- `statistics` (tool-specific)
- `report` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/summarize')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "summarize",
  "arguments": {
    "action": "binary"
  }
}
```
```json
{
  "name": "summarize",
  "arguments": {
    "action": "grep",
    "source_action": "binary",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
