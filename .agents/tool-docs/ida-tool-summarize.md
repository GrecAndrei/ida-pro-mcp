# IDA MCP Tool Doc: `summarize`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `summarize` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
LLM-friendly summarization with compact output. Actions: binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics.

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
- `grep` (host wrapper): run another action, then grep its output lines.

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
