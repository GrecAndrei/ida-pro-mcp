# IDA MCP Tool Doc: `stack_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `stack_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Stack frame analysis. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.

## Actions
- `frame` (tool-specific)
- `buffers` (tool-specific)
- `canary` (tool-specific)
- `alignment` (tool-specific)
- `spills` (tool-specific)
- `usage` (tool-specific)
- `variables` (tool-specific)
- `arrays` (tool-specific)
- `uninitialized` (tool-specific)
- `summary` (read/discovery)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/stack_analysis')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "stack_analysis",
  "arguments": {
    "action": "frame"
  }
}
```
```json
{
  "name": "stack_analysis",
  "arguments": {
    "action": "grep",
    "source_action": "frame",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
