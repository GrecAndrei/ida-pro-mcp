# IDA MCP Tool Doc: `compare`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `compare` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Function comparison and similarity. Actions: functions (side-by-side diff), blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.

## Actions
- `functions` (tool-specific)
- `blocks` (tool-specific)
- `apis` (tool-specific)
- `strings` (tool-specific)
- `constants` (tool-specific)
- `structure` (tool-specific)
- `semantics` (tool-specific)
- `batch_compare` (tool-specific)
- `find_clones` (analysis)
- `changelog` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/compare')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "compare",
  "arguments": {
    "action": "functions"
  }
}
```
```json
{
  "name": "compare",
  "arguments": {
    "action": "grep",
    "source_action": "functions",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
