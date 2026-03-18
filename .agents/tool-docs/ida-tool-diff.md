# IDA MCP Tool Doc: `diff`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `diff` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Binary differential analysis. Actions: functions, bytes, signatures, summary, export_binexport.

## Actions
- `functions` (tool-specific)
- `bytes` (tool-specific)
- `signatures` (tool-specific)
- `summary` (read/discovery)
- `export_binexport` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/diff')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "diff",
  "arguments": {
    "action": "functions"
  }
}
```
```json
{
  "name": "diff",
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
