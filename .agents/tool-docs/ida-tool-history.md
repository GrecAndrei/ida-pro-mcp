# IDA MCP Tool Doc: `history`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `history` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Undo/redo and snapshots. Actions: undo, redo, list, snapshot, restore, diff.

## Actions
- `undo` (tool-specific)
- `redo` (tool-specific)
- `list` (read/discovery)
- `snapshot` (tool-specific)
- `restore` (tool-specific)
- `diff` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/history')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "history",
  "arguments": {
    "action": "undo"
  }
}
```
```json
{
  "name": "history",
  "arguments": {
    "action": "grep",
    "source_action": "undo",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
