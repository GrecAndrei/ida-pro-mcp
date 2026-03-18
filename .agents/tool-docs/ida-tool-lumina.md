# IDA MCP Tool Doc: `lumina`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `lumina` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Lumina server interaction. Actions: pull, push, status, history, search.

## Actions
- `pull` (tool-specific)
- `push` (tool-specific)
- `status` (read/discovery)
- `history` (tool-specific)
- `search` (read/discovery)
- `get_metadata` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/lumina')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "lumina",
  "arguments": {
    "action": "pull"
  }
}
```
```json
{
  "name": "lumina",
  "arguments": {
    "action": "grep",
    "source_action": "pull",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
