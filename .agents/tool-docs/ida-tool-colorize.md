# IDA MCP Tool Doc: `colorize`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `colorize` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.

## Actions
- `set_func` (tool-specific)
- `set_range` (tool-specific)
- `set_insn` (tool-specific)
- `get` (read/discovery)
- `clear` (destructive)
- `palette` (tool-specific)
- `highlight_pattern` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/colorize')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "colorize",
  "arguments": {
    "action": "set_func"
  }
}
```
```json
{
  "name": "colorize",
  "arguments": {
    "action": "grep",
    "source_action": "set_func",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
