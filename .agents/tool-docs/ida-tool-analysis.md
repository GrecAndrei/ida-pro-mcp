# IDA MCP Tool Doc: `analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Controls IDA analysis engine settings and triggers reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, run, analyze, wait.

## Actions
- `get_options` (tool-specific)
- `set_options` (tool-specific)
- `set_processor` (tool-specific)
- `set_loader_options` (tool-specific)
- `set_architecture` (tool-specific)
- `reanalyze` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/analysis')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze`
- `bitness`: `integer`
- `end`: `string`
- `endian`: `string`
- `flags`: `integer`
- `loader`: `string`
- `options`: `object`
- `processor`: `string`
- `start`: `string`
- `value`: `string|object`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "analysis",
  "arguments": {
    "action": "get_options"
  }
}
```
```json
{
  "name": "analysis",
  "arguments": {
    "action": "grep",
    "source_action": "get_options",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
