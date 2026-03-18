# IDA MCP Tool Doc: `plugins`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `plugins` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Legacy alias for misc plugin actions. Prefer misc(action=plugin_list|plugin_run).
- Compatibility-only alias: `plugins(action='list'|'run')` is forwarded to `misc` plugin actions.
- Prefer `misc(action='plugin_list')` and `misc(action='plugin_run', name='...', arg=0)` for new calls.

## Actions
- `list` (read/discovery)
- `run` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/plugins')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "plugins",
  "arguments": {
    "action": "list"
  }
}
```
```json
{
  "name": "plugins",
  "arguments": {
    "action": "grep",
    "source_action": "list",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
