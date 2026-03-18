# IDA MCP Tool Doc: `hooks`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `hooks` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Hook suggestion and script generation. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.

## Actions
- `suggest` (tool-specific)
- `generate_frida` (tool-specific)
- `generate_detours` (tool-specific)
- `find_targets` (tool-specific)
- `inline_hooks` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/hooks')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "hooks",
  "arguments": {
    "action": "suggest"
  }
}
```
```json
{
  "name": "hooks",
  "arguments": {
    "action": "grep",
    "source_action": "suggest",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
