# IDA MCP Tool Doc: `nav`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `nav` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Navigation and triage. Actions: goto, cursor, interesting.

## Actions
- `goto` (tool-specific)
- `cursor` (tool-specific)
- `interesting` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/nav')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "nav",
  "arguments": {
    "action": "goto"
  }
}
```
```json
{
  "name": "nav",
  "arguments": {
    "action": "grep",
    "source_action": "goto",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
