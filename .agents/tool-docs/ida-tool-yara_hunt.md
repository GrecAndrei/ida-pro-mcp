# IDA MCP Tool Doc: `yara_hunt`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `yara_hunt` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
YARA pattern matching. Actions: scan, compile, list_rules.

## Actions
- `scan` (analysis)
- `compile` (tool-specific)
- `list_rules` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/yara_hunt')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "yara_hunt",
  "arguments": {
    "action": "scan"
  }
}
```
```json
{
  "name": "yara_hunt",
  "arguments": {
    "action": "grep",
    "source_action": "scan",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
