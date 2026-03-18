# IDA MCP Tool Doc: `modify`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `modify` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Rename, comment, set types, and patch assembly. Actions: rename, comment (regular/repeatable/anterior/posterior), set_type, patch_asm (assembles instruction(s) and patches bytes, supports multi-line separated by semicolons).

## Actions
- `rename` (write/mutate)
- `comment` (tool-specific)
- `set_type` (write/mutate)
- `patch_asm` (write/mutate)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/modify')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "modify",
  "arguments": {
    "action": "rename"
  }
}
```
```json
{
  "name": "modify",
  "arguments": {
    "action": "grep",
    "source_action": "rename",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
