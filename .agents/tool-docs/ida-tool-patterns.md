# IDA MCP Tool Doc: `patterns`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `patterns` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Signature and pattern matching. Actions: generate, match, list_sigs, apply_sig, create_sig.

## Actions
- `generate` (tool-specific)
- `match` (tool-specific)
- `list_sigs` (tool-specific)
- `apply_sig` (tool-specific)
- `create_sig` (tool-specific)
- `matched` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/patterns')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "patterns",
  "arguments": {
    "action": "generate"
  }
}
```
```json
{
  "name": "patterns",
  "arguments": {
    "action": "grep",
    "source_action": "generate",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
