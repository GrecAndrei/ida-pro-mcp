# IDA MCP Tool Doc: `packer`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `packer` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Detect packers / protectors (UPX, MPRESS, VMProtect, Themida, ASPack, custom) and game anti-cheat references in the current IDB. Returns indicators, classification, recommendation, and a structured workflow with concrete tool calls (static_steps) and external user actions (external_steps). Actions: detect, profile, guide, status, script. script runs Python in the packer's namespace for custom heuristics.

## Actions
- `detect` (analysis)
- `profile` (tool-specific)
- `guide` (tool-specific)
- `status` (read/discovery)
- `script` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/packer')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "packer",
  "arguments": {
    "action": "detect"
  }
}
```
```json
{
  "name": "packer",
  "arguments": {
    "action": "grep",
    "source_action": "detect",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
