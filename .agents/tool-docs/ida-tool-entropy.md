# IDA MCP Tool Doc: `entropy`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `entropy` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Compute entropy over regions to detect packing, encryption, or compressed data. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.

## Actions
- `section` (tool-specific)
- `region` (tool-specific)
- `packed_detect` (tool-specific)
- `crypto_detect` (tool-specific)
- `compare` (tool-specific)
- `window` (tool-specific)
- `summary` (read/discovery)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/entropy')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `section, region, packed_detect, crypto_detect, compare, window, summary`
- `addr`: `string`
- `end_addr`: `string`
- `limit`: `integer`
- `size`: `integer`
- `step`: `integer`
- `threshold`: `number`
- `window`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "entropy",
  "arguments": {
    "action": "section"
  }
}
```
```json
{
  "name": "entropy",
  "arguments": {
    "action": "grep",
    "source_action": "section",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
