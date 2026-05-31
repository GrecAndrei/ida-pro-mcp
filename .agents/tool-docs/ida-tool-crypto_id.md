# IDA MCP Tool Doc: `crypto_id`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `crypto_id` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Detect cryptographic algorithms, constants, and encoding routines in the binary. Actions: identify, constants, encoding, checksums, entropy_analysis, aes_ni.

## Actions
- `identify` (tool-specific)
- `constants` (tool-specific)
- `encoding` (tool-specific)
- `checksums` (tool-specific)
- `entropy_analysis` (tool-specific)
- `aes_ni` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/crypto_id')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "crypto_id",
  "arguments": {
    "action": "identify"
  }
}
```
```json
{
  "name": "crypto_id",
  "arguments": {
    "action": "grep",
    "source_action": "identify",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
