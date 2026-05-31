# IDA MCP Tool Doc: `firmware_bootstrap`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `firmware_bootstrap` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Chip-aware post-load bootstrap pipeline for firmware binaries. Defines vector-table functions (Reset_Handler and IRQ handlers), annotates known MMIO peripherals, runs auto-analysis, and returns a bootstrap report.

## Actions
- `(call with chip_family/load_base/memory_map/peripheral_addresses)` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/firmware_bootstrap')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `chip_family`: `string`
- `load_base`: `integer|string`
- `memory_map`: `array`
- `peripheral_addresses`: `array`
- `post_load_actions`: `array`

## Minimal Call Shapes
```json
{
  "name": "firmware_bootstrap",
  "arguments": {
    "action": "(call with chip_family/load_base/memory_map/peripheral_addresses)"
  }
}
```
```json
{
  "name": "firmware_bootstrap",
  "arguments": {
    "action": "grep",
    "source_action": "(call with chip_family/load_base/memory_map/peripheral_addresses)",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
