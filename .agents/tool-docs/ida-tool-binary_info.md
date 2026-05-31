# IDA MCP Tool Doc: `binary_info`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `binary_info` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Retrieves binary metadata including PE/ELF headers, sections, and build info. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.

## Actions
- `headers` (tool-specific)
- `sections` (read/discovery)
- `relocations` (tool-specific)
- `resources` (tool-specific)
- `debug_info` (tool-specific)
- `compiler` (tool-specific)
- `linker` (tool-specific)
- `timestamps` (tool-specific)
- `checksums` (tool-specific)
- `overlay` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/binary_info')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "binary_info",
  "arguments": {
    "action": "headers"
  }
}
```
```json
{
  "name": "binary_info",
  "arguments": {
    "action": "grep",
    "source_action": "headers",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
