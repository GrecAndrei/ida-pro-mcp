# IDA MCP Tool Doc: `memory`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `memory` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Read, write, and inspect raw memory/bytes in the binary or debuggee, plus host filesystem read/write helpers. Actions: read, write, hexdump, search, compare, pointers, find_pointers, entropy, strings, struct_walk, histogram, read_file, write_file.

## Actions
- `read` (read/discovery)
- `write` (write/mutate)
- `hexdump` (tool-specific)
- `search` (read/discovery)
- `compare` (tool-specific)
- `pointers` (tool-specific)
- `find_pointers` (tool-specific)
- `entropy` (tool-specific)
- `strings` (tool-specific)
- `struct_walk` (tool-specific)
- `histogram` (tool-specific)
- `read_file` (tool-specific)
- `write_file` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/memory')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `13`
- `addr`: `string`
- `addr1`: `string`
- `addr2`: `string`
- `content`: `string` - Content to write for write_file
- `data`: `string`
- `depth`: `integer`
- `encoding`: `string` - File encoding (default: utf-8). Use 'binary' for hex-encoded binary data.
- `end_addr`: `string`
- `int_width`: `integer`
- `path`: `string` - File path for read_file/write_file
- `pattern`: `string`
- `regex`: `boolean`
- `size`: `integer`
- `type`: `string` - allowed_count: `13`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "memory",
  "arguments": {
    "action": "read"
  }
}
```
```json
{
  "name": "memory",
  "arguments": {
    "action": "grep",
    "source_action": "read",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
