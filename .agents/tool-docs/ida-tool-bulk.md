# IDA MCP Tool Doc: `bulk`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bulk` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Applies batch edits (renames, comments, types) to multiple addresses in one call. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.

## Actions
- `rename` (write/mutate)
- `comment` (tool-specific)
- `apply_type` (tool-specific)
- `rename_stack` (tool-specific)
- `import_annotations` (tool-specific)
- `export_annotations` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/bulk')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `rename, comment, apply_type, rename_stack, import_annotations, export_annotations`
- `continue_on_error`: `boolean`
- `items`: `array`
- `path`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "bulk",
  "arguments": {
    "action": "rename"
  }
}
```
```json
{
  "name": "bulk",
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
