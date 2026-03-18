# IDA MCP Tool Doc: `bulk`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bulk` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Bulk rename/comment/type operations. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations. Supports continue_on_error.

## Actions
- `rename` (write/mutate)
- `comment` (write/mutate)
- `apply_type` (tool-specific)
- `rename_stack` (tool-specific)
- `import_annotations` (tool-specific)
- `export_annotations` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/bulk')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `rename, comment, apply_type, rename_stack, import_annotations, export_annotations`
- `continue_on_error`: `boolean`
- `items`: `array`
- `path`: `string`

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
