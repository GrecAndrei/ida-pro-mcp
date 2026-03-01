# IDA MCP Tool Doc: `bulk`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bulk` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Bulk rename/comment/type operations. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations. Supports continue_on_error.

## Actions
- `rename`
- `comment`
- `apply_type`
- `rename_stack`
- `import_annotations`
- `export_annotations`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `rename, comment, apply_type, rename_stack, import_annotations, export_annotations`
- `continue_on_error`: `boolean`
- `items`: `array`
- `path`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
