# IDA MCP Tool Doc: `types`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `types` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.

## Actions
- `list` (read/discovery)
- `get` (read/discovery)
- `set_prototype` (tool-specific)
- `parse_decl` (tool-specific)
- `declare` (tool-specific)
- `apply` (write/mutate)
- `search_structs` (tool-specific)
- `infer` (tool-specific)
- `read_struct` (tool-specific)
- `import_header` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/types')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "types",
  "arguments": {
    "action": "list"
  }
}
```
```json
{
  "name": "types",
  "arguments": {
    "action": "grep",
    "source_action": "list",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
