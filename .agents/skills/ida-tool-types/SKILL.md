# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`types`

## Use This Skill When
- You need to call the `types` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.

## Actions
- `list`
- `get`
- `set_prototype`
- `parse_decl`
- `declare`
- `apply`
- `search_structs`
- `infer`
- `read_struct`
- `import_header`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
