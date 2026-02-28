# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`segments`

## Use This Skill When
- You need to call the `segments` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Segment management. Actions: list, add, delete, set_attr, set_perms, move, info.

## Actions
- `list`
- `add`
- `delete`
- `set_attr`
- `set_perms`
- `move`
- `info`

## Parameters
- `action`: `string` - allowed: `list, add, delete, set_attr, set_perms, move, info`
- `attr`: `string`
- `count`: `integer`
- `end`: `string`
- `name`: `string`
- `offset`: `integer`
- `sclass`: `string`
- `start`: `string`
- `value`: `string|integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
