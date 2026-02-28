# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`funcs`

## Use This Skill When
- You need to call the `funcs` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Function boundary management. Actions: create (auto-converts bytes to code, supports end address, flags, and force deletion of overlaps), delete (finds containing function if addr is inside one), set_flags, set_name (alias: rename), add_comment, list (supports regex/glob/substring query filtering), info (detailed function info with optional prototype and stack frame).

## Actions
- `create`
- `delete`
- `set_flags`
- `set_name`
- `rename`
- `add_comment`
- `list`
- `info`

## Parameters
- `action`: `string` - allowed: `create, delete, set_flags, set_name, rename, add_comment, list, info`
- `addr`: `string`
- `comment`: `string`
- `count`: `integer`
- `end`: `string`
- `flags`: `integer`
- `force`: `boolean`
- `include_prototype`: `boolean`
- `include_stack`: `boolean`
- `name`: `string`
- `named_only`: `boolean`
- `offset`: `integer`
- `query`: `string`
- `repeatable`: `boolean`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
