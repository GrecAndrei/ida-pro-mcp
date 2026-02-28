# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`edit`

## Use This Skill When
- You need to call the `edit` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Unified write/edit hub. Quick actions: rename, comment, type, patch, create_func, bulk.

## Actions
- `rename`
- `comment`
- `type`
- `patch`
- `create_func`
- `bulk`

## Parameters
- `action`: `string` - allowed: `rename, comment, type, patch, create_func, bulk`
- `args`: `object`
- `subaction`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
