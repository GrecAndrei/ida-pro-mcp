# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`truncation`

## Use This Skill When
- You need to call the `truncation` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Continuation helper for auto-truncated responses. Actions: continue (retrieve next chunk by token/field).

## Actions
- `continue`

## Parameters
- `action`: `string` - allowed: `continue`
- `count`: `integer`
- `field`: `string`
- `offset`: `integer`
- `token`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
