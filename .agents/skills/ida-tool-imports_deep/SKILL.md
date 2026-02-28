# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`imports_deep`

## Use This Skill When
- You need to call the `imports_deep` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Advanced import resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.

## Actions
- `thunks`
- `delay`
- `forwarded`
- `ordinal`
- `api_sets`
- `resolve`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
