# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`batch`

## Use This Skill When
- You need to call the `batch` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Run multiple tool calls in a single request. Arguments: calls[], continue_on_error.

## Actions
- `run`

## Parameters
- `calls`: `array`
- `continue_on_error`: `boolean`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
