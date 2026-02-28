# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`data_ops`

## Use This Skill When
- You need to call the `data_ops` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.

## Actions
- `make_data`
- `make_array`
- `make_string`
- `undefine`
- `make_code`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
