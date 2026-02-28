# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`taint`

## Use This Skill When
- You need to call the `taint` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Static data flow and vulnerability analysis. Actions: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice.

## Actions
- `find_arg_usage`
- `trace_return`
- `find_sinks`
- `data_flow`
- `backward_trace`
- `slice`

## Parameters
- `action`: `string` - allowed: `find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice`
- `addr`: `string`
- `arg_num`: `integer`
- `depth`: `integer`
- `max_hits`: `integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
