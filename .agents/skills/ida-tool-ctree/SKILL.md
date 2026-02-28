# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`ctree`

## Use This Skill When
- You need to call the `ctree` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Hex-Rays AST (CTree) analysis. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow.

## Actions
- `get`
- `traverse`
- `find_calls`
- `find_vars`
- `find_strings`
- `find_conditions`
- `get_logic_flow`

## Parameters
- `action`: `string` - allowed: `get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow`
- `addr`: `string`
- `depth`: `integer`
- `query`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
