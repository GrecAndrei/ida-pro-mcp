# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`analysis`

## Use This Skill When
- You need to call the `analysis` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.

## Actions
- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`

## Parameters
- `action`: `string` - allowed: `get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze`
- `bitness`: `integer`
- `end`: `string`
- `endian`: `string`
- `flags`: `integer`
- `loader`: `string`
- `options`: `object`
- `processor`: `string`
- `start`: `string`
- `value`: `string|object`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
