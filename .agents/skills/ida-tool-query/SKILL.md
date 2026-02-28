# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`query`

## Use This Skill When
- You need to call the `query` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Unified read-only query hub. Actions: data, search, idb, code, types, imports_deep, symbols, patterns.

## Actions
- `data`
- `search`
- `idb`
- `code`
- `types`
- `imports_deep`
- `symbols`
- `patterns`

## Parameters
- `action`: `string` - allowed: `data, search, idb, code, types, imports_deep, symbols, patterns`
- `args`: `object`
- `subaction`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
