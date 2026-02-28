# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`data`

## Use This Skill When
- You need to call the `data` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Function listing, global variables, strings, imports, and exports. Actions: functions, globals, strings, imports, exports, lookup, bulk_query. Supports include_prototype, include_xrefs, min_size, named_only filters. Query patterns auto-detect regex (e.g. ^init, \w+alloc), glob (*alloc*), or plain substring.

## Actions
- `functions`
- `globals`
- `strings`
- `imports`
- `exports`
- `lookup`
- `bulk_query`

## Parameters
- `action`: `string` - allowed: `functions, globals, strings, imports, exports, lookup, bulk_query`
- `count`: `integer`
- `include_prototype`: `boolean`
- `include_xrefs`: `boolean`
- `items`: `array`
- `min_size`: `integer`
- `named_only`: `boolean`
- `offset`: `integer`
- `query`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
