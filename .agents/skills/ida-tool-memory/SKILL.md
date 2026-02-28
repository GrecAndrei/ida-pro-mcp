# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`memory`

## Use This Skill When
- You need to call the `memory` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Direct database memory access. Actions: read, write, hexdump.

## Actions
- `read`
- `write`
- `hexdump`

## Parameters
- `action`: `string` - allowed: `read, write, hexdump`
- `addr`: `string`
- `data`: `string`
- `size`: `integer`
- `type`: `string` - allowed_count: `13`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
