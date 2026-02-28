# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`calc`

## Use This Skill When
- You need to call the `calc` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Mathematical and address resolution. Actions: eval, offset, convert, resolve, deref, chain, align.

## Actions
- `eval`
- `offset`
- `convert`
- `resolve`
- `deref`
- `chain`
- `align`

## Parameters
- `action`: `string` - allowed: `eval, offset, convert, resolve, deref, chain, align`
- `addr`: `string`
- `expr`: `string`
- `offsets`: `array|string`
- `size`: `integer`
- `target`: `string`
- `type`: `string`
- `value`: `string|integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
