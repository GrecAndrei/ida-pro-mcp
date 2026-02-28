# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`entropy`

## Use This Skill When
- You need to call the `entropy` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Entropy and packing detection. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.

## Actions
- `section`
- `region`
- `packed_detect`
- `crypto_detect`
- `compare`
- `window`
- `summary`

## Parameters
- `action`: `string` - allowed: `section, region, packed_detect, crypto_detect, compare, window, summary`
- `addr`: `string`
- `end_addr`: `string`
- `limit`: `integer`
- `size`: `integer`
- `step`: `integer`
- `threshold`: `number`
- `window`: `integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
