# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`compare`

## Use This Skill When
- You need to call the `compare` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Function comparison and similarity. Actions: functions (side-by-side diff), blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.

## Actions
- `functions`
- `blocks`
- `apis`
- `strings`
- `constants`
- `structure`
- `semantics`
- `batch_compare`
- `find_clones`
- `changelog`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
