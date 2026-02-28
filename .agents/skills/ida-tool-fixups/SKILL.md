# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`fixups`

## Use This Skill When
- You need to call the `fixups` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Relocation/fixup management. Actions: list, get, add, delete.

## Actions
- `list`
- `get`
- `add`
- `delete`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
