# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`structs`

## Use This Skill When
- You need to call the `structs` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Structure recovery and reconstruction. Actions: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable.

## Actions
- `recover`
- `analyze_usage`
- `list`
- `create`
- `add_member`
- `apply`
- `reconstruct_vtable`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
