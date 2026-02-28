# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`hooks`

## Use This Skill When
- You need to call the `hooks` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Hook suggestion and script generation. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.

## Actions
- `suggest`
- `generate_frida`
- `generate_detours`
- `find_targets`
- `inline_hooks`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
