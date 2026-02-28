# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`lumina`

## Use This Skill When
- You need to call the `lumina` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Lumina server interaction. Actions: pull, push, status, history, search.

## Actions
- `pull`
- `push`
- `status`
- `history`
- `search`
- `get_metadata`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
