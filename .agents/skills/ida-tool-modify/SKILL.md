# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`modify`

## Use This Skill When
- You need to call the `modify` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Rename, comment, set types, and patch assembly. Actions: rename, comment (regular/repeatable/anterior/posterior), set_type, patch_asm (assembles instruction(s) and patches bytes, supports multi-line separated by semicolons).

## Actions
- `rename`
- `comment`
- `set_type`
- `patch_asm`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
