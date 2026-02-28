# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`yara_hunt`

## Use This Skill When
- You need to call the `yara_hunt` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
YARA pattern matching. Actions: scan, compile, list_rules.

## Actions
- `scan`
- `compile`
- `list_rules`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
