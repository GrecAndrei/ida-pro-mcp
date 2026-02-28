# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`plugins`

## Use This Skill When
- You need to call the `plugins` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Legacy alias for misc plugin actions. Prefer misc(action=plugin_list|plugin_run).

## Actions
- (none documented)

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
