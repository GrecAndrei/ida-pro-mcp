# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`export`

## Use This Skill When
- You need to call the `export` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Database export. Actions: listing, html, idc, json, binexport, headers.

## Actions
- `listing`
- `html`
- `idc`
- `json`
- `binexport`
- `headers`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
