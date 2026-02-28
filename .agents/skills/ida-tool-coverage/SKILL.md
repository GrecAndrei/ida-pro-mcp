# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`coverage`

## Use This Skill When
- You need to call the `coverage` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Code coverage import and analysis. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter.

## Actions
- `import_drcov`
- `import_lighthouse`
- `highlight`
- `report`
- `uncovered`
- `filter`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
