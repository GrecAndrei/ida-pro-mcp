# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`symbols`

## Use This Skill When
- You need to call the `symbols` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
PDB/DWARF symbol management. Actions: load_pdb, load_dwarf, status, apply, export.

## Actions
- `load_pdb`
- `load_dwarf`
- `status`
- `apply`
- `export`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
