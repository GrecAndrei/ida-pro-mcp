# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`code`

## Use This Skill When
- You need to call the `code` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.

## Actions
- `decompile`
- `disasm`
- `xrefs_to`
- `xrefs_from`
- `xrefs_to_field`
- `callees`
- `callers`
- `blocks`
- `analyze`
- `callgraph`
- `export`
- `find_paths`
- `strings_in_func`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
