# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`binary_info`

## Use This Skill When
- You need to call the `binary_info` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Binary metadata analysis. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.

## Actions
- `headers`
- `sections`
- `relocations`
- `resources`
- `debug_info`
- `compiler`
- `linker`
- `timestamps`
- `checksums`
- `overlay`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
