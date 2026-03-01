# IDA MCP Tool Doc: `binary_info`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `binary_info` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
