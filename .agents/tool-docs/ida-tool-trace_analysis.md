# IDA MCP Tool Doc: `trace_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `trace_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Execution trace processing. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit.

## Actions
- `import_trace`
- `analyze_coverage`
- `find_loops`
- `extract_api_calls`
- `basic_blocks_hit`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
