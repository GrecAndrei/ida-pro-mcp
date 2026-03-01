# IDA MCP Tool Doc: `summarize`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `summarize` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
LLM-friendly summarization with compact output. Actions: binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics.

## Actions
- `binary`
- `function`
- `segment`
- `imports_by_category`
- `strings_by_category`
- `complexity`
- `call_hierarchy`
- `data_flow`
- `security_posture`
- `statistics`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
