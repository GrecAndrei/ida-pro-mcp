# IDA MCP Tool Doc: `trace_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `trace_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Execution trace processing. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit.

## Actions
- `import_trace` (tool-specific)
- `analyze_coverage` (tool-specific)
- `find_loops` (tool-specific)
- `extract_api_calls` (tool-specific)
- `basic_blocks_hit` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/trace_analysis')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "trace_analysis",
  "arguments": {
    "action": "import_trace"
  }
}
```
```json
{
  "name": "trace_analysis",
  "arguments": {
    "action": "grep",
    "source_action": "import_trace",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
