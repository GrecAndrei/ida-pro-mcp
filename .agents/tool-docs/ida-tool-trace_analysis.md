# IDA MCP Tool Doc: `trace_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `trace_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Analyzes imported execution traces for coverage, loops, API sequences, and anti-analysis detection. Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, execution_timeline_graph, cross_run_diff, coverage_debug_plan, anti_analysis_detect, trace_entropy, api_sequence, loop_analysis.

## Actions
- `import_trace` (tool-specific)
- `analyze_coverage` (tool-specific)
- `find_loops` (tool-specific)
- `extract_api_calls` (tool-specific)
- `basic_blocks_hit` (tool-specific)
- `execution_timeline_graph` (tool-specific)
- `cross_run_diff` (tool-specific)
- `coverage_debug_plan` (tool-specific)
- `anti_analysis_detect` (tool-specific)
- `trace_entropy` (tool-specific)
- `api_sequence` (tool-specific)
- `loop_analysis` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

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
