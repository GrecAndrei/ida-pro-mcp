# IDA MCP Tool Doc: `taint`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `taint` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Data flow taint analysis from user-controlled sources to dangerous sinks. Actions: sources (list all taint sources: recv/read/fgets/getenv imports + blackboard IOCs), sinks (dangerous sinks reachable from a source), trace (trace forward from addr/source, write vuln entries to blackboard), paths (full call-graph paths source→sink with dataflow description), report (all sources → all reachable sinks). Example: taint(action='trace', source='recv') finds all paths from recv to memcpy/strcpy/system.

## Actions
- `sources` (tool-specific)
- `sinks` (tool-specific)
- `trace` (tool-specific)
- `paths` (tool-specific)
- `report` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/taint')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "taint",
  "arguments": {
    "action": "sources"
  }
}
```
```json
{
  "name": "taint",
  "arguments": {
    "action": "grep",
    "source_action": "sources",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
