# IDA MCP Tool Doc: `classify`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `classify` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Classify functions and binaries by purpose. function: single function — embedding-driven BehaviorClassifier (bge-code-v1). binary: overall binary type. all_functions: classify all functions — unnamed functions use BehaviorClassifier. library_code/wrappers/callbacks/initializers/error_handlers: structural classification. hot_functions: most-called functions. orphans: no-caller functions (entry points / dead code). induce_schema: SchemaBoot attribute-value schema for structured retrieval. anchor_coverage: report per-anchor coverage over current IDB. NOTE: the binary and function actions share names with summarize.binary / summarize.function but produce DIFFERENT output — classify returns categories/behavior tags, summarize returns counts/structure. Pick the one that matches the question.

## Actions
- `function` (tool-specific)
- `binary` (tool-specific)
- `all_functions` (tool-specific)
- `library_code` (tool-specific)
- `wrappers` (tool-specific)
- `callbacks` (tool-specific)
- `initializers` (tool-specific)
- `error_handlers` (tool-specific)
- `hot_functions` (tool-specific)
- `orphans` (tool-specific)
- `induce_schema` (tool-specific)
- `anchor_coverage` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/classify')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "classify",
  "arguments": {
    "action": "function"
  }
}
```
```json
{
  "name": "classify",
  "arguments": {
    "action": "grep",
    "source_action": "function",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
