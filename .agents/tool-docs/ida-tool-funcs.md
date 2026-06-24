# IDA MCP Tool Doc: `funcs`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `funcs` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Function boundary management (≈ IDA P/Delete keys). create: define a function at addr (≡ pressing P in IDA). delete: remove function definition. info: full function metadata — pass include_xrefs/include_prototype/include_stack for richer output. metrics: size/complexity/call counts. find_similar: structural similarity search. suggest_names: name candidates from heuristics. Note: regex-based filters live in search, while renames and comments live on modify; listings on code. Actions: create, delete, set_flags, info, metrics, find_similar, suggest_names.

## Actions
- `create` (write/mutate)
- `delete` (destructive)
- `set_flags` (write/mutate)
- `info` (read/discovery)
- `metrics` (tool-specific)
- `find_similar` (tool-specific)
- `suggest_names` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/funcs')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `create, delete, set_flags, info, metrics, find_similar, suggest_names`
- `addr`: `string`
- `comment`: `string`
- `count`: `integer`
- `ea`: `string`
- `end`: `string`
- `end_ea`: `string`
- `flags`: `integer`
- `force`: `boolean`
- `function`: `string`
- `include_items`: `boolean`
- `include_prototype`: `boolean`
- `include_stack`: `boolean`
- `include_xrefs`: `boolean`
- `limit`: `integer`
- `min_score`: `number`
- `name`: `string`
- `named_only`: `boolean`
- `offset`: `integer`
- `query`: `string`
- `repeatable`: `boolean`
- `start`: `string`
- `stop`: `string`
- `target`: `string`
- `threshold`: `number`
- `top_k`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "funcs",
  "arguments": {
    "action": "create"
  }
}
```
```json
{
  "name": "funcs",
  "arguments": {
    "action": "grep",
    "source_action": "create",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
