# IDA MCP Tool Doc: `search`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `search` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Pattern and reference search. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref, regex, func_by_sig, find, callers, callees, api, vulnerable, constants, decompiled. Supports case_sensitive, include_context. Pattern auto-detects regex (e.g. mov.*eax$, \bfoo\b), glob, or plain substring.

## Actions
- `bytes` (tool-specific)
- `string` (tool-specific)
- `immediate` (tool-specific)
- `name` (tool-specific)
- `insns` (tool-specific)
- `text` (tool-specific)
- `operand` (tool-specific)
- `comment` (tool-specific)
- `data_ref` (tool-specific)
- `code_ref` (tool-specific)
- `regex` (tool-specific)
- `func_by_sig` (tool-specific)
- `find` (tool-specific)
- `callers` (tool-specific)
- `callees` (tool-specific)
- `api` (tool-specific)
- `vulnerable` (tool-specific)
- `constants` (tool-specific)
- `decompiled` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/search')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `19`
- `addr`: `string`
- `case_sensitive`: `boolean`
- `end`: `string`
- `include_breakdown`: `boolean`
- `include_context`: `boolean`
- `include_items`: `boolean`
- `limit`: `integer`
- `max_functions`: `integer`
- `offset`: `integer`
- `pattern`: `string`
- `query`: `string`
- `sample`: `boolean`
- `sample_max_funcs`: `integer`
- `start`: `string`
- `timeout_ms`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "search",
  "arguments": {
    "action": "bytes"
  }
}
```
```json
{
  "name": "search",
  "arguments": {
    "action": "grep",
    "source_action": "bytes",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
