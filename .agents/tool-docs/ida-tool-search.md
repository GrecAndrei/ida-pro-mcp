# IDA MCP Tool Doc: `search`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `search` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Pattern and reference search. Actions: bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref, regex, func_by_sig, find, callers, callees, api, vulnerable, constants, decompiled. Supports case_sensitive, include_context. Pattern auto-detects regex (e.g. mov.*eax$, \bfoo\b), glob, or plain substring.

## Actions
- `bytes`
- `string`
- `immediate`
- `name`
- `insns`
- `text`
- `operand`
- `comment`
- `data_ref`
- `code_ref`
- `regex`
- `func_by_sig`
- `find`
- `callers`
- `callees`
- `api`
- `vulnerable`
- `constants`
- `decompiled`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed_count: `19`
- `case_sensitive`: `boolean`
- `end`: `string`
- `include_breakdown`: `boolean`
- `include_context`: `boolean`
- `include_items`: `boolean`
- `limit`: `integer`
- `offset`: `integer`
- `pattern`: `string`
- `query`: `string`
- `start`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
