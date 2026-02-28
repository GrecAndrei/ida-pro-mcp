# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`search`

## Use This Skill When
- You need to call the `search` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- `action`: `string` - allowed_count: `19`
- `case_sensitive`: `boolean`
- `end`: `string`
- `include_context`: `boolean`
- `limit`: `integer`
- `offset`: `integer`
- `pattern`: `string`
- `query`: `string`
- `start`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
