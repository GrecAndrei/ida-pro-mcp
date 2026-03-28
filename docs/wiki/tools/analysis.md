# ANALYSIS Tool Manual

## What It Does
Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.

## Actions
- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`

## Parameters
- `_compact`: `boolean` — Shortcut for compact/full mode toggle.
- `_error_details`: `string`; allowed: `none, basic, full` — Controls verbosity of error details.
- `_qol_mode`: `string`; allowed: `tiny, balanced, debug` — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: `boolean` — Compact batch envelopes in compact mode.
- `_response_char_budget`: `integer` — Approximate max output chars before truncation middleware applies.
- `_response_fields`: `array | string` — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: `integer` — Max list items retained in compact mode.
- `_response_max_string`: `integer` — Max string length retained in compact mode.
- `_response_mode`: `string`; allowed: `compact, full` — Output mode. compact is default and reduces token usage.
- `_response_omit`: `array | string` — Optional top-level field omission list.
- `_response_table`: `boolean` — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: `string`; allowed: `get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, grep, pick, head, tail, next, stats`
- `bitness`: `integer`
- `cursor`: `string`
- `end`: `string`
- `endian`: `string`
- `flags`: `integer`
- `grep`: `string` — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: `boolean`
- `grep_field`: `string` — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: `boolean`
- `grep_limit`: `integer`
- `grep_offset`: `integer`
- `grep_pattern`: `string`
- `grep_regex`: `boolean`
- `head_n`: `integer`
- `idb`: `string` — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `loader`: `string`
- `next_token`: `string`
- `on`: `string`
- `options`: `object`
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `processor`: `string`
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: `string`
- `stats_include_payload`: `boolean`
- `subaction`: `string`
- `tail_n`: `integer`
- `target_action`: `string`
- `token`: `string`
- `value`: `string | object`

## Example
```json
{
  "name": "analysis",
  "arguments": {
    "action": "get_options"
  }
}
```

## Notes
- `idb` is optional for most tools and resolves from active session when omitted.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
