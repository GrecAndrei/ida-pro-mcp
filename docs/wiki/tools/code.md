# CODE Tool Manual

## What It Does
Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.

## Actions
- `decompile`
- `disasm`
- `xrefs_to`
- `xrefs_from`
- `xrefs_to_field`
- `callees`
- `callers`
- `blocks`
- `analyze`
- `callgraph`
- `export`
- `find_paths`
- `strings_in_func`

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
- `action`: `string`; allowed_count: `19`
- `addr`: `string`
- `addrs`: `array | string`
- `cursor`: `string`
- `disasm_style`: `string`; allowed: `csmini, classic, annotated`
- `end`: `string`
- `field_name`: `string`
- `format`: `string`
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
- `include_bytes`: `boolean`
- `limit`: `integer`
- `max_depth`: `integer`
- `max_items`: `integer`
- `next_token`: `string`
- `on`: `string`
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: `boolean`
- `subaction`: `string`
- `tail_n`: `integer`
- `target`: `string`
- `target_action`: `string`
- `token`: `string`

## Example
```json
{
  "name": "code",
  "arguments": {
    "action": "decompile"
  }
}
```

## Notes
- `idb` is optional for most tools and resolves from active session when omitted.
- High-noise action aliases are normalized (examples: `assembly` -> `disasm`, `decompiled` -> `decompile`, `paths` -> `find_paths`).
- High-noise argument aliases are normalized (examples: `targets` -> `addrs`, `style` -> `disasm_style`, `address` -> `addr/addrs`).
- Wrapped and malformed address list values are tolerated where unambiguous (example: `[0x401000,0x401010]`).
- All responses include `llm_pointer_note` in ALL CAPS to reinforce calc/memory usage for address math.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
