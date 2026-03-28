# WIKI Tool Manual

## What It Does
Built-in documentation system with ranked and semantic search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs. Actions: list_topics, read, search, semantic_search, sections, index.

## Actions
- `list_topics`
- `read`
- `search`
- `semantic_search`
- `sections`
- `index`

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
- `action`: `string`; allowed: `list_topics, read, search, semantic_search, sections, index, grep, pick, head, tail, next, stats`
- `category`: `string | array`
- `context_lines`: `integer`
- `cursor`: `string`
- `fuzzy`: `boolean`
- `grep`: `string` — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: `boolean`
- `grep_field`: `string` — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: `boolean`
- `grep_limit`: `integer`
- `grep_offset`: `integer`
- `grep_pattern`: `string`
- `grep_regex`: `boolean`
- `head_n`: `integer`
- `include_related`: `boolean`
- `include_snippets`: `boolean`
- `limit`: `integer`
- `line_end`: `integer`
- `line_start`: `integer`
- `lines`: `string` — Line selector such as '10-40', '25', '10-', or '-40'.
- `max_results`: `integer`
- `next_token`: `string`
- `offset`: `integer`
- `on`: `string`
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `query`: `string`
- `section`: `string`
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: `boolean`
- `strict_topic`: `boolean`
- `subaction`: `string`
- `tail_n`: `integer`
- `target_action`: `string`
- `token`: `string`
- `topic`: `string`
- `verbose`: `boolean` — Include full structural metadata in wiki responses.

## Example
```json
{
  "name": "wiki",
  "arguments": {
    "action": "list_topics"
  }
}
```

## Notes
- `idb` is optional for most tools and resolves from active session when omitted.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
