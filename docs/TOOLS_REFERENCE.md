# MCP Tools Reference

Generated from `ida_mcp_stdio.py` (`TOOLS`, `TOOL_ACTIONS`, `build_input_schema`).

Notes:
- `session(action="create")` requires `binary_path` and does not accept `idb_path`/`use_existing`.
- For non-session tools, `idb` is optional; active session is used when omitted.
- `tools/list` now defaults to full descriptions + full input schemas for direct LLM consumption.

## session

### Actions
- `discover`
- `create`
- `get`
- `list`
- `switch`
- `close`
- `status`
- `rebuild`
- `update`
- `rename`
- `duplicate`
- `export_session`
- `import_session`
- `archive`
- `unarchive`
- `tag`
- `untag`
- `find_by_tag`
- `add_note`
- `clear_notes`
- `cleanup_stale`
- `stats`
- `validate`
- `bulk_delete`
- `bulk_tag`
- `search_notes`
- `recent`
- `oldest`
- `snapshot`
- `restore_snapshot`
- `merge`
- `macro_set`
- `macro_get`
- `macro_list`
- `macro_delete`
- `macro_run`
- `recent_workset`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum_count: 42)
- `aggressive_cleanup`: boolean
- `analysis_actions`: array
- `analysis_options`: object — Advanced analysis options payload
- `apply_once`: boolean
- `backup_on_recover`: boolean
- `baseaddr`: ['string', 'integer']
- `binary_path`: string — Path to target binary
- `bitness`: integer
- `cursor`: string
- `data`: object — Macro payload for macro_set.
- `end`: ['string', 'integer']
- `endian`: string
- `flags`: integer
- `force_new`: boolean — Force creation of a new session even if one exists
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `ida_args`: ['string', 'array']
- `include_bookmarks`: boolean — Include bookmark entries in recent_workset.
- `include_items`: boolean — Include structured items in recent_workset response.
- `limit`: integer — Max sessions to return (list action)
- `loader`: string
- `loader_options`: ['string', 'object']
- `macro`: string — Alias for macro name in macro_* actions.
- `macro_data`: object — Alias for macro payload in macro_set.
- `max_ea`: ['string', 'integer']
- `min_ea`: ['string', 'integer']
- `n`: integer — Count for recent/oldest/recent_workset actions.
- `name`: string — Name for macro_* actions or rename action.
- `next_token`: string
- `notes`: string — Free-form notes for the session (create action).
- `offset`: integer — Skip first N sessions (list action)
- `on`: string
- `options`: object
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `processor`: string
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string — Filter sessions by name/path (supports regex, glob, substring)
- `reanalyze`: boolean
- `recover`: boolean
- `run_action`: string — Session action to execute for macro_run (default from macro or create).
- `session_id`: string — Session ID for switch/close
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: ['string', 'integer']
- `start_ea`: ['string', 'integer']
- `stats_include_payload`: boolean
- `subaction`: string
- `tags`: ['array', 'string'] — Tags for the session (create action). Comma-separated string or array.
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `value`: ['string', 'object']

## truncation

### Actions
- `continue`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: continue, grep, pick, head, tail, next, stats)
- `count`: integer
- `cursor`: string
- `field`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## bookmarks

### Actions
- `add`
- `list`
- `delete`
- `update`
- `clear`
- `find`
- `export`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: add, list, delete, update, clear, find, export, grep, pick, head, tail, next, stats)
- `addr`: string
- `category`: string
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `id`: integer
- `name`: string
- `next_token`: string
- `notes`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `priority`: integer
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tags`: ['array', 'string']
- `tail_n`: integer
- `target_action`: string
- `token`: string

## batch

### Actions
- `run`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `calls`: array
- `continue_on_error`: boolean

## analysis

### Actions
- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, grep, pick, head, tail, next, stats)
- `bitness`: integer
- `cursor`: string
- `end`: string
- `endian`: string
- `flags`: integer
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `loader`: string
- `next_token`: string
- `on`: string
- `options`: object
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `processor`: string
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: string
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `value`: ['string', 'object']

## query

### Actions
- `data`
- `search`
- `idb`
- `code`
- `types`
- `imports_deep`
- `symbols`
- `patterns`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: data, search, idb, code, types, imports_deep, symbols, patterns, grep, pick, head, tail, next, stats)
- `args`: object
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## edit

### Actions
- `rename`
- `comment`
- `type`
- `patch`
- `create_func`
- `bulk`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: rename, comment, type, patch, create_func, bulk, grep, pick, head, tail, next, stats)
- `args`: object
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## idb

### Actions
- `meta`
- `summary`
- `segments`
- `entrypoints`
- `bookmarks`
- `overview`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: meta, summary, segments, entrypoints, bookmarks, overview, grep, pick, head, tail, next, stats)
- `count`: integer
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## code

### Actions
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

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func, grep, pick, head, tail, next, stats)
- `addr`: string
- `addrs`: ['array', 'string']
- `cursor`: string
- `disasm_style`: string (enum: csmini, classic, annotated)
- `end`: string
- `field_name`: string
- `format`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_bytes`: boolean
- `limit`: integer
- `max_depth`: integer
- `max_items`: integer
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target`: string
- `target_action`: string
- `token`: string

## data

### Actions
- `functions`
- `globals`
- `strings`
- `imports`
- `exports`
- `lookup`
- `bulk_query`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: functions, globals, strings, imports, exports, lookup, bulk_query, grep, pick, head, tail, next, stats)
- `count`: integer
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_prototype`: boolean
- `include_xrefs`: boolean
- `items`: array
- `min_size`: integer
- `named_only`: boolean
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## search

### Actions
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

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum_count: 25)
- `addr`: string
- `case_sensitive`: boolean
- `cursor`: string
- `end`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_breakdown`: boolean
- `include_context`: boolean
- `include_items`: boolean
- `limit`: integer
- `max_functions`: integer
- `next_token`: string
- `offset`: integer
- `on`: string
- `pattern`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `sample`: boolean
- `sample_max_funcs`: integer
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: string
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `timeout_ms`: integer
- `token`: string

## types

### Actions
- `list`
- `get`
- `set_prototype`
- `parse_decl`
- `declare`
- `apply`
- `search_structs`
- `infer`
- `read_struct`
- `import_header`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## memory

### Actions
- `read`
- `write`
- `hexdump`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: read, write, hexdump, grep, pick, head, tail, next, stats)
- `addr`: string
- `cursor`: string
- `data`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `size`: integer
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `type`: string (enum: bytes, u8, u16, u32, u64, s8, s16, s32, s64, f32, f64, ptr, string)

## modify

### Actions
- `rename`
- `comment`
- `set_type`
- `patch_asm`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: rename, comment, set_type, patch_asm, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## funcs

### Actions
- `create`
- `delete`
- `set_flags`
- `set_name`
- `rename`
- `add_comment`
- `list`
- `info`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: create, delete, set_flags, set_name, rename, add_comment, list, info, grep, pick, head, tail, next, stats)
- `addr`: string
- `comment`: string
- `count`: integer
- `cursor`: string
- `end`: string
- `flags`: integer
- `force`: boolean
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_items`: boolean
- `include_prototype`: boolean
- `include_stack`: boolean
- `include_xrefs`: boolean
- `name`: string
- `named_only`: boolean
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `repeatable`: boolean
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## segments

### Actions
- `list`
- `add`
- `delete`
- `set_attr`
- `set_perms`
- `move`
- `info`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: list, add, delete, set_attr, set_perms, move, info, grep, pick, head, tail, next, stats)
- `attr`: string
- `count`: integer
- `cursor`: string
- `end`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `name`: string
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `sclass`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: string
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `value`: ['string', 'integer']

## bulk

### Actions
- `rename`
- `comment`
- `apply_type`
- `rename_stack`
- `import_annotations`
- `export_annotations`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: rename, comment, apply_type, rename_stack, import_annotations, export_annotations, grep, pick, head, tail, next, stats)
- `continue_on_error`: boolean
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `items`: array
- `next_token`: string
- `on`: string
- `path`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## misc

### Actions
- `python`
- `idc`
- `load_sig`
- `cache_stats`
- `read_file`
- `write_file`
- `plugin_list`
- `plugin_run`
- `health`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health, grep, pick, head, tail, next, stats)
- `arg`: integer — Plugin argument for plugin_run
- `code`: string — Multi-line Python code to execute
- `content`: string — Content to write for write_file
- `cursor`: string
- `encoding`: string — File encoding (default: utf-8). Use 'binary' for hex-encoded binary data.
- `expr`: string — Python expression or IDC script to evaluate
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `name`: string — Signature name for load_sig
- `next_token`: string
- `on`: string
- `path`: string — File path for read_file/write_file
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `verbose`: boolean — Include per-runtime details for health action.

## plugins

### Actions
- `list`
- `run`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: list, run, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## calc

### Actions
- `eval`
- `offset`
- `convert`
- `resolve`
- `deref`
- `chain`
- `align`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: eval, offset, convert, resolve, deref, chain, align, grep, pick, head, tail, next, stats)
- `addr`: string
- `cursor`: string
- `expr`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `offsets`: ['array', 'string']
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `size`: integer
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target`: string
- `target_action`: string
- `token`: string
- `type`: string
- `value`: ['string', 'integer']

## nav

### Actions
- `goto`
- `cursor`
- `interesting`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: goto, cursor, interesting, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## debug

### Actions
- `start`
- `stop`
- `continue`
- `step_into`
- `step_over`
- `run_to`
- `run_until`
- `breakpoints`
- `add_bp`
- `del_bp`
- `enable_bp`
- `regs`
- `set_reg`
- `threads`
- `modules`
- `callstack`
- `read_mem`
- `write_mem`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum_count: 24)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## trace

### Actions
- `get`
- `clear`
- `set_options`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: get, clear, set_options, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## coverage

### Actions
- `import_drcov`
- `import_lighthouse`
- `highlight`
- `report`
- `uncovered`
- `filter`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: import_drcov, import_lighthouse, highlight, report, uncovered, filter, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## trace_analysis

### Actions
- `import_trace`
- `analyze_coverage`
- `find_loops`
- `extract_api_calls`
- `basic_blocks_hit`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## project

### Actions
- `save`
- `close`
- `open`
- `load_binary`
- `list_recent`
- `get_cwd`
- `set_cwd`
- `list_dir`
- `exists`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## agent

### Actions
- `analyze_function`
- `explore_address`
- `find_references`
- `search_all`
- `search_structs`
- `context_pack`
- `quick`
- `rename_suggestions`
- `batch_context`
- `similar`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar, grep, pick, head, tail, next, stats)
- `addr`: string
- `cursor`: string
- `depth`: integer
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_pseudocode`: boolean
- `max_items`: integer
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `use_cache`: boolean

## microcode

### Actions
- `get`
- `blocks`
- `instructions`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: get, blocks, instructions, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## graph

### Actions
- `callgraph`
- `cfg`
- `xref_graph`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: callgraph, cfg, xref_graph, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## ctree

### Actions
- `get`
- `traverse`
- `find_calls`
- `find_vars`
- `find_strings`
- `find_conditions`
- `get_logic_flow`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, grep, pick, head, tail, next, stats)
- `addr`: string
- `cursor`: string
- `depth`: integer
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## taint

### Actions
- `find_arg_usage`
- `trace_return`
- `find_sinks`
- `data_flow`
- `backward_trace`
- `slice`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice, grep, pick, head, tail, next, stats)
- `addr`: string
- `arg_num`: integer
- `cursor`: string
- `depth`: integer
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `max_hits`: integer
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## emulate

### Actions
- `static_trace`
- `appcall`
- `decrypt_strings`
- `eval_expr`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: static_trace, appcall, decrypt_strings, eval_expr, grep, pick, head, tail, next, stats)
- `addr`: string
- `args`: array
- `cursor`: string
- `expr`: string
- `follow_calls`: boolean
- `func_name`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_blocks`: boolean
- `max_depth`: integer
- `max_steps`: integer
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## entropy

### Actions
- `section`
- `region`
- `packed_detect`
- `crypto_detect`
- `compare`
- `window`
- `summary`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: section, region, packed_detect, crypto_detect, compare, window, summary, grep, pick, head, tail, next, stats)
- `addr`: string
- `cursor`: string
- `end_addr`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `limit`: integer
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `size`: integer
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `step`: integer
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `threshold`: number
- `token`: string
- `window`: integer

## structs

### Actions
- `recover`
- `analyze_usage`
- `list`
- `create`
- `add_member`
- `apply`
- `reconstruct_vtable`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## imports_deep

### Actions
- `thunks`
- `delay`
- `forwarded`
- `ordinal`
- `api_sets`
- `resolve`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: thunks, delay, forwarded, ordinal, api_sets, resolve, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## patterns

### Actions
- `generate`
- `match`
- `list_sigs`
- `apply_sig`
- `create_sig`
- `matched`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: generate, match, list_sigs, apply_sig, create_sig, matched, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## symbols

### Actions
- `load_pdb`
- `load_dwarf`
- `status`
- `apply`
- `export`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: load_pdb, load_dwarf, status, apply, export, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## diff

### Actions
- `functions`
- `bytes`
- `signatures`
- `summary`
- `export_binexport`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: functions, bytes, signatures, summary, export_binexport, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## lumina

### Actions
- `pull`
- `push`
- `status`
- `history`
- `search`
- `get_metadata`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: pull, push, status, history, search, get_metadata, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## export

### Actions
- `listing`
- `html`
- `idc`
- `json`
- `binexport`
- `headers`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: listing, html, idc, json, binexport, headers, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## history

### Actions
- `undo`
- `redo`
- `list`
- `snapshot`
- `restore`
- `diff`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: undo, redo, list, snapshot, restore, diff, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## comments_ai

### Actions
- `get_context`
- `set_structured`
- `bulk_set`
- `export_md`
- `import_md`
- `summary`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: get_context, set_structured, bulk_set, export_md, import_md, summary, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## colorize

### Actions
- `set_func`
- `set_range`
- `set_insn`
- `get`
- `clear`
- `palette`
- `highlight_pattern`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: set_func, set_range, set_insn, get, clear, palette, highlight_pattern, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## data_ops

### Actions
- `make_data`
- `make_array`
- `make_string`
- `undefine`
- `make_code`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: make_data, make_array, make_string, undefine, make_code, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## fixups

### Actions
- `list`
- `get`
- `add`
- `delete`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: list, get, add, delete, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## hooks

### Actions
- `suggest`
- `generate_frida`
- `generate_detours`
- `find_targets`
- `inline_hooks`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: suggest, generate_frida, generate_detours, find_targets, inline_hooks, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## wiki

### Actions
- `list_topics`
- `read`
- `search`
- `semantic_search`
- `sections`
- `index`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: list_topics, read, search, semantic_search, sections, index, grep, pick, head, tail, next, stats)
- `category`: ['string', 'array']
- `context_lines`: integer
- `cursor`: string
- `fuzzy`: boolean
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `include_related`: boolean
- `include_snippets`: boolean
- `limit`: integer
- `line_end`: integer
- `line_start`: integer
- `lines`: string — Line selector such as '10-40', '25', '10-', or '-40'.
- `max_results`: integer
- `next_token`: string
- `offset`: integer
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `query`: string
- `section`: string
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `strict_topic`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
- `topic`: string
- `verbose`: boolean — Include full structural metadata in wiki responses.

## yara_hunt

### Actions
- `scan`
- `compile`
- `list_rules`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: scan, compile, list_rules, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## vuln_scan

### Actions
- `buffer_overflow`
- `format_string`
- `integer_overflow`
- `use_after_free`
- `command_injection`
- `race_condition`
- `null_deref`
- `info_leak`
- `auth_bypass`
- `hardcoded_creds`
- `scan_all`
- `classify`
- `osv_query`
- `intelligence_report`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify, osv_query, intelligence_report, grep, pick, head, tail, next, stats)
- `addr`: string — Address or function scope for scanning.
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_context`: boolean — Include compact decompiled context when available.
- `include_dataflow_graph`: boolean — Include compact correlation graph in scan_all/intelligence_report.
- `include_remediation_plan`: boolean — Include prioritized remediation plan in scan_all/intelligence_report.
- `limit`: integer — Max findings to return (capped for context safety).
- `max_graph_depth`: integer — Correlation graph depth (0-3) for intelligence outputs.
- `next_token`: string
- `offset`: integer — Skip first N ranked findings.
- `on`: string
- `osv_coordinates`: array — OSV package coordinates (ecosystem:name@version or pkg:purl). Used by osv_query and optional scan_all enrichment.
- `osv_ecosystem`: string — Default OSV ecosystem for shorthand coordinates like name@version.
- `osv_endpoint`: string — OSV endpoint/base URL (default: https://api.osv.dev).
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `scan_profile`: string (enum: quick, balanced, deep) — Scan depth profile controlling local evidence/ranking rigor.
- `severity`: string (enum: critical, high, medium, low) — Optional severity filter.
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## gadgets

### Actions
- `rop`
- `jop`
- `cop`
- `syscall`
- `write_what_where`
- `stack_pivot`
- `shellcode_space`
- `mitigations`
- `seh_handlers`
- `pivot_chains`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## c2_detect

### Actions
- `indicators`
- `persistence`
- `evasion`
- `injection`
- `exfiltration`
- `lateral_movement`
- `privilege_escalation`
- `capabilities`
- `config_extract`
- `ioc_extract`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: indicators, persistence, evasion, injection, exfiltration, lateral_movement, privilege_escalation, capabilities, config_extract, ioc_extract, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## deobfuscate

### Actions
- `detect_encoding`
- `xor_scan`
- `stack_strings`
- `opaque_predicates`
- `control_flow_flatten`
- `dead_code`
- `api_hashing`
- `dynamic_dispatch`
- `anti_disasm`
- `decode_attempt`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: detect_encoding, xor_scan, stack_strings, opaque_predicates, control_flow_flatten, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## crypto_id

### Actions
- `identify`
- `constants`
- `key_schedule`
- `block_cipher`
- `hash_detect`
- `rng_detect`
- `asymmetric`
- `custom_crypto`
- `encoding`
- `checksums`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: identify, constants, key_schedule, block_cipher, hash_detect, rng_detect, asymmetric, custom_crypto, encoding, checksums, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## abi

### Actions
- `detect`
- `stack_args`
- `reg_args`
- `return_type`
- `varargs`
- `struct_return`
- `tail_calls`
- `prologue`
- `epilogue`
- `abi_violations`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## summarize

### Actions
- `binary`
- `function`
- `segment`
- `imports_by_category`
- `strings_by_category`
- `complexity`
- `call_hierarchy`
- `data_flow`
- `security_posture`
- `statistics`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## classify

### Actions
- `function`
- `binary`
- `all_functions`
- `library_code`
- `wrappers`
- `callbacks`
- `initializers`
- `error_handlers`
- `hot_functions`
- `orphans`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: function, binary, all_functions, library_code, wrappers, callbacks, initializers, error_handlers, hot_functions, orphans, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## compare

### Actions
- `functions`
- `blocks`
- `apis`
- `strings`
- `constants`
- `structure`
- `semantics`
- `batch_compare`
- `find_clones`
- `changelog`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: functions, blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## stack_analysis

### Actions
- `frame`
- `buffers`
- `canary`
- `alignment`
- `spills`
- `usage`
- `variables`
- `arrays`
- `uninitialized`
- `summary`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## protocol

### Actions
- `detect`
- `parsers`
- `serializers`
- `handlers`
- `endpoints`
- `tls_config`
- `socket_flow`
- `packet_struct`
- `magic_numbers`
- `state_machine`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## annotation

### Actions
- `auto_comment`
- `label_loops`
- `label_branches`
- `mark_dangerous`
- `annotate_constants`
- `tag_functions`
- `document_args`
- `mark_error_paths`
- `propagate_names`
- `cleanup`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: auto_comment, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## xref_analysis

### Actions
- `call_chain`
- `common_callers`
- `common_callees`
- `hub_functions`
- `leaf_functions`
- `recursive`
- `dominator`
- `influence`
- `dependency_graph`
- `dead_functions`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## xfer_analysis

### Actions
- `call_chain`
- `common_callers`
- `common_callees`
- `hub_functions`
- `leaf_functions`
- `recursive`
- `dominator`
- `influence`
- `dependency_graph`
- `dead_functions`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## string_ops

### Actions
- `decode_all`
- `find_urls`
- `find_paths`
- `find_registry`
- `find_ips`
- `find_emails`
- `find_commands`
- `encoding_stats`
- `multilingual`
- `suspicious`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: decode_all, find_urls, find_paths, find_registry, find_ips, find_emails, find_commands, encoding_stats, multilingual, suspicious, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## cfg_analysis

### Actions
- `complexity`
- `loops`
- `branches`
- `paths`
- `dominators`
- `post_dominators`
- `back_edges`
- `natural_loops`
- `irreducible`
- `flatten_detect`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## binary_info

### Actions
- `headers`
- `sections`
- `relocations`
- `resources`
- `debug_info`
- `compiler`
- `linker`
- `timestamps`
- `checksums`
- `overlay`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string

## llm_helpers

### Actions
- `context_window`
- `function_digest`
- `binary_digest`
- `explain_address`
- `suggest_next`
- `progress_report`
- `focus_area`
- `question_answer`
- `guided_analysis`
- `cheatsheet`

### Args
- `_compact`: boolean — Shortcut for compact/full mode toggle.
- `_error_details`: string (enum: none, basic, full) — Controls verbosity of error details.
- `_qol_mode`: string (enum: tiny, balanced, debug) — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: boolean — Compact batch envelopes in compact mode.
- `_response_char_budget`: integer — Approximate max output chars before truncation middleware applies.
- `_response_fields`: ['array', 'string'] — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: integer — Max list items retained in compact mode.
- `_response_max_string`: integer — Max string length retained in compact mode.
- `_response_mode`: string (enum: compact, full) — Output mode. compact is default and reduces token usage.
- `_response_omit`: ['array', 'string'] — Optional top-level field omission list.
- `_response_table`: boolean — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: string (enum: context_window, function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet, grep, pick, head, tail, next, stats)
- `cursor`: string
- `grep`: string — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: boolean
- `grep_field`: string — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: boolean
- `grep_limit`: integer
- `grep_offset`: integer
- `grep_pattern`: string
- `grep_regex`: boolean
- `head_n`: integer
- `idb`: string — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `next_token`: string
- `on`: string
- `pick_fields`: ['array', 'string'] — For action='pick': top-level fields to include.
- `pick_omit`: ['array', 'string'] — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: string (enum: tiny, balanced, debug)
- `source_action`: string — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: boolean
- `subaction`: string
- `tail_n`: integer
- `target_action`: string
- `token`: string
