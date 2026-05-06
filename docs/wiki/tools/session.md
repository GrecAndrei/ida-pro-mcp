# SESSION Tool Manual

## What It Does
Session lifecycle + runtime context hub. Actions: discover/create/get/list/switch/close/status/rebuild/update/rename/duplicate/export/import/archive/tag/note/stats/validate/snapshot/merge/macros/recent_workset. IDB is optional: after create/switch, tools use active session. If provided, idb accepts session ID, SID_* IDB id, binary path, or full IDB path.

## Actions
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
- `bootstrap_init`
- `bootstrap_run_tournament`
- `bootstrap_compute_blend`
- `bootstrap_status`
- `bootstrap_ingest_outcome`
- `bootstrap_open_dispute`
- `bootstrap_list_disputes`
- `bootstrap_resolve_dispute`
- `bootstrap_summary`
- `bootstrap_snapshot`
- `bootstrap_list_snapshots`
- `bootstrap_drift_report`
- `bootstrap_simulate_batch`
- `bootstrap_prune_data`
- `bootstrap_export_metrics`
- `bootstrap_summary_detailed`
- `bootstrap_calibration_report`
- `bootstrap_update_baseline`
- `bootstrap_evaluate_alerts`
- `bootstrap_mitigation_plan`
- `bootstrap_apply_mitigation`
- `bootstrap_mitigation_history`
- `bootstrap_mitigation_effectiveness`
- `bootstrap_policy_reweight`
- `bootstrap_policy_reweight_history`
- `bootstrap_autopilot`

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
- `action`: `string`; allowed_count: `69`
- `aggressive_cleanup`: `boolean`
- `analysis_actions`: `array`
- `analysis_options`: `object` — Advanced analysis options payload
- `apply_once`: `boolean`
- `backup_on_recover`: `boolean`
- `baseaddr`: `string | integer`
- `binary_path`: `string` — Path to target binary
- `bitness`: `integer`
- `cursor`: `string`
- `data`: `object` — Macro payload for macro_set.
- `end`: `string | integer`
- `endian`: `string`
- `flags`: `integer`
- `force_new`: `boolean` — Force creation of a new session even if one exists
- `grep`: `string` — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: `boolean`
- `grep_field`: `string` — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: `boolean`
- `grep_limit`: `integer`
- `grep_offset`: `integer`
- `grep_pattern`: `string`
- `grep_regex`: `boolean`
- `head_n`: `integer`
- `ida_args`: `string | array`
- `include_bookmarks`: `boolean` — Include bookmark entries in recent_workset.
- `include_items`: `boolean` — Include structured items in recent_workset response.
- `limit`: `integer` — Max sessions to return (list action)
- `loader`: `string`
- `loader_options`: `string | object`
- `macro`: `string` — Alias for macro name in macro_* actions.
- `macro_data`: `object` — Alias for macro payload in macro_set.
- `max_ea`: `string | integer`
- `min_ea`: `string | integer`
- `n`: `integer` — Count for recent/oldest/recent_workset actions.
- `name`: `string` — Name for macro_* actions or rename action.
- `next_token`: `string`
- `note`: `string` — Single note payload for add_note action.
- `notes`: `string` — Free-form notes for the session (create action).
- `offset`: `integer` — Skip first N sessions (list action)
- `on`: `string`
- `options`: `object`
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `processor`: `string`
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `query`: `string` — Filter sessions by name/path (supports regex, glob, substring)
- `reanalyze`: `boolean`
- `recover`: `boolean`
- `run_action`: `string` — Session action to execute for macro_run (default from macro or create).
- `session_id`: `string` — Session ID for switch/close
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `start`: `string | integer`
- `start_ea`: `string | integer`
- `stats_include_payload`: `boolean`
- `subaction`: `string`
- `tags`: `array | string` — Tags for the session (create action). Comma-separated string or array.
- `tail_n`: `integer`
- `target_action`: `string`
- `token`: `string`
- `value`: `string | object`

## Example
```json
{
  "name": "session",
  "arguments": {
    "action": "discover"
  }
}
```

## Notes
- `create` requires `binary_path` and rejects `idb_path`/`use_existing`.
- High-noise action aliases are normalized (examples: `metrics` -> `stats`, `new` -> `create`, `clone` -> `duplicate`).
- High-noise argument aliases are normalized (examples: `id` -> `session_id`, `binary` -> `binary_path`, `label` -> `tag`, `save_macro` -> `macro_set` action alias route).
- Noisy wrapper payloads such as `[ABCD1234]` for `session_id` are tolerated where unambiguous.
- All responses include `llm_pointer_note` in ALL CAPS to reinforce calc/memory usage for address math.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
