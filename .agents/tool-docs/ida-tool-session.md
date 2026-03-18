# IDA MCP Tool Doc: `session`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `session` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Session lifecycle + runtime context hub. Actions: discover/create/get/list/switch/close/status/rebuild/update/rename/duplicate/export/import/archive/tag/note/stats/validate/snapshot/merge/macros/recent_workset. IDB is optional: after create/switch, tools use active session. If provided, idb accepts session ID, SID_* IDB id, binary path, or full IDB path.

## Actions
- `discover` (tool-specific)
- `create` (write/mutate)
- `get` (read/discovery)
- `list` (read/discovery)
- `switch` (tool-specific)
- `close` (destructive)
- `status` (read/discovery)
- `rebuild` (tool-specific)
- `update` (tool-specific)
- `rename` (write/mutate)
- `duplicate` (tool-specific)
- `export_session` (tool-specific)
- `import_session` (tool-specific)
- `archive` (tool-specific)
- `unarchive` (tool-specific)
- `tag` (tool-specific)
- `untag` (tool-specific)
- `find_by_tag` (tool-specific)
- `add_note` (tool-specific)
- `clear_notes` (tool-specific)
- `cleanup_stale` (tool-specific)
- `stats` (tool-specific)
- `validate` (tool-specific)
- `bulk_delete` (tool-specific)
- `bulk_tag` (tool-specific)
- `search_notes` (tool-specific)
- `recent` (tool-specific)
- `oldest` (tool-specific)
- `snapshot` (tool-specific)
- `restore_snapshot` (tool-specific)
- `merge` (tool-specific)
- `macro_set` (tool-specific)
- `macro_get` (tool-specific)
- `macro_list` (tool-specific)
- `macro_delete` (tool-specific)
- `macro_run` (tool-specific)
- `recent_workset` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/session')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `37`
- `aggressive_cleanup`: `boolean`
- `analysis_actions`: `array`
- `analysis_options`: `object` - Advanced analysis options payload
- `apply_once`: `boolean`
- `backup_on_recover`: `boolean`
- `baseaddr`: `string|integer`
- `binary_path`: `string` - Path to target binary
- `bitness`: `integer`
- `data`: `object` - Macro payload for macro_set.
- `end`: `string|integer`
- `endian`: `string`
- `flags`: `integer`
- `force_new`: `boolean` - Force creation of a new session even if one exists
- `ida_args`: `string|array`
- `idb_path`: `string` - Existing IDB path (alias of use_existing)
- `include_bookmarks`: `boolean` - Include bookmark entries in recent_workset.
- `include_items`: `boolean` - Include structured items in recent_workset response.
- `limit`: `integer` - Max sessions to return (list action)
- `loader`: `string`
- `loader_options`: `string|object`
- `macro`: `string` - Alias for macro name in macro_* actions.
- `macro_data`: `object` - Alias for macro payload in macro_set.
- `max_ea`: `string|integer`
- `min_ea`: `string|integer`
- `n`: `integer` - Count for recent/oldest/recent_workset actions.
- `name`: `string` - Name for macro_* actions or rename action.
- `notes`: `string` - Free-form notes for the session (create action).
- `offset`: `integer` - Skip first N sessions (list action)
- `options`: `object`
- `processor`: `string`
- `query`: `string` - Filter sessions by name/path (supports regex, glob, substring)
- `reanalyze`: `boolean`
- `recover`: `boolean`
- `run_action`: `string` - Session action to execute for macro_run (default from macro or create).
- `session_id`: `string` - Session ID for switch/close
- `start`: `string|integer`
- `start_ea`: `string|integer`
- `tags`: `array|string` - Tags for the session (create action). Comma-separated string or array.
- `use_existing`: `string` - Existing IDB path to reuse
- `value`: `string|object`

## Minimal Call Shapes
```json
{
  "name": "session",
  "arguments": {
    "action": "discover"
  }
}
```
```json
{
  "name": "session",
  "arguments": {
    "action": "grep",
    "source_action": "discover",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
