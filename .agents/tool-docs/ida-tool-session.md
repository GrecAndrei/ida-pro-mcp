# IDA MCP Tool Doc: `session`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `session` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Session management. Actions: discover, create (auto-detects existing sessions for same binary or IDB, supports processor/bitness/endian/loader params, analysis_options, idb_path, ida_args, tags, notes, and force_new), get (single session lookup by ID with runtime status), list (supports limit/offset for pagination, query for regex/glob/substring filtering, includes runtime status), switch (by session_id or binary_path), close (PERMANENTLY DELETES session and all associated files including IDB), status (shows current session with runtime info), rebuild (recreate IDB with new analysis options and recovery controls), update (modify session fields), rename (set custom name), duplicate (clone session), export_session/import_session (portable metadata), archive/unarchive (archive management), tag/untag/find_by_tag (tagging), add_note/clear_notes (notes), cleanup_stale (remove old sessions), stats (session statistics), validate (check integrity), bulk_delete/bulk_tag (batch operations), search_notes (search across notes), recent/oldest (sorted access), snapshot/restore_snapshot (point-in-time snapshots), merge (combine session metadata). Once a session is created or switched, all other tools automatically use it without requiring the 'idb' parameter.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed_count: `31`
- `aggressive_cleanup`: `boolean`
- `analysis_actions`: `array`
- `analysis_options`: `object` - Advanced analysis options payload
- `apply_once`: `boolean`
- `backup_on_recover`: `boolean`
- `baseaddr`: `string|integer`
- `binary_path`: `string` - Path to target binary
- `bitness`: `integer`
- `end`: `string|integer`
- `endian`: `string`
- `flags`: `integer`
- `force_new`: `boolean` - Force creation of a new session even if one exists
- `ida_args`: `string|array`
- `idb_path`: `string` - Existing IDB path (alias of use_existing)
- `limit`: `integer` - Max sessions to return (list action)
- `loader`: `string`
- `loader_options`: `string|object`
- `max_ea`: `string|integer`
- `min_ea`: `string|integer`
- `notes`: `string` - Free-form notes for the session (create action).
- `offset`: `integer` - Skip first N sessions (list action)
- `options`: `object`
- `processor`: `string`
- `query`: `string` - Filter sessions by name/path (supports regex, glob, substring)
- `reanalyze`: `boolean`
- `recover`: `boolean`
- `session_id`: `string` - Session ID for switch/close
- `start`: `string|integer`
- `start_ea`: `string|integer`
- `tags`: `array|string` - Tags for the session (create action). Comma-separated string or array.
- `use_existing`: `string` - Existing IDB path to reuse
- `value`: `string|object`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
