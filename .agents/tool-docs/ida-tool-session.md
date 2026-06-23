# IDA MCP Tool Doc: `session`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `session` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Full session lifecycle with runtime tracking, analysis notebook, hypothesis tracking. Actions: create/switch/close/list/status, snapshot/restore, rate_skill/suggest_strategy/suggest_triage/suggest_analogy/apply_analogy, notebook_append/read, track_hypothesis/confirm/refute, get_phase/advance_phase, recent_workset, macro_set/run, dashboard, health. cleanup_stale: remove sessions older than max_age_days (default 30) — run this when sessions accumulate. health: server, runtime, IDA, session, wiki, and tool-surface diagnostics (verbose=true for per-runtime breakdown).

## Actions
- `health` (tool-specific)
- `create` (write/mutate)
- `discover` (tool-specific)
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
- `rate_skill` (tool-specific)
- `list_skills` (tool-specific)
- `suggest_strategy` (tool-specific)
- `suggest_triage` (tool-specific)
- `suggest_analogy` (tool-specific)
- `apply_analogy` (tool-specific)
- `log_activity` (tool-specific)
- `get_activity_log` (tool-specific)
- `notebook_append` (tool-specific)
- `notebook_read` (tool-specific)
- `notebook_section` (tool-specific)
- `track_hypothesis` (tool-specific)
- `confirm_hypothesis` (tool-specific)
- `refute_hypothesis` (tool-specific)
- `list_hypotheses` (tool-specific)
- `dashboard` (tool-specific)
- `get_phase` (tool-specific)
- `advance_phase` (tool-specific)
- `link_session` (tool-specific)
- `cross_reference_sessions` (tool-specific)
- `list_snapshots` (tool-specific)
- `macro_set` (tool-specific)
- `macro_get` (tool-specific)
- `macro_list` (tool-specific)
- `macro_delete` (tool-specific)
- `macro_run` (tool-specific)
- `recent_workset` (tool-specific)
- `kill` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/session')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `60`
- `aggressive_cleanup`: `boolean`
- `analysis_actions`: `array`
- `analysis_options`: `object` - Advanced analysis payload. Preferred for architecture/loader config at session creation.
- `apply_once`: `boolean`
- `architecture`: `object` - Canonical preload architecture block for create/update (processor, bitness, endian, loader, loader_options, flags).
- `backup_on_recover`: `boolean`
- `baseaddr`: `string|integer`
- `binary_path`: `string` - Path to target binary
- `bitness`: `integer` - Target bitness: 16, 32, or 64.
- `context`: `string` - Optional context search/intent string to compute novelty against.
- `data`: `object` - Macro payload for macro_set.
- `end`: `string|integer`
- `endian`: `string` - Target endianness: le/little or be/big.
- `flags`: `integer`
- `force_new`: `boolean` - Force creation of a new session even if one exists
- `ida_args`: `string|array`
- `include_bookmarks`: `boolean` - Include bookmark entries in recent_workset.
- `include_items`: `boolean` - Include structured items in recent_workset response.
- `library_idbs`: `array` - Optional list of absolute historical library IDB paths to match against.
- `limit`: `integer` - Max sessions to return (list action)
- `loader`: `string` - Loader name used before initial analysis.
- `loader_options`: `string|object` - Loader option payload applied before analysis.
- `macro`: `string` - Alias for macro name in macro_* actions.
- `macro_data`: `object` - Alias for macro payload in macro_set.
- `mappings`: `array` - List of mapping objects to apply, where each object contains addr, name (optional), and comment (optional).
- `max_ea`: `string|integer`
- `min_ea`: `string|integer`
- `n`: `integer` - Count for recent/oldest/recent_workset actions.
- `name`: `string` - Name for macro_* actions or rename action.
- `note`: `string` - Single note payload for add_note action.
- `notes`: `string` - Free-form notes for the session (create action).
- `offset`: `integer` - Skip first N sessions (list action)
- `options`: `object`
- `processor`: `string` - Processor name (e.g. arm, mipsl, tricore).
- `query`: `string` - Filter sessions by name/path (supports regex, glob, substring)
- `reanalyze`: `boolean`
- `recover`: `boolean`
- `run_action`: `string` - Session action to execute for macro_run (default from macro or create).
- `session_id`: `string` - Session ID for switch/close
- `start`: `string|integer`
- `start_ea`: `string|integer`
- `tags`: `array|string` - Tags for the session (create action). Comma-separated string or array.
- `threshold_cosine`: `number` - Minimum cosine similarity threshold (default: 0.85).
- `threshold_structural`: `number` - Minimum structural ratio similarity threshold (default: 0.70).
- `value`: `string|object` - Loader option payload alias (same as loader_options).
- `verbose`: `boolean` - Include per-runtime details for health action.
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "session",
  "arguments": {
    "action": "health"
  }
}
```
```json
{
  "name": "session",
  "arguments": {
    "action": "grep",
    "source_action": "health",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
