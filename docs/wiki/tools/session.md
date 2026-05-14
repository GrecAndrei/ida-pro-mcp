# session

Manages analysis sessions, notebooks, hypotheses, skills, macros, and session lifecycle.

## Actions

### Lifecycle
- `create` — starts a new analysis session for a binary; params: `binary_path`, `options`
- `switch` — switches to an existing session; params: `session_id`
- `close` — closes a session; params: `session_id`
- `list` — lists all sessions
- `status` — returns current session status
- `stats` — returns session statistics (call counts, duration, etc.)
- `archive` — archives a session; params: `session_id`
- `unarchive` — restores an archived session; params: `session_id`
- `recent` — lists recently accessed sessions
- `oldest` — lists oldest sessions
- `discover` — finds orphaned IDB files and recovers sessions
- `get` — retrieves session metadata; params: `session_id`
- `rebuild` — rebuilds session metadata from IDB
- `update` — updates session metadata; params: `session_id`, fields to update
- `rename` — renames a session; params: `session_id`, `name`
- `duplicate` — duplicates a session; params: `session_id`
- `export_session` — exports session to portable format; params: `session_id`, `path`
- `import_session` — imports a previously exported session; params: `path`
- `validate` — validates session integrity; params: `session_id`
- `cleanup_stale` — removes stale/broken sessions
- `merge` — merges two sessions; params: `source_id`, `target_id`
- `bulk_delete` — deletes multiple sessions; params: `session_ids`
- `dashboard` — returns overview of all sessions with key metrics

### Snapshots
- `snapshot` — saves a named snapshot of current session state; params: `name`
- `restore_snapshot` — restores a previously saved snapshot; params: `name`
- `list_snapshots` — lists available snapshots

### Notebook
- `notebook_append` — appends text to the session notebook; params: `text`
- `notebook_read` — reads the full notebook or a section
- `notebook_section` — reads a specific notebook section; params: `section`

### Hypotheses
- `track_hypothesis` — records a new hypothesis; params: `hypothesis`, `evidence`
- `confirm_hypothesis` — marks a hypothesis as confirmed; params: `hypothesis_id`, `evidence`
- `refute_hypothesis` — marks a hypothesis as refuted; params: `hypothesis_id`, `reason`
- `list_hypotheses` — lists all tracked hypotheses with status

### Skills (MemRL)
- `crystallize_skill` — saves a successful workflow as a reusable skill; params: `name`, `steps`, `tags`
- `rate_skill` — applies TD-style Q-value update to a skill; params: `skill_id`, `outcome`
- `list_skills` — lists all crystallized skills
- `suggest_strategy` — ranks skills by Q-value and context match; params: `context`

### Activity
- `log_activity` — logs an activity entry; params: `activity`, `details`
- `get_activity_log` — retrieves the activity log; params: `count`

### Phases
- `get_phase` — returns current analysis phase
- `advance_phase` — advances to next phase (with dead-end detection); params: `reason`

### Context Resume
- `recent_workset` — returns recent activity + bookmarks for quick context resume

### Macros
- `macro_set` — defines a named macro (sequence of tool calls); params: `name`, `calls`
- `macro_get` — retrieves a macro definition; params: `name`
- `macro_list` — lists all macros
- `macro_delete` — deletes a macro; params: `name`
- `macro_run` — executes a macro; params: `name`

### Tags & Notes
- `tag` — adds a tag to a session; params: `session_id`, `tag`
- `untag` — removes a tag; params: `session_id`, `tag`
- `find_by_tag` — finds sessions by tag; params: `tag`
- `bulk_tag` — tags multiple sessions; params: `session_ids`, `tag`
- `add_note` — adds a note to a session; params: `session_id`, `note`
- `clear_notes` — clears all notes; params: `session_id`
- `search_notes` — searches notes across sessions; params: `query`

### Links
- `link` — links two sessions; params: `session_id_a`, `session_id_b`, `relation`
- `cross_reference` — finds cross-references between sessions

## Examples

```json
{"name": "session", "arguments": {"action": "create", "binary_path": "/path/to/binary"}}
```

```json
{"name": "session", "arguments": {"action": "switch", "session_id": "AB12CD34"}}
```

```json
{"name": "session", "arguments": {"action": "notebook_append", "text": "Found decryption routine at 0x401200"}}
```

```json
{"name": "session", "arguments": {"action": "track_hypothesis", "hypothesis": "Function at 0x401200 is AES-CBC decrypt", "evidence": "Uses 16-byte block size, references S-box table"}}
```

```json
{"name": "session", "arguments": {"action": "crystallize_skill", "name": "crypto_id_flow", "steps": ["search strings for key schedule constants", "decompile candidate", "classify as crypto"], "tags": ["crypto"]}}
```

```json
{"name": "session", "arguments": {"action": "suggest_strategy", "context": "identify encryption algorithm"}}
```

```json
{"name": "session", "arguments": {"action": "recent_workset"}}
```

```json
{"name": "session", "arguments": {"action": "macro_set", "name": "triage", "calls": ["idb:meta", "data:imports", "search:strings"]}}
```

## Notes

- IDB path is not required after `create` or `switch` — all subsequent tool calls use the active session automatically.
- `crystallize_skill` saves workflows as L3 skills; `suggest_strategy` ranks them by Q-value for the current context.
- Hypotheses follow a formal lifecycle: `track` → `confirm` or `refute`. Use `list_hypotheses` to review status.
- `advance_phase` includes dead-end detection — it will warn if progress has stalled.
- `recent_workset` is the fastest way to resume context after a context window reset.
- Macros store sequences of tool calls that can be replayed with `macro_run`.
- Session metadata persists in the user runtime directory and survives IDA restarts.
