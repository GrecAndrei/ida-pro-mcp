# session

Manages analysis sessions, notebooks, hypotheses, skills, macros, and phase tracking for a binary.

## Actions
- `create` — start a new session. Requires `binary_path`. Does NOT accept `idb_path` or `use_existing`.
- `switch` — switch active session by `session_id`. Triggers background session diff (compares embedding indexes, writes session_diff to blackboard).
- `close` — close a session by `session_id`
- `list` — list all sessions
- `get` — get metadata for a session
- `status` — runtime status of active session
- `recent_workset` — resume context from recent activity + bookmarks
- `notebook_append` — append text to per-session analysis notebook. Params: `text`, optional `section`
- `notebook_read` — read notebook contents. Optional `section`
- `track_hypothesis` — record a hypothesis. Params: `hypothesis`, optional `evidence`
- `confirm_hypothesis` — mark hypothesis confirmed. Params: `hypothesis_id`, `evidence`
- `refute_hypothesis` — mark hypothesis refuted. Params: `hypothesis_id`, `reason`
- `list_hypotheses` — list all tracked hypotheses
- `crystallize_skill` — save a successful workflow as reusable skill. Params: `name`, `steps`, `context`
- `rate_skill` — TD-style Q-value update. Params: `skill_id`, `outcome`
- `suggest_strategy` — rank skills by Q-value + context match
- `list_skills` — list crystallized skills
- `log_activity` — log an episodic activity entry. Params: `activity`, optional `tags`
- `get_activity_log` — retrieve activity log. Optional `limit`
- `get_phase` — get current analysis phase
- `advance_phase` — advance to next phase. Optional `force`
- `macro_set` — define a macro. Params: `name`, `calls`
- `macro_get` — retrieve macro by `name`
- `macro_list` — list all macros
- `macro_delete` — delete macro by `name`
- `macro_run` — execute a saved macro by `name`

## Examples
```json
{"name": "session", "arguments": {"action": "create", "binary_path": "/tmp/target.elf"}}
```
```json
{"name": "session", "arguments": {"action": "notebook_append", "text": "Main dispatch at 0x401000", "section": "findings"}}
```

## Notes
- `create` only accepts `binary_path`; passing `idb_path` or `use_existing` is an error.
- `switch` writes a session_diff entry to the blackboard comparing embedding indexes between sessions.
- Notebooks, hypotheses, and skills persist across context window resets.
