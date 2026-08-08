# Support

Meta-operations.

| Operation | Purpose |
| --- | --- |
| `ida_help(query=...)` | Exact contract and example for an operation, or search the catalog. |
| `ida_continue(token)` | Continue a truncated result (`_continue.token` / `_continue.fields`). |
| `ida_python(code)` | Execute a Python expression in the active IDA process. `risk_ack` required. Blocked in safe mode. Pass `idb=<session_id>` on a shared connection to target a specific session. |

Prefer `ida_help` over guessing an operation's arguments — every operation
has a strict schema and a validating example. Responses can be truncated to
bound token usage; `ida_continue` fetches the rest without re-running the
operation.

`ida_python` is the escape hatch for anything the surface does not cover. It
runs arbitrary code inside IDA, so it requires `risk_ack: true`, is gated by
safe mode, and is subject to operator policy.

When several agents share one MCP connection there is no per-agent identity by
default, so the connection-wide active session is a shared default. Pass
`idb=<session_id>` (or an IDB/binary path) to `ida_python` to execute inside a
specific session; without it, the code runs in whichever session opened last.
An orchestrator can opt into **Agent SSO** (`session action=sso_activate`) to
give each agent a distinct identity and isolated active session — see
[Sessions](../core/sessions.md). The safe-mode gate follows the target:
`ida_python` is blocked only while the session it is aimed at is still
analyzing.

Every code-execution response carries a `_executed_in` block so the caller can
see at a glance where the code actually ran:

```json
"_executed_in": {
  "session_id": "SID_ABC123",
  "idb_path": "/cache/sessions/SID_ABC123/...i64",
  "image_base": "0xc000"
}
```

If the image base looks wrong for the binary you meant to inspect, the call was
aimed at a different session — re-run with `idb=<session_id>`.
