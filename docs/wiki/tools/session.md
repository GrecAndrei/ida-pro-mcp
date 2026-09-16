# Session

Session lifecycle, analysis state, multi-session management, and Agent SSO subagent isolation.

Every analysis targets an IDA session (an `idat` process bound to a binary and IDB).
By default, operations target the currently active session unless an `idb` parameter
targets a specific session ID.

---

## Operations Overview

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_open_binary(binary_path)` | Open a binary in a new or existing IDA session (blocking wait for analysis). | `binary_path` |
| `ida_open_background(binary_path)` | Open a binary without blocking on IDA analysis (experimental, starts in safe mode). | `binary_path` |
| `ida_session_state` | Current binary name, analysis progress, and next recommended actions. | — |
| `ida_session_status` | Check if IDA analysis is complete (`safe_mode: false`). Lightweight poll. | — |
| `ida_session_health` | Server, IDA runtime, cache, and RPC queue health diagnostics. | — |
| `ida_session_get(session_id)` | Retrieve detailed runtime metadata and lease status for a session. | `session_id` |
| `ida_session_list(query=...)` | List all active and cached sessions, optionally filtered by name/path. | — |
| `ida_session_switch(session_id=...)` | Switch the active session to another session by ID or binary path. | — |
| `ida_close_session` | Close the active IDA session and release its runtime and lease. | `risk_ack` |
| `ida_sso_activate(agents=...)` | Activate the one-shot Agent SSO realm with an allowlist of subagent names. | `agents` |
| `ida_agent_login(name, ticket)` | Authenticate a subagent with an HMAC ticket on a shared MCP connection. | `name`, `ticket` |
| `ida_agent_logout(name)` | Log out a subagent and tear down only its owned sessions and leases. | `name` |

---

## 1. Opening Binaries

### Standard Open (`ida_open_binary`)

```json
{
  "binary_path": "/path/to/target.bin",
  "processor": "riscv",
  "bitness": 64,
  "baseaddr": "0x80000000"
}
```

By default, `ida_open_binary` blocks until IDA's initial auto-analysis completes, so the returned session is ready for decompilation and whole-binary analysis (`safe_mode: false`). Re-opening a binary with an existing database reuses the cached IDB immediately.

### Background Open (`ida_open_background`)

Opens the binary immediately without waiting for auto-analysis. The session starts in safe mode (`safe_mode: true`), during which whole-binary sweeps and indexing are blocked. Poll `ida_session_status` until `safe_mode` clears.

---

## 2. Multi-Session Management

- `ida_session_list`: View all sessions with their IDB paths, process IDs, and lock states.
- `ida_session_switch(session_id="SID_XYZ")`: Changes the active session.
- When calling any tool across multiple open sessions, you can pass `idb="SID_XYZ"` directly to avoid switching the active session back and forth.
- `ida_close_session(risk_ack=true)`: Terminates the live `idat` process and releases lock files.

---

## 3. Agent SSO (Subagent Isolation)

When multiple autonomous agents (e.g. planner, decompilation specialist, security auditor) share a single MCP connection, **Agent SSO** provides distinct identities, private active sessions, and isolated resource cleanup:

1. **Activate Realm**:
   ```json
   {"name": "ida_sso_activate", "arguments": {"agents": ["planner", "auditor"]}}
   ```
2. **Subagent Login**:
   ```json
   {"name": "ida_agent_login", "arguments": {"name": "auditor", "ticket": "<hmac_ticket>"}}
   ```
3. **Scoped Calls**: Calls from logged-in agents are tracked with agent-scoped session ownership and continuation tokens.
4. **Logout**:
   ```json
   {"name": "ida_agent_logout", "arguments": {"name": "auditor"}}
   ```
   Releases only the logging-out agent's resources without interrupting peer subagents.

See [Sessions Core Guide](../core/sessions.md) for deeper architecture and lifecycle details.
