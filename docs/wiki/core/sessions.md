# Sessions

Every analysis happens inside a **session**: one IDA runtime (idat) bound to
one binary and its IDB. The MCP server manages sessions for you; `ida_*`
operations target the *active* session unless an `idb` argument names
another one.

## Opening a binary

| Operation | Purpose |
| --- | --- |
| `ida_open_binary(binary_path)` | Open in a new or existing session. |
| `ida_open_background(binary_path)` | Open without blocking on IDA analysis. |
| `ida_session_switch(session_id=...)` | Change the active session. |

`ida_open_binary` returns immediately with `session_id`, `binary_path`, and
analysis flags. **Large binaries** (≥ `IDA_MCP_LARGE_BINARY_MB`, default
50 MiB) are auto-routed to the background path: the response reports
`background: true`, `auto_backgrounded: true`, and `safe_mode: true`, and you
poll `ida_session_status` until analysis completes. Re-opening a binary that
already has a completed IDB reuses the existing session synchronously.

## Safe mode

While a session's IDA auto-analysis is running, the session is in **safe
mode** (`safe_mode: true` in open/status/state responses). Safe mode blocks
everything that touches whole-binary analysis — `analysis` set_architecture/
reanalyze/run, indexing, firmware bootstrap, symbol loads, and arbitrary
scripts (`ida_python`) — and suppresses auto-enrichment. **Manual small-area
work stays available**: disassembly, decompilation of single functions,
reads, strings, xrefs, comments/renames, and findings.

Safe mode lifts only when a live runtime confirms `analysis_complete: true`.
For background-loaded sessions the runtime is then reloaded against the fully
analyzed IDB, and the next response for the session carries a one-shot
`analysis_complete` warning. A runtime that dies mid-build keeps the gate on
and reports `background_error`.

## Staying oriented

| Operation | Purpose |
| --- | --- |
| `ida_session_state` | Current binary, analysis progress, next useful actions. |
| `ida_session_status` | Is analysis ready? (`safe_mode`, `analysis_complete`). |
| `ida_session_health` | Server/runtime/cache diagnostics, RPC queue depth. |
| `ida_session_get(session_id=...)` | Details for one session. |
| `ida_session_list` | All sessions, filtered by query. |
| `ida_session_switch(...)` | Change the active session. |
| `ida_close_session` | Close the active session and release its runtime. **Requires `risk_ack: true`** — close tears down a live `idat` process and releases the session's lease, and without the acknowledgement the call is rejected (`POLICY_DENIED`). |

## Agent SSO (subagent isolation)

When several subagents share one MCP connection (opencode-style), they used to
be indistinguishable: a single *active* session, shared ownership, and a
connection close that tore down everyone's runtimes. **Agent SSO** gives each
subagent its own identity over that shared connection — its own active
session, its own ownership, and teardown scoped to it alone.

### Flow

> **Known gap.** The SSO actions run behind the legacy `session` tool/action
> interface (`tools/call name="session" action=sso_activate|agent_login|agent_logout`).
> The default agent surface advertises only the `ida_*` operations, and none of
> them covers SSO, so this flow is **not reachable (or discoverable) through
> `tools/list`**. `mint_agent_ticket` is a host-side Python helper in
> `host/server/server_client_state.py` with no MCP operation behind it — an
> external MCP client cannot mint tickets through the public interface; it must
> construct them itself (computing the HMAC with the realm secret) or run
> host-side code.

1. **Orchestrator activates the realm** and assigns the agent names:
   `session action=sso_activate agents=["rev_a","audit_b"]`. The realm is
   one-shot per server process; the secret comes from the `secret` argument,
   the `IDA_MCP_SSO_SECRET` env var, or is generated (and returned) once.
2. **Orchestrator mints a ticket per agent** with that secret. Tickets are
   `name.payload.signature` where the signature is
   `HMAC-SHA256(secret, payload)` and the payload carries `{name, exp, scopes,
   nonce}` (the host's `mint_agent_ticket(secret, name, exp, scopes, nonce)`
   helper shows the exact construction). Give each subagent its ticket (env
   var / system prompt).
3. **Subagent logs on** once: `session action=agent_login name=rev_a
   ticket=<ticket>`. The server verifies signature, expiry, allowlist, and
   that the ticket name matches — then binds the identity to *this* connection.
4. **Every session-scoped call carries its agent tag**:
   `session action=status agent=rev_a`. The tag is validated against the
   logged-in identity for the current connection and is never forwarded to IDA.
5. **Teardown**: `session action=agent_logout name=rev_a` (or connection
   close) releases **only** that agent's runtimes and leases.

### What isolation means

- Each agent has its own **active session** (`current_session` is per-agent);
  agent A creating a binary never clobbers agent B's active target.
- **Ownership is agent-scoped**: while agent A is actively running a session,
  agent B gets `FILE_LOCKED` if it tries to switch to it. (An idle recorded
  session can be adopted — that's the session-reuse path, unchanged.)
- **Truncation tokens** are scoped per `connection:agent`, so two agents never
  collide on a `next_token`.
- Calls without an `agent` tag behave exactly as before (unbound / legacy).

### Validation rules

| Condition | Result |
| --- | --- |
| SSO not activated | `POLICY_DENIED` |
| Name not in the allowlist | `POLICY_DENIED` |
| Forged / tampered signature | `POLICY_DENIED` |
| Expired ticket | `POLICY_DENIED` |
| Logged in on a *different* connection | `POLICY_DENIED` |
| `agent` tag on an un-logged-in name | `POLICY_DENIED` |

## Ownership forensics (who holds a session)

When several MCP hosts or daemon connections share one session store, a
`FILE_LOCKED` error used to say only *that* the session was busy — not *who*
held it, or whether that holder was even alive. Session list/state payloads
and the `FILE_LOCKED` error now carry an ownership report:

| Field | Meaning |
| --- | --- |
| `locked` | Another live owner is actively running this session's IDA. |
| `holder` | `"this-host-runtime"` (a live runtime in this server) or `"foreign-lease"` (a lease owned by a different MCP host process). |
| `owner_id` / `owner_pid` | The MCP host identity and PID that holds the lease. |
| `owner_alive` | Whether that owner process still exists. |
| `idat_pid` | The IDA runtime process PID. |
| `lease_age_seconds` | Age of the lease file (stale leases age out). |

A session with a **dead owner** is reported `locked: false` — it is
reclaimable, and stale-lease cleanup reclaims its `owner.json` and terminates
its orphaned idat without ever touching anything owned by a live process.

## RPC concurrency

The per-session RPC lane serializes requests to one IDA bridge (one SDK
request at a time); different sessions run in parallel. The queue is bounded:
after `IDA_MCP_RPC_QUEUE_TIMEOUT` seconds (default 300, `0` = unlimited) a
queued call fails fast with a recoverable `IDA_BUSY` error. `IDA_TIMEOUT`
means the socket recv deadline expired; `IDA_CRASHED` means the runtime
process exited.
