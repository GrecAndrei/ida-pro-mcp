# Session operations

`ida_open_binary`, `ida_open_background`, `ida_session_state`,
`ida_session_status`, `ida_session_health`, `ida_session_get`,
`ida_session_list`, `ida_session_switch`, `ida_close_session`.

`ida_close_session` requires `risk_ack: true` — it is a destructive action
that tears down a live `idat` process and releases the session's lease. Pass
`risk_ack` only after verifying the teardown is intended.

See [Sessions](../core/sessions.md) — lifecycle, background loading, safe
mode, and RPC concurrency.
