# Sessions and troubleshooting

A session binds one binary and IDB to one IDA runtime. Operations use the
active session unless an `idb` or session-specific argument selects another.

## A session is still in safe mode

Check:

```text
ida_session_state
ida_session_status
```

Safe mode normally means auto-analysis is still running or has not been
confirmed complete. Poll status until the live runtime reports completion.
Manual small-area reads—such as single-function disassembly, decompilation,
strings, xrefs, comments, renames, and findings—remain available, while
whole-binary work such as indexing is blocked.

If the runtime dies during analysis, the gate stays closed and the status
reports the background error. Re-open or rebuild the session rather than
assuming analysis completed.

`ida_open_binary` is blocking by default and waits for initial auto-analysis.
`ida_open_background` is experimental, disabled unless
`IDA_MCP_BACKGROUND_OPEN=1` is set, and starts the session in safe mode. Use it
only when the client can poll `ida_session_status` and handle the gated state.

## A call is busy or times out

One IDA bridge processes one request at a time per session. Different sessions
can run in parallel. A queued call can fail with `IDA_BUSY` after the queue
timeout; `IDA_TIMEOUT` means the socket receive deadline expired, and
`IDA_CRASHED` means the runtime exited.

Use `ida_session_health` for runtime and queue diagnostics. Reduce the scope of
large operations, use background indexing, and avoid sending several
long-running calls to the same session concurrently.

## A session is locked

A session may be owned by another live MCP host or connection. Session listings
and `FILE_LOCKED` errors include ownership information such as the owner
process, whether it is alive, and the IDA runtime PID.

Do not kill a live owner's process. A dead owner is reclaimable through stale
lease cleanup; verify the ownership report first.

## A result is truncated

Responses may include `_continue`. Call `ida_continue` with the returned token
and fields rather than repeating the original operation. Repeating can redo
expensive analysis and may produce a different state after an edit.

## A semantic search is unavailable

Check the installed model and backend with the relevant status operations or
run the installer doctor:

```bash
python install.py --embedder-doctor
```

An unavailable semantic backend is an explicit unavailable result, not a zero
vector or a score pretending to be semantic. Use lexical discovery while
repairing the model, library, server, or credentials.

## A mutation is denied

Check both requirements:

1. the operation includes its required `risk_ack: true`; and
2. operator policy permits the operation.

A session cannot relax the operator baseline. `ida_python` is arbitrary code
inside IDA, so it is additionally subject to policy and safe-mode restrictions.

## Multiple agents share one connection

Without Agent SSO, the active session is connection-wide. An orchestrator can
opt into SSO with `ida_sso_activate`, then issue tickets and have each agent
call `ida_agent_login`. Identity, active session, ownership, and continuation
tokens are then scoped per agent.

References: [session operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md),
[session implementation](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/host/server/server_session.py),
[server configuration](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/host/config.py).
