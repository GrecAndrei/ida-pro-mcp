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
| `ida_close_session` | Close the active session and release its runtime. |

## RPC concurrency

The per-session RPC lane serializes requests to one IDA bridge (one SDK
request at a time); different sessions run in parallel. The queue is bounded:
after `IDA_MCP_RPC_QUEUE_TIMEOUT` seconds (default 300, `0` = unlimited) a
queued call fails fast with a recoverable `IDA_BUSY` error. `IDA_TIMEOUT`
means the socket recv deadline expired; `IDA_CRASHED` means the runtime
process exited.
