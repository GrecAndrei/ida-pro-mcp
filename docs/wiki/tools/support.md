# Support

Meta-operations.

| Operation | Purpose |
| --- | --- |
| `ida_help(query=...)` | Exact contract and example for an operation, or search the catalog. |
| `ida_continue(token)` | Continue a truncated result (`_continue.token` / `_continue.fields`). |
| `ida_python(code)` | Execute a Python expression in the active IDA process. `risk_ack` required. Blocked in safe mode. |

Prefer `ida_help` over guessing an operation's arguments — every operation
has a strict schema and a validating example. Responses can be truncated to
bound token usage; `ida_continue` fetches the rest without re-running the
operation.

`ida_python` is the escape hatch for anything the surface does not cover. It
runs arbitrary code inside IDA, so it requires `risk_ack: true`, is gated by
safe mode, and is subject to operator policy.
